// +build ignore

#include <linux/types.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include "bpf_helpers.h"
#include <bpf/bpf_endian.h>

#include <stddef.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*
A massive oversimplifcation of what is in this file.

               ┌───────────────────────────────┐             ┌───────────────────────────────────┐
               │      Inactivity Timeout       │             │           Devices                 │
               │                               │             │            map                    │
               │       uint64 (minutes)        │             │     key: ipv4 (u32)               │
               │                               │             │     val: sizeof(struct device)    │
               └───────────────────────────────┘             │                 │                 │
                                                             └─────────────────┼─────────────────┘
                                                                               │
                                                                 ┌─────────────▼──────────────┐
                                                                 │     device   struct        │
            ┌─────────────────────────────────────┐              │                            │
            │                User                 │◄─────────────┼─ userid         char[20]   │
            │                                     │              │  sessionExpiry  uint64     │
            ├─────────────────────────────────────┤              │  lastPacketTime uint64     │
            │           AccountLocked             │              │  deviceLock     uint32     │
            │               uint32                │              └────────────────────────────┘
            ├─────────────────────────────────────┤
            │           Public Routes LPM         │
            │              key uint32             │             ┌─────────────────────────────┐
            │         value policies[128]─────────┼───────┐     │        policy struct        │
            │                                     │       │     │     policy_type uint16      │
            ├─────────────────────────────────────┤       ├────►│     lower_port  uint16      │
            │           MFA Routes LPM            │       │     │     upper_port  uint16      │
            │              key uint32             │       │     │     proto       uint16      │
            │         value policies[128] ────────┼───────┘     │                             │
            │                                     │             └─────────────────────────────┘
            └─────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Packet Flow                                                           │
│                                                                                                         │
│                                                                                                         │
│                                                                                                         │
│                              │                                                                          │
│                 Input Packet │                                                                          │
│                              │                                                                          │
│                      ┌───────▼───────┐                                                                  │
│                      │               │                                                       ┌────────┐ │
│                      │  Decode IPv4  │                  if packet not ipv4                   │        │ │
│                      │               │  ─────────────────────────────────────────────────────►  DROP  │ │
│                      │    Header     │                                                       │        │ │
│                      │               │                                                       └────────┘ │
│                      └───────┬───────┘                                                                  │
│                              │                                                                          │
│                              │                                                                          │
│                   src : u32  │                                                                          │
│                   dst : u32  │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                 ┌────────────▼─────────────┐                                                            │
│                 │                          │                                                            │
│                 │       Lookup Device      │                                                            │
│                 │                          │                                                ┌────────┐  │
│                 │  device = (              │               not_found(device)                │        │  │
│                 │     valid(Devices[src])  │ ───────────────────────────────────────────────►  DROP  │  │
│                 │           or             │                                                │        │  │
│                 │     valid(Devices[dst])  │                                                └────────┘  │
│                 │  )                       │                                                            │
│                 │                          │                                                            │
│                 └────────────┬─────────────┘                                                            │
│                              │                                                                          │
│                              │                                                                          │
│           userid : char[20]  │  device found                                                            │
│                              │                                                                          │
│                              │                                                                          │
│                  ┌───────────▼─────────────┐                                                            │
│                  │        Lookup User      │                                                            │
│                  │                         │                                                ┌────────┐  │
│                  │    user = users(        │                 not_found(userid)              │        │  │
│                  │      userid             │ ───────────────────────────────────────────────►  DROP  │  │
│                  │    )                    │                                                │        │  │
│                  │                         │                                                └────────┘  │
│                  └───────────┬─────────────┘                                                            │
│                              │                                                                          │
│                              │                                                                          │
│ device.LastPacketTime : u64  │                                                                          │
│                dst_ip : u32  │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                 ┌────────────▼────────────┐                                                 ┌────────┐  │
│                 │         Routes          │         matches neither public or mfa routes    │        │  │
│                 │          Check          │ ────────────────────────────────────────────────►  DROP  │  │
│                 └────────────┬────────────┘                                                 │        │  │
│                              │                                                              └────────┘  │
│                              │                                                                          │
│  policies struct policy[128] │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                     ┌────────┴─────────┐                                                                │
│                     │                  │                                                    ┌────────┐  │
│                     │  Check Policies  │              no_match(polices,port,proto)          │        │  │
│                     │                  │     ───────────────────────────────────────────────►  DROP  │  │
│                     └────────┬─────────┘                                                    │        │  │
│                              │                                                              └────────┘  │
│                              │                                                                          │
│                         ┌────▼────┐                                                                     │
│                         │         │                                                                     │
│                         │   PASS  │                                                                     │
│                         │         │                                                                     │
│                         └─────────┘                                                                     │
│                                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

#define MAX_POLICIES 128
#define MAX_MAP_ENTRIES 1024
#define MAX_USERID_LENGTH 20 // Length of sha1 hash

// These definitions are used for searching the trie structure to determine the type of rule we've got.
#define STOP 0 // Signal stop searching array

#define PUBLIC 4
#define RANGE 8   // Port & protocol range e.g 22-2000
#define SINGLE 16 // Single port & protocol

struct bpf_map_def
{
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int inner_map_idx;
    unsigned int numa_node;
};

enum
{
    IPPROTO_IP = 0, /* Dummy protocol for TCP		*/
#define IPPROTO_IP IPPROTO_IP
    IPPROTO_ICMP = 1, /* Internet Control Message Protocol	*/
#define IPPROTO_ICMP IPPROTO_ICMP
    IPPROTO_IGMP = 2, /* Internet Group Management Protocol	*/
#define IPPROTO_IGMP IPPROTO_IGMP
    IPPROTO_IPIP = 4, /* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_IPIP IPPROTO_IPIP
    IPPROTO_TCP = 6, /* Transmission Control Protocol	*/
#define IPPROTO_TCP IPPROTO_TCP
    IPPROTO_EGP = 8, /* Exterior Gateway Protocol		*/
#define IPPROTO_EGP IPPROTO_EGP
    IPPROTO_PUP = 12, /* PUP protocol				*/
#define IPPROTO_PUP IPPROTO_PUP
    IPPROTO_UDP = 17, /* User Datagram Protocol		*/
#define IPPROTO_UDP IPPROTO_UDP
    IPPROTO_IDP = 22, /* XNS IDP protocol			*/
#define IPPROTO_IDP IPPROTO_IDP
    IPPROTO_TP = 29, /* SO Transport Protocol Class 4	*/
#define IPPROTO_TP IPPROTO_TP
    IPPROTO_DCCP = 33, /* Datagram Congestion Control Protocol */
#define IPPROTO_DCCP IPPROTO_DCCP
    IPPROTO_IPV6 = 41, /* IPv6-in-IPv4 tunnelling		*/
#define IPPROTO_IPV6 IPPROTO_IPV6
    IPPROTO_RSVP = 46, /* RSVP Protocol			*/
#define IPPROTO_RSVP IPPROTO_RSVP
    IPPROTO_GRE = 47, /* Cisco GRE tunnels (rfc 1701,1702)	*/
#define IPPROTO_GRE IPPROTO_GRE
    IPPROTO_ESP = 50, /* Encapsulation Security Payload protocol */
#define IPPROTO_ESP IPPROTO_ESP
    IPPROTO_AH = 51, /* Authentication Header protocol	*/
#define IPPROTO_AH IPPROTO_AH
    IPPROTO_MTP = 92, /* Multicast Transport Protocol		*/
#define IPPROTO_MTP IPPROTO_MTP
    IPPROTO_BEETPH = 94, /* IP option pseudo header for BEET	*/
#define IPPROTO_BEETPH IPPROTO_BEETPH
    IPPROTO_ENCAP = 98, /* Encapsulation Header			*/
#define IPPROTO_ENCAP IPPROTO_ENCAP
    IPPROTO_PIM = 103, /* Protocol Independent Multicast	*/
#define IPPROTO_PIM IPPROTO_PIM
    IPPROTO_COMP = 108, /* Compression Header Protocol		*/
#define IPPROTO_COMP IPPROTO_COMP
    IPPROTO_L2TP = 115, /* Layer 2 Tunnelling Protocol		*/
#define IPPROTO_L2TP IPPROTO_L2TP
    IPPROTO_SCTP = 132, /* Stream Control Transport Protocol	*/
#define IPPROTO_SCTP IPPROTO_SCTP
    IPPROTO_UDPLITE = 136, /* UDP-Lite (RFC 3828)			*/
#define IPPROTO_UDPLITE IPPROTO_UDPLITE
    IPPROTO_MPLS = 137, /* MPLS in IP (RFC 4023)		*/
#define IPPROTO_MPLS IPPROTO_MPLS
    IPPROTO_ETHERNET = 143, /* Ethernet-within-IPv6 Encapsulation	*/
#define IPPROTO_ETHERNET IPPROTO_ETHERNET
    IPPROTO_RAW = 255, /* Raw IP packets			*/
#define IPPROTO_RAW IPPROTO_RAW
    IPPROTO_MPTCP = 262, /* Multipath TCP connection		*/
#define IPPROTO_MPTCP IPPROTO_MPTCP
    IPPROTO_MAX
};

struct iphdr
{
    __u8 ihl : 4,
        version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __struct_group(/* no tag */, addrs, /* no attrs */,
                   __be32 saddr;
                   __be32 daddr;);
    /*The options start here. */
};

struct udphdr
{
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

struct tcphdr
{
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4,
        doff : 4,
        fin : 1,
        syn : 1,
        rst : 1,
        psh : 1,
        ack : 1,
        urg : 1,
        ece : 1,
        cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

struct icmphdr
{
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union
    {
        struct
        {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct
        {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
};

struct device
{
    __u64 sessionExpiry;
    __u64 lastPacketTime;

    // Hash of username (sha1 20 bytes)
    // Essentially allows us to compress all usernames, if collisions are a problem in the future we'll move to sha256 or xxhash
    char user_id[MAX_USERID_LENGTH];

    __u32 PAD;

} __attribute__((__packed__));

struct ip
{
    __u32 src_ip;
    __u16 src_port;

    __u32 dst_ip;
    __u16 dst_port;

    __u32 proto;
};

struct bpf_map_def SEC("maps") devices = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_MAP_ENTRIES,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct device),
    .map_flags = 0,
};

// User

struct bpf_map_def SEC("maps") account_locked = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_MAP_ENTRIES,
    .key_size = MAX_USERID_LENGTH,
    .value_size = sizeof(__u32),
    .map_flags = 0,
};

// Two tables of the same construction

// Inner map is a LPM tri, so we use this as the key
struct ip4_trie_key
{
    __u32 prefixlen; // first member must be u32
    __u32 addr;
} __attribute__((__packed__));

struct policy
{
    __u16 policy_type;
    __u16 proto;
    __u16 lower_port;
    __u16 upper_port;
} __attribute__((__packed__));

// Hahed username to LPM trie, value size *has* to be u32 as this is a HASH of MAPS
struct bpf_map_def SEC("maps") policies_table = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .max_entries = MAX_MAP_ENTRIES,
    .key_size = MAX_USERID_LENGTH,
    .value_size = sizeof(__u32),
    .map_flags = 0,
};

// end user

// A single variable in nano seconds
struct bpf_map_def SEC("maps") inactivity_timeout_minutes = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 1,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .map_flags = 0,
};

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/

#define MAX_PACKET_OFF 0xffff

static __always_inline int parse_ip_src_dst_addr(struct xdp_md *ctx, struct ip *ip_info)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // As this is being attached to a wireguard interface (tun device), we dont get layer 2 frames
    // Just happy little ip packets

    // Then parse the IP header.
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
    {
        return 0;
    }

    // We dont support ipv6
    if (ip->version != 4)
    {
        return 0;
    }

    ip_info->proto = ip->protocol;
    ip_info->dst_port = 0;
    ip_info->src_port = 0;

    __u64 ip_header_length = (ip->ihl * 4);
    if (ip_header_length > MAX_PACKET_OFF)
    {
        return 0;
    }

    if ((void *)(data + ip_header_length) > data_end)
    {
        return 0;
    }

    switch (ip->protocol)
    {

    case IPPROTO_UDP:
    {

        struct udphdr *udph = (data + ip_header_length);

        if (udph + 1 > (struct udphdr *)data_end)
        {
            return 0;
        }

        ip_info->dst_port = udph->dest;
        ip_info->src_port = udph->source;

        break;
    }

    case IPPROTO_TCP:
    {

        struct tcphdr *tcph = (data + ip_header_length);

        if (tcph + 1 > (struct tcphdr *)data_end)
        {
            return 0;
        }

        ip_info->dst_port = tcph->dest;
        ip_info->src_port = tcph->source;

        break;
    }
    case IPPROTO_ICMP:
    {
        struct icmphdr *icmph = (data + ip_header_length);

        if (icmph + 1 > (struct icmphdr *)data_end)
        {
            return 0;
        }

        break;
    }
    }

    // Return the source IP address in network byte order.
    ip_info->src_ip = (__u32)(ip->saddr);
    ip_info->dst_ip = (__u32)(ip->daddr);

    return 1;
}

static __always_inline int conntrack(struct ip *ip_info)
{

    __u32 address = ip_info->dst_ip;
    __u16 port = ip_info->dst_port;

    // Determine which address is our device
    struct device *current_device = bpf_map_lookup_elem(&devices, &ip_info->src_ip);
    if (current_device == NULL)
    {
        current_device = bpf_map_lookup_elem(&devices, &ip_info->dst_ip);
        if (current_device == NULL)
        {
            return 0;
        }

        // Our device is the dst, so what we need to check in the firewall is the src
        address = ip_info->src_ip;
        port = ip_info->src_port;
    }

    port = bpf_ntohs(port);

    // Check if the account exists
    __u32 *isAccountLocked = bpf_map_lookup_elem(&account_locked, current_device->user_id);
    if (isAccountLocked == NULL)
    {
        return 0;
    }

    // Our userland defined inactivity timeout
    __u32 index = 0;
    __u64 *inactivity_timeout = bpf_map_lookup_elem(&inactivity_timeout_minutes, &index);
    if (inactivity_timeout == NULL)
    {
        return 0;
    }

    __u64 currentTime = bpf_ktime_get_ns();

    // If the inactivity timeout is not disabled and users session has timed out
    __u8 isTimedOut = (*inactivity_timeout != __UINT64_MAX__ && ((currentTime - current_device->lastPacketTime) >= *inactivity_timeout));

    struct ip4_trie_key key = {0};

    key.addr = address;
    key.prefixlen = 32;

    // The inner maps must be a LPM trie

    // Order of preference is MFA -> Public, just in case someone adds multiple entries for the same route to make sure accidental exposure is less likely
    // If the key is a match for the LPM in the public table
    void *user_policies = bpf_map_lookup_elem(&policies_table, current_device->user_id);

    struct policy *applicable_policies = (user_policies != NULL) ? bpf_map_lookup_elem(user_policies, &key) : NULL;
    if (applicable_policies == NULL)
    {
        return 0;
    }

    // The upper bytes of a policy tell us if the policies are MFA or Public
    // We dont have to pay attention to all the polices in a route as they should all be of one type
    if (!(applicable_policies->policy_type & PUBLIC))
    {
        // If device does not belong to a locked account and the device itself isnt locked and if it isnt timed out
        if (*isAccountLocked || isTimedOut || current_device->sessionExpiry == 0 ||
            // If either max session lifetime is disabled, or it is before the max lifetime of the session
            (current_device->sessionExpiry != __UINT64_MAX__ && currentTime > current_device->sessionExpiry))
        {
            // If we match a MFA policy, but we are not authorised dont fall through to the public route lookup
            // just die
            return 0;
        }
    }

    if (!isTimedOut)
    {
        // Doesnt matter that this isnt thread safe
        current_device->lastPacketTime = currentTime;
    }

    for (__u16 i = 0; i < MAX_POLICIES; i++)
    {

        __u32 key = i;
        struct policy policy = *(applicable_policies + key);

        // As the array is static in size, we want to be able to terminate the search asap
        if (policy.policy_type == STOP)
        {
            return 0;
        }

        // 0 = ANY
        if (policy.proto == 0 || policy.proto == ip_info->proto)
        {

            if (policy.policy_type & SINGLE)
            {
                return (policy.lower_port == 0 || policy.lower_port == port);
            }

            if (policy.policy_type & RANGE)
            {
                return (policy.lower_port <= port && policy.upper_port >= port);
            }
        }
    }

    return 0;
}

SEC("xdp")
int xdp_wag_firewall(struct xdp_md *ctx)
{
    struct ip ip_info = {0};
    if (!parse_ip_src_dst_addr(ctx, &ip_info))
    {
        return XDP_DROP;
    }

    if (conntrack(&ip_info))
    {
        return XDP_PASS;
    }

    return XDP_DROP;
}
