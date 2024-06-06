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
                                                                 ┌──────────────────────────────┐
                                                                 │        Devices               │
                                                                 │         map                  │
                                                                 │  key: ipv4 (u32)             │
                                                                 │  val: sizeof(struct device)  │
                                                                 │              │               │
   ┌────────────────────────────────────────────┐                └──────────────┼───────────────┘
   │                   Policies                 │                               │
   │                                            │                 ┌─────────────▼──────────────┐
   │                     map                    │                 │     device   struct        │
   │                                            │                 │                            │
   │  key: userid char[20] ◄────────────────────┼─────────────────┼─ userid         char[20]   │
   │  val: Max Polices * sizeof(struct device)  │                 │  sessionExpiry  uint64     │
   │                      │                     │                 │  lastPacketTime uint64     │
   └──────────────────────┼─────────────────────┘                 │  associatedNode uint64     │
                          │                                       │                            │
                          │                                       └────────────────────────────┘
                    Max Policies
                          │
           ┌──────────────▼──────────────┐
           │        policy struct        │     ┌────────────────────┐  ┌─────────────────────────┐
           │     policy_type uint16      │     │ Inactivity Timeout │  │     Associated Node     │
           │     lower_port  uint16      │     │                    │  │                         │
           │     upper_port  uint16      │     │       Array        │  │          Array          │
           │     proto       uint16      │     │                    │  │                         │
           │                             │     │  uint64 (minutes)  │  │  uint64 (etcd node id)  │
           └─────────────────────────────┘     └────────────────────┘  └─────────────────────────┘

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
│                  │                         │                                                            │
│                  │                         │                                                ┌────────┐  │
│                  │    Check User Exists    │                 not_found(userid)              │        │  │
│                  │                         │ ───────────────────────────────────────────────►  DROP  │  │
│                  │                         │                                                │        │  │
│                  └───────────┬─────────────┘                                                └────────┘  │
│                              │                                                                          │
│                              │                                                                          │
│            node_id : uint64  │                                                                          │
│                              │                                                                          │
│                              ▼                                                                          │
│                   ┌──────────────────────┐                                                              │
│                   │                      │                                                              │
│                   │        Check         │            device not associated with current    ┌────────┐  │
│                   │                      │                            node                  │        │  │
│                   │       Node ID        │   ───────────────────────────────────────────────►  DROP  │  │
│                   │          =           │                                                  │        │  │
│                   │  Peer Associated ID  │                                                  └────────┘  │
│                   │                      │                                                              │
│                   └──────────┬───────────┘                                                              │
│                              │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                              ▼                                                                          │
│                   ┌──────────────────────┐                                                              │
│                   │                      │                                                              │
│                   │                      │                                                              │
│                   │                      │                                                              │
│                   │    Check Policies    │                                                              │
│                   │                      │◄─────────────────────┐                                       │
│                   │                      │                      │                                       │
│                   │                      │                      │                                       │
│                   └──────────┬──────┬────┘ Check all policies   │                                       │
│                              │      │          128 MAX          │                                       │
│                              │      │                           │                                       │
│                              │      └───────────────────────────┘                                       │
│                              │                                                                          │
│                              │                                                                          │
│                              │                                                                          │
│                              │     If user policies allow access to dst ip                              │
│                              │                    and                                                   │
│                              │       (either user is authorized                                         │
│                              │                   or                                                     │
│                              │        the route is public/always allowed)                               │
│                              │                                                                          │
│                              │                                                                          │
│                         ┌────▼───┐                                                                      │
│                         │        │                                                                      │
│                         │  PASS  │                                                                      │
│                         │        │                                                                      │
│                         └────────┘                                                                      │
│                                                                                                         │
│                                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

#define MAX_POLICIES 128
#define MAX_MAP_ENTRIES 1024
#define MAX_USERID_LENGTH 20 // Length of sha1 hash

// These definitions are used for searching the trie structure to determine the type of rule we've got.
#define STOP 0 // Signal stop searching array

#define ANY 0
#define PUBLIC 4
#define RANGE 8   // Port & protocol range e.g 22-2000
#define SINGLE 16 // Single port & protocol
#define DENY 32   // Deny flag

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

struct ip
{
    __u32 src_ip;
    __u16 src_port;

    __u32 dst_ip;
    __u16 dst_port;

    __u32 proto;
};

struct device
{
    __u64 sessionExpiry;
    __u64 lastPacketTime;

    // Hash of username (sha1 20 bytes)
    // Essentially allows us to compress all usernames, if collisions are a problem in the future we'll move to sha256 or xxhash
    char user_id[MAX_USERID_LENGTH];

    __u32 PAD;

    __u64 associatedNode;

} __attribute__((__packed__));


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

// A single variable that contains the node ID
struct bpf_map_def SEC("maps") node_Id = {
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


    // General index used to get things out of the map arrays
    __u32 index = 0;

    __u64 *current_node_id = bpf_map_lookup_elem(&node_Id, &index);
    if (current_node_id == NULL)
    {
        return 0;
    }

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

    // Get public and mfa policies for a user, the whole table will be searched as MFA rules take preference (and can fail early if it matches and the user is not authed)
    void *user_policies = bpf_map_lookup_elem(&policies_table, current_device->user_id);
    struct policy *applicable_policies = (user_policies != NULL) ? bpf_map_lookup_elem(user_policies, &key) : NULL;
    if (applicable_policies == NULL)
    {
        return 0;
    }

    if (!isTimedOut)
    {
        // Doesnt matter that this isnt thread safe
        current_device->lastPacketTime = currentTime;
    }

    int decision = 0;
    for (__u16 i = 0; i < MAX_POLICIES; i++)
    {

        __u32 key = i;
        struct policy policy = *(applicable_policies + key);

        // As the array is static in size, we want to be able to terminate the search asap
        if (policy.policy_type == STOP)
        {
            return decision;
        }

        //      ANY = 0
        //      If we match the protocol,
        //      If type is SINGLE and the port is either any, or equal
        //      OR
        //      If type is RANGE and the port is within bounds
        if ((policy.proto == ANY || policy.proto == ip_info->proto) &&
            ((policy.policy_type & SINGLE && (policy.lower_port == ANY || policy.lower_port == port)) ||
             (policy.policy_type & RANGE && (policy.lower_port <= port && policy.upper_port >= port))))
        {

            if (policy.policy_type & DENY)
            {
                // Deny rules take precedence over everything
                return 0;
            }
            else if (policy.policy_type & PUBLIC)
            {
                // If a public route matches, it may still be overriden by a MFA or a Deny policy so we have to check all policies
                decision = 1;
            }
            else
            {
                // MFA restrictions take precedence over public rules, so if we match an MFA policy under this route
                // Then we can fail/succeed fast

                // If device does not belong to a locked account, the device itself isnt locked and if it isnt timed out
                decision = (*current_node_id != current_device->associatedNode && 
                        !*isAccountLocked && !isTimedOut && current_device->sessionExpiry != 0 &&
                        // If either max session lifetime is disabled, or it is before the max lifetime of the session
                        (current_device->sessionExpiry == __UINT64_MAX__ || currentTime < current_device->sessionExpiry));

                // if we match an MFA policy, but are not authorised then immediately return 0 so we cant match another public rule
                // Otherwise continue to make sure we hit any deny rules that are present and match        
                if(!decision) {
                    return 0;
                }
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
