// +build ignore

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/bpf_common.h>

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/*
A massive oversimplifcation of what is in this file.

┌─────────────────────────────────────┐                      ┌───────────────────────────────────┐    ┌───────────────────────────────┐
│                User                 │◄───┐                 │           Devices                 │    │      Inactivity Timeout       │
│                                     │    │                 │            map                    │    │                               │
├─────────────────────────────────────┤    │                 │     key: ipv4 (u32)               │    │       uint64 (minutes)        │
│           Public Routes LPM         │    │                 │     val: sizeof(struct device)    │    │                               │
│              key uint32             │    │                 │                                   │    └───────────────────────────────┘
├─────────────────────────────────────┤    │                 └───────────────────────────────────┘
│           MFA Routes LPM            │    │
│              key uint32             │    │                     ┌────────────────────────────┐
├─────────────────────────────────────┤    │                     │     device   struct        │
│           AccountLocked             │    │                     │                            │
│               uint32                │    └─────────────────────┼─ userid         char[20]   │
└─────────────────────────────────────┘                          │  sessionExpiry  uint64     │
                                                                 │  lastPacketTime uint64     │
                                                                 │  deviceLock     uint32     │
                                                                 └────────────────────────────┘

    ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
    │                                                          Packet Flow                                                           │
    │                                                                                                                                │
    │                                                                                                                                │
    │                                                                                                                                │
    │                                                     │                                                                          │
    │                                        Input Packet │                                                                          │
    │                                                     │                                                                          │
    │                                             ┌───────▼───────┐                                                                  │
    │                                             │               │                                                       ┌────────┐ │
    │                                             │  Decode IPv4  │                  if packet not ipv4                   │        │ │
    │                                             │               │  ─────────────────────────────────────────────────────►  DROP  │ │
    │                                             │    Header     │                                                       │        │ │
    │                                             │               │                                                       └────────┘ │
    │                                             └───────┬───────┘                                                                  │
    │                                                     │                                                                          │
    │                                                     │                                                                          │
    │                                          src : u32  │                                                                          │
    │                                          dst : u32  │                                                                          │
    │                                                     │                                                                          │
    │                                                     │                                                                          │
    │                                        ┌────────────▼─────────────┐                                                            │
    │                                        │                          │                                                            │
    │                                        │       Lookup Device      │                                                            │
    │                                        │                          │                                                ┌────────┐  │
    │                                        │  device = (              │               not_found(device)                │        │  │
    │                                        │     valid(Devices[src])  │ ───────────────────────────────────────────────►  DROP  │  │
    │                                        │           or             │                                                │        │  │
    │                                        │     valid(Devices[dst])  │                                                └────────┘  │
    │                                        │  )                       │                                                            │
    │                                        │                          │                                                            │
    │                                        └────────────┬─────────────┘                                                            │
    │                                                     │                                                                          │
    │                                                     │                                                                          │
    │                                  userid : char[20]  │  device found                                                            │
    │                                                     │                                                                          │
    │                                                     │                                                                          │
    │                                         ┌───────────▼─────────────┐                                                            │
    │                                         │        Lookup User      │                                                            │
    │                                         │                         │                                                ┌────────┐  │
    │                                         │    user = users(        │                 not_found(userid)              │        │  │
    │                                         │      userid             │ ───────────────────────────────────────────────►  DROP  │  │
    │                                         │    )                    │                                                │        │  │
    │                                         │                         │                                                └────────┘  │
    │                                         └───────────┬─────────────┘                                                            │
    │                                                     │                                                                          │
    │                                                     │                                                                          │
    │                        device.LastPacketTime : u64  │                                                                          │
    │                                       dst_ip : u32  │                                                                          │
    │                                                     │                           user.isMFARoute(dst_ip)                        │
    │                                                     │                                    and                                   │
    │                user.isMFARoute(dst_ip)              │                         (user.AccountLocked or                           │
    │  ┌────────┐          and               ┌────────────▼────────────┐ time.Now-LastPacketTime >= InactivityTimeout or ┌────────┐  │
    │  │        │      isAuthorised          │        MFA Routes       │      user.SessionExpiry < time.Now)             │        │  │
    │  │  PASS  │◄────────────────────────── │         Check           │ ────────────────────────────────────────────────►  DROP  │  │
    │  │        │                            └────────────┬────────────┘                                                 │        │  │
    │  └────────┘                                         │                                                              └────────┘  │
    │                                       dst_ip : u32  │                                                                          │
    │                                                     │                                                                          │
    │  ┌────────┐                            ┌────────────▼────────────┐                                                             │
    │  │        │ user.isPublicRoute(dst_ip) │       Public Routes     │                                                             │
    │  │  PASS  │◄────────────────────────── │         Check           │                                                             │
    │  │        │                            └────────────┬────────────┘                                                             │
    │  └────────┘                                         │                                                                          │
    │                                                     │                                                                          │
    │                                                     │                                                                          │
    │                                                ┌────▼────┐                                                                     │
    │                                                │         │                                                                     │
    │                                                │   DROP  │                                                                     │
    │                                                │         │                                                                     │
    │                                                └─────────┘                                                                     │
    │                                                                                                                                │
    └────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

#define MAX_MAP_ENTRIES 1200
#define MAX_USERID_LENGTH 20 // Length of sha1 hash

// These definitions are used for searching the trie structure to determine the type of rule we've got.
#define ANY 0    // All ports and protocols
#define RANGE 1  // Port & protocol range e.g 22-2000
#define SINGLE 2 // Single port & protocol

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

    // rest can be arbitrary
    __u16 rule_type;

    __u16 proto;
    __u16 port;

    __u16 PAD1;

    __u32 addr;
} __attribute__((__packed__));

// Username  to LPM trie, value size *has* to be u32 as this is a HASH of MAPS
struct bpf_map_def SEC("maps") public_table = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .max_entries = MAX_MAP_ENTRIES,
    .key_size = MAX_USERID_LENGTH,
    .value_size = sizeof(__u32),
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") mfa_table = {
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

    switch (ip->protocol)
    {

    case IPPROTO_UDP:
    {

        struct udphdr *udph = (data + (ip->ihl * 4));

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

        struct tcphdr *tcph = (data + (ip->ihl * 4));

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
        struct icmphdr *icmph = (data + (ip->ihl * 4));

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

struct any
{
    __u16 proto;
    __u16 port;

    __u32 PAD1;
} __attribute__((__packed__));

struct range
{
    __u16 proto;
    __u16 lower_port;
    __u16 upper_port;

    __u16 PAD;
} __attribute__((__packed__));

// Value organised in big endian
// if ANY type this is a 2 byte proto type where 0 means all protocols. [2 bytes proto][6 empty]
//    RANGE type 2 bytes proto, 2 bytes lower port, 2 bytes upper port. [2 bytes proto][2 bytes lower][2 bytes upper][2 bytes empty]
//    SINGLE type, no meaning 1 byte for yes or no. [all empty]
static __always_inline int validate_rule(struct ip4_trie_key *key, void *table_result)
{
    switch (key->rule_type)
    {
    case ANY:
    {
        struct any *any_rule = (struct any *)table_result;
        // if the port is 0, then this is any port
        return (any_rule->proto == 0 || any_rule->proto == key->proto) && (any_rule->port == 0 || any_rule->port == key->port);
    }
    case RANGE:
    {
        struct range *range_rule = (struct range *)table_result;
        return (range_rule->proto == 0 || range_rule->proto == key->proto) && (key->port > range_rule->lower_port && key->port < range_rule->upper_port);
    }
    default:
    {

        // Single rule is done via the LPM itself. E.g the port and protocol are stored along with the IPv4 address so no active checking needs to happen here. If its a single then by its very nature we've matched.
        // Just doing an additional check for the NULL just to be 100% sure
        return (table_result != NULL);
    }
    }
}

static __always_inline int check(struct ip4_trie_key *key, struct device *current_device, __u64 currentTime, u8 isTimedOut, __u32 *isAccountLocked)
{
    // The inner maps must be a LPM trie

    // Order of preference is MFA -> Public, just in case someone adds multiple entries for the same route to make sure accidental exposure is less likely
    // If the key is a match for the LPM in the public table
    void *restricted_routes = bpf_map_lookup_elem(&mfa_table, current_device->user_id);

    void *mfa_result = (restricted_routes != NULL) ? bpf_map_lookup_elem(restricted_routes, key) : NULL;
    if (mfa_result != NULL)
    {
        bpf_printk("match mfa");

        // If device does not belong to a locked account and the device itself isnt locked and if it isnt timed out
        if (!*isAccountLocked && !isTimedOut && current_device->sessionExpiry != 0 &&
            // If either max session lifetime is disabled, or it is before the max lifetime of the session
            (current_device->sessionExpiry == __UINT64_MAX__ || currentTime < current_device->sessionExpiry))
        {

            if (!validate_rule(key, mfa_result))
            {
                return 0;
            }

            // Accessing pointers like this is very odd, and not regarding thread safety feels weird
            current_device->lastPacketTime = currentTime;

            return 1;
        }

        // If we match a MFA route, but we are not authorised dont fall through to the public route lookup
        // just die
        return 0;
    }

    void *public_routes = bpf_map_lookup_elem(&public_table, current_device->user_id);

    void *public_result = (public_routes != NULL) ? bpf_map_lookup_elem(public_routes, key) : NULL;
    if (public_result != NULL)
    {

        bpf_printk("match pub");

        if (!validate_rule(key, public_result))
        {
            return 0;
        }

        // Only update the lastpacket time if we're not expired
        if (!isTimedOut)
        {
            current_device->lastPacketTime = currentTime;
        }
        return 1;
    }

    return 0;
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

    bpf_printk("dst port: %d", __bpf_ntohs(port));

    // Check if the account exists
    __u32 *isAccountLocked = bpf_map_lookup_elem(&account_locked, current_device->user_id);
    if (isAccountLocked == NULL)
    {
        return 0;
    }

    // Our userland defined inactivity timeout
    u32 index = 0;
    __u64 *inactivity_timeout = bpf_map_lookup_elem(&inactivity_timeout_minutes, &index);
    if (inactivity_timeout == NULL)
    {
        return 0;
    }

    __u64 currentTime = bpf_ktime_get_boot_ns();

    // If the inactivity timeout is not disabled and users session has timed out
    u8 isTimedOut = (*inactivity_timeout != __UINT64_MAX__ && ((currentTime - current_device->lastPacketTime) >= *inactivity_timeout));

    struct ip4_trie_key key = {0};
    key.proto = ip_info->proto;

    key.prefixlen = 64;

    key.rule_type = ANY;
    if (check(&key, current_device, currentTime, isTimedOut, isAccountLocked))
    {
        return 1;
    }

    bpf_printk("failed any");

    key.rule_type = RANGE;
    if (check(&key, current_device, currentTime, isTimedOut, isAccountLocked))
    {
        return 1;
    }

    bpf_printk("failed range");

    key.port = port;
    key.addr = address;

    key.rule_type = SINGLE;
    if (check(&key, current_device, currentTime, isTimedOut, isAccountLocked))
    {
        return 1;
    }

    bpf_printk("failed single");

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
