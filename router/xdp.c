// +build ignore

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
                                                                 │                            │
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

struct device
{
    // Hash of username (sha1 20 bytes)
    // Essentially allows us to compress all usernames, if collisions are a problem in the future we'll move to sha256 or xxhash
    char user_id[MAX_USERID_LENGTH];
    __u64 sessionExpiry;
    __u64 lastPacketTime;
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
    __u32 addr;      // rest can be arbitrary
};

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
static __always_inline int parse_ip_src_dst_addr(struct xdp_md *ctx, __u32 *ip_src_addr, __u32 *ip_dst_addr)
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

    // Return the source IP address in network byte order.
    *ip_src_addr = (__u32)(ip->saddr);
    *ip_dst_addr = (__u32)(ip->daddr);

    return 1;
}

static __always_inline int conntrack(__u32 *src_ip, __u32 *dst_ip)
{

    // Find device
    struct device *current_device = bpf_map_lookup_elem(&devices, src_ip);
    if (!current_device)
    {
        return 0;
    }

    // Check if the account exists
    __u32 *isLocked = bpf_map_lookup_elem(&account_locked, src_ip);
    if (!isLocked)
    {
        return 0;
    }

    // Our userland defined inactivity timeout
    u32 index = 0;
    __u64 *inactivity_timeout = bpf_map_lookup_elem(&inactivity_timeout_minutes, &index);
    if (!inactivity_timeout)
    {
        return 0;
    }

    __u64 currentTime = bpf_ktime_get_boot_ns();

    // The inner map must be a LPM trie
    struct ip4_trie_key key = {
        .prefixlen = 32,
        .addr = *dst_ip,
    };

    u8 isTimedOut = (*inactivity_timeout != __UINT64_MAX__ && ((currentTime - current_device->lastPacketTime) >= *inactivity_timeout));

    // Order of preference is MFA -> Public, just in case someone adds multiple entries for the same route to make sure accidental exposure is less likely
    // If the key is a match for the LPM in the public table
    void *user_restricted_routes = bpf_map_lookup_elem(&mfa_table, current_device->user_id);
    if (user_restricted_routes && bpf_map_lookup_elem(user_restricted_routes, &key))
    {
        // If the inactivity timeout is not disabled and users session has timed out

        // If the account is NOT locked
        if (!*isLocked &&
            // If either max session lifetime is disabled, or it is before the max lifetime of the session
            (current_device->sessionExpiry == __UINT64_MAX__ || current_device->sessionExpiry > currentTime) &&
            !isTimedOut)
        {

            // Honestly, this susses me the fuck out
            current_device->lastPacketTime = currentTime;
            return 1;
        }

        // If we match a MFA route, but we are not authorised dont fall through to the public route lookup
        // just die
        return 0;
    }

    void *user_public_routes = bpf_map_lookup_elem(&public_table, current_device->user_id);
    if (user_public_routes && bpf_map_lookup_elem(user_public_routes, &key))
    {
        // Only update the lastpacket time if we're not expired
        if (!isTimedOut)
        {
            current_device->lastPacketTime = currentTime;
        }
        return 1;
    }

    return 0;
}

SEC("xdp")
int xdp_wag_firewall(struct xdp_md *ctx)
{
    __u32 src_ip, dst_ip;
    if (!parse_ip_src_dst_addr(ctx, &src_ip, &dst_ip))
    {
        return XDP_DROP;
    }

    if (conntrack(&src_ip, &dst_ip) || conntrack(&dst_ip, &src_ip))
    {

        return XDP_PASS;
    }

    return XDP_DROP;
}
