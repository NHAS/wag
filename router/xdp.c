// +build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// One /24
#define MAX_MAP_ENTRIES 256

// Inner map is a LPM tri, so we use this as the key
struct ip4_trie_key
{
    __u32 prefixlen; // first member must be u32
    __u32 addr;      // rest can are arbitrary
};

struct bpf_map_def SEC("maps") allowance_table = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .max_entries = MAX_MAP_ENTRIES,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
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
    void *innerMap = bpf_map_lookup_elem(&allowance_table, src_ip);

    // The inner map should be a LPM trie
    struct ip4_trie_key key = {
        .prefixlen = 32,
        .addr = *dst_ip,
    };

    return innerMap && bpf_map_lookup_elem(innerMap, &key);
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
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
