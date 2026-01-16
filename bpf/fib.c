// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// XDP-based cached FIB lookup program.
// Maintains a global LPM trie for FIB entries and per-CPU LRU caches
// for fast /32 lookups.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// LPM trie key for IPv4 prefix lookup.
struct lpm_key {
    __u32 prefixlen;  // Prefix length in bits (0-32 for IPv4).
    __u32 addr;       // IPv4 address in network byte order.
};

// Forwarding information stored in both trie and cache.
struct fwd_info {
    __u32 next_hop;           // Next-hop IPv4 address (network order).
    __u32 ifindex;            // Output interface index.
    __u8  src_mac[ETH_ALEN];  // Source MAC (interface MAC).
    __u8  dst_mac[ETH_ALEN];  // Destination MAC (next-hop MAC).
};

// Cache key: just the destination IP (/32 lookup).
struct cache_key {
    __u32 dst_ip;  // Destination IP in network byte order.
};

// Per-CPU statistics counters.
struct stats {
    __u64 packets;     // Total packets processed.
    __u64 cache_hits;  // Cache hits.
    __u64 cache_miss;  // Cache misses (required trie lookup).
    __u64 fwd_ok;      // Successfully forwarded packets.
    __u64 fwd_fail;    // Failed forwarding (no route, etc.).
};

// Configuration flags.
struct config {
    __u32 cache_enabled;  // 0 = disabled, 1 = enabled.
};

// LPM trie for FIB entries (millions of routes).
// BPF_F_NO_PREALLOC is REQUIRED for LPM_TRIE maps.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, struct fwd_info);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 10000000);  // 10M routes.
} fib_trie SEC(".maps");

// Per-CPU LRU cache for /32 lookups.
// Provides fast path for repeated destination IPs.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct cache_key);
    __type(value, struct fwd_info);
    __uint(max_entries, 65536);  // 64K entries per CPU.
} fib_cache SEC(".maps");

// Per-CPU statistics array.
// Single entry (index 0) holds all counters.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// Configuration array (single entry).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Device map for bpf_redirect_map (faster than bpf_redirect).
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);  // Max interfaces to redirect to.
} tx_ports SEC(".maps");

// Update IP header checksum incrementally after TTL decrement.
static __always_inline void update_ip_checksum(struct iphdr *ip)
{
    __u32 csum = ip->check;
    csum = ~csum & 0xFFFF;
    // TTL is in the high byte of the 16-bit word at offset 8.
    // When TTL decrements by 1, the checksum increases by 0x0100.
    csum += 0x0100;
    // Fold carry.
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;
}

SEC("xdp")
int xdp_fib_lookup(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Update statistics.
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
    if (!s)
        return XDP_PASS;

    s->packets++;

    // Get configuration.
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return XDP_PASS;

    struct fwd_info *fwd = NULL;
    __u32 dst_ip = ip->daddr;

    // Step 1: Check per-CPU cache if enabled.
    if (cfg->cache_enabled) {
        struct cache_key ck = { .dst_ip = dst_ip };
        fwd = bpf_map_lookup_elem(&fib_cache, &ck);

        // Validate cache entry: with LRU_PERCPU_HASH, each CPU has its own
        // value. CPUs that haven't seen this flow will have zeroed entries
        // (ifindex=0). Only use cache if entry is valid.
        if (fwd && fwd->ifindex != 0) {
            s->cache_hits++;
            goto forward;
        }
        s->cache_miss++;
    }

    // Step 2: LPM trie lookup.
    struct lpm_key lk = {
        .prefixlen = 32,  // Full match for longest prefix.
        .addr = dst_ip,
    };

    fwd = bpf_map_lookup_elem(&fib_trie, &lk);
    if (!fwd) {
        s->fwd_fail++;
        return XDP_PASS;  // No route, pass to kernel stack.
    }

    // Step 3: Cache the result if caching is enabled.
    if (cfg->cache_enabled) {
        struct cache_key ck = { .dst_ip = dst_ip };
        // LRU_PERCPU_HASH auto-evicts oldest entries when full.
        bpf_map_update_elem(&fib_cache, &ck, fwd, BPF_ANY);
        // Re-lookup to get a valid pointer after update.
        fwd = bpf_map_lookup_elem(&fib_cache, &ck);
        if (!fwd) {
            // Fallback: re-lookup from trie.
            fwd = bpf_map_lookup_elem(&fib_trie, &lk);
            if (!fwd) {
                s->fwd_fail++;
                return XDP_PASS;
            }
        }
    }

forward:
    // Check TTL.
    if (ip->ttl <= 1) {
        s->fwd_fail++;
        return XDP_PASS;  // TTL expired, let kernel handle ICMP.
    }

    // Decrement TTL and update checksum.
    ip->ttl--;
    update_ip_checksum(ip);

    // Rewrite MAC addresses.
    __builtin_memcpy(eth->h_dest, fwd->dst_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fwd->src_mac, ETH_ALEN);

    s->fwd_ok++;

    // Redirect to output interface using DEVMAP.
    return bpf_redirect_map(&tx_ports, fwd->ifindex, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
