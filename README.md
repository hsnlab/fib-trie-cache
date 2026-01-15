# fibctl - eBPF Cached FIB Lookup System

An XDP-based IP forwarding system with per-CPU LRU caching, designed to evaluate cached FIB lookup scaling properties.

## Architecture

```
                         XDP Program (per-packet)
┌────────────────────────────────────────────────────────────────┐
│  1. Parse IPv4 dst_ip                                          │
│  2. Lookup per-CPU LRU cache (/32)  ──hit──►  forward          │
│            │ miss                                              │
│            ▼                                                   │
│  3. Lookup global LPM trie (prefixes)                          │
│            │                                                   │
│            ▼                                                   │
│  4. Cache result, rewrite MACs, XDP_REDIRECT                   │
└────────────────────────────────────────────────────────────────┘
```

## Building

```bash
make deps      # Install Go dependencies + bpf2go
make generate  # Generate eBPF Go bindings
make build     # Build bin/fibctl
```

Requirements: Go 1.21+, clang, Linux 5.x+ with BPF support.

## Quick Start

```bash
# 1. Prepare routes (rewrite next-hops for hairpin testing)
fibctl fib-rewrite data/full_fib.txt routes.txt --next-hop 192.168.1.1

# 2. Load XDP program
sudo fibctl load -i eth0

# 3. Import routes
sudo fibctl import routes.txt

# 4. Generate test traffic
fibctl pcap-gen routes.txt traffic.pcap --flow-size 10000 --packets 10000000

# 5. Run measurement (moongen, tcpreplay, etc.)
# ...

# 6. Watch stats
sudo fibctl stats -w

# 7. Cleanup
sudo fibctl unload
```

## Commands

### Program Lifecycle

| Command | Description |
|---------|-------------|
| `fibctl load -i <iface> [-m native\|generic]` | Load XDP and attach to interface |
| `fibctl unload` | Detach and remove all state |
| `fibctl info` | Show FIB info (routes, cache status, hit rate) |

### Route Management

| Command | Description |
|---------|-------------|
| `fibctl import <file>` | Bulk import routes from file |
| `fibctl add <prefix> <next-hop>` | Add single route |
| `fibctl remove <prefix>` | Remove route |
| `fibctl reset` | Clear all routes, cache, and stats |

Route file format:
```
# Comments start with #
10.0.0.0/8 192.168.1.1
172.16.0.0/12 192.168.1.2
```

### Cache Control

| Command | Description |
|---------|-------------|
| `fibctl cache enable` | Enable per-CPU caching |
| `fibctl cache disable` | Disable caching (baseline measurement) |
| `fibctl cache invalidate` | Clear all cache entries |
| `fibctl cache status` | Show cache status |

### Statistics

| Command | Description |
|---------|-------------|
| `fibctl stats` | Show current stats |
| `fibctl stats -w` | Watch continuously (prints every 100k pkts) |
| `fibctl stats --per-cpu` | Show per-CPU breakdown |
| `fibctl reset-stats` | Zero all counters |

### Test Data Generation

| Command | Description |
|---------|-------------|
| `fibctl fib-rewrite <in> <out> --next-hop <ip>` | Rewrite all next-hops (for hairpin) |
| `fibctl pcap-gen <fib> <out.pcap> [options]` | Generate test PCAP |

PCAP generation options:
```
--flow-size N     # Number of unique destination IPs (default: 1000)
--packets N       # Total packets to generate (default: 1000000)
--dist uniform    # Distribution: uniform or zipf
--zipf-s 1.5      # Zipf skew parameter (higher = more skewed)
--src-ip IP       # Source IP (default: 10.0.0.1)
--src-mac MAC     # Source MAC (default: 00:00:00:00:00:01)
--dst-mac MAC     # Destination MAC (default: 00:00:00:00:00:02)
```

## Measurement Workflow

### 1. Setup

```bash
# Configure NIC queues = number of CPUs
ethtool -L eth0 combined $NUM_CPUS

# Configure RSS to hash on dst IP only
ethtool -N eth0 rx-flow-hash udp4 d
```

### 2. Baseline (no cache)

```bash
sudo fibctl load -i eth0
sudo fibctl import routes.txt
sudo fibctl cache disable
sudo fibctl reset-stats

# Run traffic, record throughput
sudo fibctl stats
```

### 3. With Cache

```bash
sudo fibctl cache enable
sudo fibctl reset-stats

# Run traffic, record throughput
sudo fibctl stats
```

### 4. Scaling Test

Repeat with increasing CPU counts:
```bash
for cpus in 1 2 4 8 16; do
    # Adjust NIC queues
    ethtool -L eth0 combined $cpus
    # Pin traffic generator to use $cpus cores
    # Run test, collect stats
done
```

## Configuration

Default values (compile-time, in `bpf/fib.c`):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `fib_trie.max_entries` | 10M | Max routes in LPM trie |
| `fib_cache.max_entries` | 64K | Cache entries per CPU |
| `tx_ports.max_entries` | 256 | Max redirect interfaces |

BPF pin path: `/sys/fs/bpf/fibctl` (override with `-p`)

## Implementation Details

### Maps

| Map | Type | Purpose |
|-----|------|---------|
| `fib_trie` | LPM_TRIE | Global FIB (longest prefix match) |
| `fib_cache` | LRU_PERCPU_HASH | Per-CPU /32 cache |
| `stats_map` | PERCPU_ARRAY | Per-CPU counters |
| `config_map` | ARRAY | Runtime config (cache enable/disable) |
| `tx_ports` | DEVMAP | Redirect target interfaces |

### Next-Hop Resolution

When adding routes, `fibctl` automatically resolves:
1. **Output interface**: via `netlink.RouteGet(next_hop)`
2. **Source MAC**: from output interface
3. **Destination MAC**: via ARP cache lookup (triggers resolution if needed)

### Cache Invalidation

Any trie modification (add/remove/import) invalidates the entire cache to ensure consistency (LPM changes can affect any cached /32).

## License

GPL-2.0 OR BSD-3-Clause (eBPF program), MIT (Go code)
