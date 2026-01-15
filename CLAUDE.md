# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make           # Full build: deps → generate → build (use on fresh checkout)
make dev       # Regenerate + rebuild (after BPF changes)
make quick     # Build only (after Go-only changes, BPF unchanged)
make test      # Run all tests
make fmt       # Format Go and BPF code
make verify-bpf # Verify BPF code compiles
```

Note: `make build` alone fails on fresh checkout because it requires generated BPF files. Use `make` or `make generate` first.

## Architecture

fibctl implements XDP-based IP forwarding with a two-level lookup:
1. **Fast path**: Per-CPU LRU cache for /32 destination lookups (cache hits)
2. **Slow path**: Global LPM trie for prefix-based routing (cache misses)

### Key Components

- **bpf/fib.c**: XDP kernel program (eBPF C) - packet processing, maps, cache logic
- **internal/fib/**: Manager for BPF lifecycle, route management, stats, cache control
- **internal/netutil/**: Next-hop resolution (routing, ARP/MAC lookup via netlink)
- **cmd/fibctl/**: Cobra CLI commands

### BPF Maps (defined in bpf/fib.c)

| Map | Type | Purpose |
|-----|------|---------|
| `fib_trie` | LPM_TRIE | Global FIB (longest prefix match) |
| `fib_cache` | LRU_PERCPU_HASH | Per-CPU /32 cache |
| `stats_map` | PERCPU_ARRAY | Per-CPU counters |
| `config_map` | ARRAY | Runtime config |
| `tx_ports` | DEVMAP | Redirect interfaces |

### Data Flow

1. XDP parses IPv4 dst_ip
2. Check per-CPU LRU cache → hit = forward
3. Cache miss → LPM trie lookup
4. Cache result, rewrite MACs, XDP_REDIRECT

### Code Generation

`go generate` in internal/fib/ runs bpf2go to generate Go bindings from bpf/fib.c:
- `internal/fib/bpf_x86_bpfel.go` (amd64)
- `internal/fib/bpf_arm64_bpfel.go` (arm64)

## Key Types (internal/fib/types.go)

- `LpmKey`: Prefix + address for trie lookups
- `FwdInfo`: Next-hop IP, ifindex, src/dst MACs
- `CacheKey`: /32 destination IP
- `Stats`: Packets, cache hits/misses, fwd ok/fail
- `Manager`: Primary API for BPF lifecycle and operations

## Running fibctl

Requires root for XDP operations:
```bash
sudo fibctl load -i eth0       # Load and attach XDP
sudo fibctl import routes.txt  # Import routes
sudo fibctl stats -w           # Watch stats
sudo fibctl unload             # Cleanup
```

## Cache Behavior

- Any trie modification (add/remove/import) invalidates entire cache
- Cache is per-CPU LRU: automatic eviction of oldest entries
- Enable/disable cache at runtime for baseline comparison
