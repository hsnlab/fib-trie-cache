// Package fib provides the FIB manager for the XDP-based cached FIB lookup system.
package fib

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 bpf ../../bpf/fib.c -- -I/usr/include

// LpmKey matches struct lpm_key in the BPF program.
type LpmKey struct {
	Prefixlen uint32
	Addr      uint32 // Network byte order.
}

// FwdInfo matches struct fwd_info in the BPF program.
type FwdInfo struct {
	NextHop uint32
	Ifindex uint32
	SrcMac  [6]byte
	DstMac  [6]byte
}

// CacheKey matches struct cache_key in the BPF program.
type CacheKey struct {
	DstIP uint32 // Network byte order.
}

// Stats matches struct stats in the BPF program.
type Stats struct {
	Packets   uint64
	CacheHits uint64
	CacheMiss uint64
	FwdOk     uint64
	FwdFail   uint64
}

// Config matches struct config in the BPF program.
type Config struct {
	CacheEnabled uint32
}
