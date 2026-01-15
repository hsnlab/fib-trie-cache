package main

import (
	"github.com/spf13/cobra"
)

var (
	ifaceName string
	pinPath   string
)

var rootCmd = &cobra.Command{
	Use:   "fibctl",
	Short: "eBPF-based cached FIB lookup control",
	Long: `fibctl manages an XDP-based FIB lookup system with per-CPU LRU caching.

The system maintains a global LPM trie for FIB entries and per-CPU LRU caches
for fast /32 lookups. This enables cahced IP forwarding for benchmarks.`,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&ifaceName, "interface", "i", "", "Network interface name")
	rootCmd.PersistentFlags().StringVarP(&pinPath, "pin-path", "p", "/sys/fs/bpf/fibctl", "BPF filesystem pin path")
}
