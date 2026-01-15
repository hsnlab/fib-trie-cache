package main

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var addCmd = &cobra.Command{
	Use:   "add <prefix/len> <next-hop>",
	Short: "Add a route to the FIB",
	Long: `Add a single route to the FIB trie.

The next-hop will be automatically resolved to find the output interface
and MAC addresses via the routing table and ARP cache.

Example:
  fibctl add 10.0.0.0/8 192.168.1.1`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, prefix, err := net.ParseCIDR(args[0])
		if err != nil {
			return fmt.Errorf("invalid prefix %s: %w", args[0], err)
		}

		nextHop := net.ParseIP(args[1])
		if nextHop == nil {
			return fmt.Errorf("invalid next-hop IP: %s", args[1])
		}

		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.AddRoute(*prefix, nextHop); err != nil {
			return fmt.Errorf("adding route: %w", err)
		}

		fmt.Printf("Added route: %s -> %s\n", prefix, nextHop)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
