package main

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var removeCmd = &cobra.Command{
	Use:   "remove <prefix/len>",
	Short: "Remove a route from the FIB",
	Long: `Remove a route from the FIB trie.

Example:
  fibctl remove 10.0.0.0/8`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, prefix, err := net.ParseCIDR(args[0])
		if err != nil {
			return fmt.Errorf("invalid prefix %s: %w", args[0], err)
		}

		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.RemoveRoute(*prefix); err != nil {
			return fmt.Errorf("removing route: %w", err)
		}

		fmt.Printf("Removed route: %s\n", prefix)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(removeCmd)
}
