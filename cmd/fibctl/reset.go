package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset the FIB, cache, and statistics",
	Long: `Clear all routes from the FIB trie, invalidate all caches,
and reset statistics counters to zero.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.Reset(); err != nil {
			return fmt.Errorf("resetting: %w", err)
		}

		fmt.Println("FIB, cache, and statistics have been reset.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(resetCmd)
}
