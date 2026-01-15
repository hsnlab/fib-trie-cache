package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var unloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload the XDP FIB program",
	Long: `Detach the XDP program from the interface and remove all pinned maps.

This completely removes the program and all associated state.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)

		// Try to detach first.
		if err := mgr.Detach(); err != nil {
			fmt.Printf("Warning: could not detach XDP: %v\n", err)
		}

		// Then unload and clean up.
		if err := mgr.Unload(); err != nil {
			return fmt.Errorf("unloading: %w", err)
		}

		fmt.Println("XDP program unloaded and maps removed.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unloadCmd)
}
