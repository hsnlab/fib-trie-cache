package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import routes from a file",
	Long: `Import routes from a file in bulk.

File format: one route per line, "prefix/len next-hop-ip"
Lines starting with # are comments.

Example file content:
  # My routes
  10.0.0.0/8 192.168.1.1
  172.16.0.0/12 192.168.1.2

Usage:
  fibctl import routes.txt`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filename := args[0]

		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		count, err := mgr.ImportRoutes(filename)
		if err != nil {
			return fmt.Errorf("importing routes: %w (imported %d routes before error)", err, count)
		}

		fmt.Printf("Successfully imported %d routes from %s\n", count, filename)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(importCmd)
}
