package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the per-CPU cache",
	Long:  `Commands for managing the per-CPU LRU cache.`,
}

var enableCacheCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable the per-CPU cache",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.SetCacheEnabled(true); err != nil {
			return fmt.Errorf("enabling cache: %w", err)
		}

		fmt.Println("Cache enabled.")
		return nil
	},
}

var disableCacheCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable the per-CPU cache (direct trie lookup)",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.SetCacheEnabled(false); err != nil {
			return fmt.Errorf("disabling cache: %w", err)
		}

		fmt.Println("Cache disabled. All lookups will go directly to the LPM trie.")
		return nil
	},
}

var invalidateCacheCmd = &cobra.Command{
	Use:   "invalidate",
	Short: "Clear all entries from the cache",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.InvalidateCache(); err != nil {
			return fmt.Errorf("invalidating cache: %w", err)
		}

		fmt.Println("Cache invalidated.")
		return nil
	},
}

var statusCacheCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cache status",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		enabled, err := mgr.IsCacheEnabled()
		if err != nil {
			return fmt.Errorf("getting cache status: %w", err)
		}

		count, err := mgr.GetCacheCount()
		if err != nil {
			return fmt.Errorf("getting cache count: %w", err)
		}

		status := "disabled"
		if enabled {
			status = "enabled"
		}

		fmt.Printf("Cache Status: %s\n", status)
		fmt.Printf("Cache Entries: ~%d\n", count)
		return nil
	},
}

func init() {
	cacheCmd.AddCommand(enableCacheCmd)
	cacheCmd.AddCommand(disableCacheCmd)
	cacheCmd.AddCommand(invalidateCacheCmd)
	cacheCmd.AddCommand(statusCacheCmd)
	rootCmd.AddCommand(cacheCmd)
}
