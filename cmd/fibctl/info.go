package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show FIB information",
	Long:  `Display information about the current FIB state including route count and cache status.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		// Get route count.
		routeCount, err := mgr.GetRouteCount()
		if err != nil {
			return fmt.Errorf("getting route count: %w", err)
		}

		// Get cache status.
		cacheEnabled, err := mgr.IsCacheEnabled()
		if err != nil {
			return fmt.Errorf("getting cache status: %w", err)
		}

		// Get cache count.
		cacheCount, err := mgr.GetCacheCount()
		if err != nil {
			return fmt.Errorf("getting cache count: %w", err)
		}

		// Get stats.
		stats, err := mgr.GetStats()
		if err != nil {
			return fmt.Errorf("getting stats: %w", err)
		}

		cacheStatus := "disabled"
		if cacheEnabled {
			cacheStatus = "enabled"
		}

		hitRate := float64(0)
		if stats.CacheHits+stats.CacheMiss > 0 {
			hitRate = float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMiss) * 100
		}

		fmt.Println("FIB Information")
		fmt.Println("===============")
		fmt.Printf("Routes in trie:  %d\n", routeCount)
		fmt.Printf("Cache status:    %s\n", cacheStatus)
		fmt.Printf("Cache entries:   ~%d\n", cacheCount)
		fmt.Printf("Total packets:   %d\n", stats.Packets)
		fmt.Printf("Cache hit rate:  %.2f%%\n", hitRate)
		fmt.Printf("Pin path:        %s\n", pinPath)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
