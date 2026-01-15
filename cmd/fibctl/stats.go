package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var (
	statsInterval  time.Duration
	statsThreshold uint64
	statsWatch     bool
	statsPerCPU    bool
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Display FIB statistics",
	Long: `Display statistics about packet processing, cache hits/misses, and forwarding.

Use -w/--watch to continuously monitor statistics.
Statistics are aggregated from all CPUs by default.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if statsWatch {
			fmt.Printf("Watching statistics (interval: %s, threshold: %d packets)...\n",
				statsInterval, statsThreshold)
			fmt.Println("Press Ctrl+C to stop.")
			return mgr.WatchStats(statsInterval, statsThreshold)
		}

		if statsPerCPU {
			return mgr.PrintPerCPUStats()
		}

		return mgr.PrintStats()
	},
}

var resetStatsCmd = &cobra.Command{
	Use:   "reset-stats",
	Short: "Reset statistics counters to zero",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := fib.NewManager(pinPath)
		if err := mgr.LoadFromPin(); err != nil {
			return fmt.Errorf("loading pinned maps: %w", err)
		}
		defer mgr.Close()

		if err := mgr.ResetStats(); err != nil {
			return fmt.Errorf("resetting stats: %w", err)
		}

		fmt.Println("Statistics counters have been reset to zero.")
		return nil
	},
}

func init() {
	statsCmd.Flags().DurationVarP(&statsInterval, "interval", "n", 100*time.Millisecond, "Stats polling interval")
	statsCmd.Flags().Uint64VarP(&statsThreshold, "threshold", "t", 100000, "Packet threshold for printing")
	statsCmd.Flags().BoolVarP(&statsWatch, "watch", "w", false, "Continuously watch statistics")
	statsCmd.Flags().BoolVar(&statsPerCPU, "per-cpu", false, "Show per-CPU statistics")
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(resetStatsCmd)
}
