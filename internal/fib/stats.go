package fib

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

// AggregatedStats holds aggregated statistics from all CPUs.
type AggregatedStats struct {
	Packets   uint64
	CacheHits uint64
	CacheMiss uint64
	FwdOk     uint64
	FwdFail   uint64
	Timestamp time.Time
}

// GetStats retrieves and aggregates statistics from all CPUs.
func (m *Manager) GetStats() (*AggregatedStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return nil, fmt.Errorf("program not loaded")
	}

	// For PERCPU_ARRAY, we need to read all CPU values.
	// The cilium/ebpf library handles this automatically.
	var perCPUValues []bpfStats
	if err := m.objs.StatsMap.Lookup(uint32(0), &perCPUValues); err != nil {
		return nil, fmt.Errorf("looking up stats: %w", err)
	}

	// Aggregate across all CPUs.
	agg := &AggregatedStats{
		Timestamp: time.Now(),
	}
	for _, s := range perCPUValues {
		agg.Packets += s.Packets
		agg.CacheHits += s.CacheHits
		agg.CacheMiss += s.CacheMiss
		agg.FwdOk += s.FwdOk
		agg.FwdFail += s.FwdFail
	}

	return agg, nil
}

// GetPerCPUStats retrieves per-CPU statistics.
func (m *Manager) GetPerCPUStats() ([]bpfStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return nil, fmt.Errorf("program not loaded")
	}

	var perCPUValues []bpfStats
	if err := m.objs.StatsMap.Lookup(uint32(0), &perCPUValues); err != nil {
		return nil, fmt.Errorf("looking up stats: %w", err)
	}

	return perCPUValues, nil
}

// resetStatsLocked zeroes all statistics counters.
// Caller must hold m.mu.
func (m *Manager) resetStatsLocked() error {
	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	// Get number of CPUs.
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("getting CPU count: %w", err)
	}

	// Create zeroed per-CPU values.
	zeroStats := make([]bpfStats, numCPUs)

	if err := m.objs.StatsMap.Update(uint32(0), zeroStats, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("resetting stats: %w", err)
	}

	return nil
}

// ResetStats zeroes all statistics counters.
func (m *Manager) ResetStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resetStatsLocked()
}

// WatchStats prints statistics at configurable intervals.
// It prints every N packets or every interval, whichever comes first.
func (m *Manager) WatchStats(interval time.Duration, packetThreshold uint64) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Set up signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var lastPackets uint64

	for {
		select {
		case <-sigCh:
			fmt.Println("\nStopped watching stats.")
			return nil
		case <-ticker.C:
			stats, err := m.GetStats()
			if err != nil {
				return err
			}

			// Check if we've crossed a packet threshold.
			if stats.Packets >= lastPackets+packetThreshold || stats.Packets > lastPackets {
				hitRate := float64(0)
				if stats.CacheHits+stats.CacheMiss > 0 {
					hitRate = float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMiss) * 100
				}

				fmt.Printf("[%s] Packets: %d, Hits: %d, Miss: %d (%.1f%% hit rate), Fwd: %d, Fail: %d\n",
					stats.Timestamp.Format("15:04:05"),
					stats.Packets, stats.CacheHits, stats.CacheMiss, hitRate,
					stats.FwdOk, stats.FwdFail)

				// Update lastPackets to nearest threshold.
				if stats.Packets >= lastPackets+packetThreshold {
					lastPackets = (stats.Packets / packetThreshold) * packetThreshold
				}
			}
		}
	}
}

// PrintStats prints current statistics once.
func (m *Manager) PrintStats() error {
	stats, err := m.GetStats()
	if err != nil {
		return err
	}

	hitRate := float64(0)
	if stats.CacheHits+stats.CacheMiss > 0 {
		hitRate = float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMiss) * 100
	}

	fmt.Printf("Packets:    %d\n", stats.Packets)
	fmt.Printf("Cache Hits: %d\n", stats.CacheHits)
	fmt.Printf("Cache Miss: %d\n", stats.CacheMiss)
	fmt.Printf("Hit Rate:   %.2f%%\n", hitRate)
	fmt.Printf("Forwarded:  %d\n", stats.FwdOk)
	fmt.Printf("Failed:     %d\n", stats.FwdFail)

	return nil
}

// PrintPerCPUStats prints per-CPU statistics.
func (m *Manager) PrintPerCPUStats() error {
	perCPU, err := m.GetPerCPUStats()
	if err != nil {
		return err
	}

	fmt.Println("Per-CPU Statistics:")
	fmt.Println("CPU\tPackets\t\tHits\t\tMiss\t\tFwd\t\tFail")
	for i, s := range perCPU {
		fmt.Printf("%d\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n",
			i, s.Packets, s.CacheHits, s.CacheMiss, s.FwdOk, s.FwdFail)
	}

	return nil
}
