package fib

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// cacheSize must match CACHE_SIZE in bpf/fib.c.
// This is used for cache invalidation (iterating all possible slots).
const cacheSize = 65536

// invalidateCacheLocked clears all entries from the per-CPU direct-mapped cache.
// This is called after any trie modification to ensure consistency.
// Caller must hold m.mu.
func (m *Manager) invalidateCacheLocked() error {
	// Direct-mapped cache: iterate all possible slot indices and delete.
	// This is O(cacheSize) regardless of actual entries, but ensures
	// complete invalidation.
	for slot := uint32(0); slot < cacheSize; slot++ {
		// Ignore errors - slot may be empty.
		_ = m.objs.FibCache.Delete(slot)
	}

	return nil
}

// InvalidateCache clears all entries from the per-CPU direct-mapped cache.
// Thread-safe version for external callers.
func (m *Manager) InvalidateCache() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	return m.invalidateCacheLocked()
}

// SetCacheEnabled enables or disables the cache.
func (m *Manager) SetCacheEnabled(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	cfg := bpfConfig{CacheEnabled: 0}
	if enabled {
		cfg.CacheEnabled = 1
	}

	if err := m.objs.ConfigMap.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}

	return nil
}

// IsCacheEnabled returns whether caching is currently enabled.
func (m *Manager) IsCacheEnabled() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return false, fmt.Errorf("program not loaded")
	}

	var cfg bpfConfig
	if err := m.objs.ConfigMap.Lookup(uint32(0), &cfg); err != nil {
		return false, fmt.Errorf("looking up config: %w", err)
	}

	return cfg.CacheEnabled != 0, nil
}

// Reset clears both the FIB trie and the cache.
func (m *Manager) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	// Clear cache first.
	if err := m.invalidateCacheLocked(); err != nil {
		return fmt.Errorf("clearing cache: %w", err)
	}

	// Clear FIB trie.
	var key bpfLpmKey
	var value bpfFwdInfo
	var keysToDelete []bpfLpmKey

	iter := m.objs.FibTrie.Iterate()
	for iter.Next(&key, &value) {
		keysToDelete = append(keysToDelete, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating trie: %w", err)
	}

	for _, k := range keysToDelete {
		_ = m.objs.FibTrie.Delete(k)
	}

	// Reset statistics.
	return m.resetStatsLocked()
}

// GetCacheCount returns the approximate number of entries in the cache.
// Note: For direct-mapped PERCPU_HASH, this iterates all keys which may be slow.
func (m *Manager) GetCacheCount() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return 0, fmt.Errorf("program not loaded")
	}

	var count int
	var slot uint32
	var values []bpfCacheEntry // Slice for per-CPU values
	iter := m.objs.FibCache.Iterate()
	for iter.Next(&slot, &values) {
		count++
	}
	return count, iter.Err()
}
