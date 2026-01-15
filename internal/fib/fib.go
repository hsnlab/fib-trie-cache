package fib

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Manager handles the lifecycle of the XDP FIB program.
type Manager struct {
	mu      sync.Mutex
	objs    *bpfObjects
	xdpLink link.Link
	iface   *net.Interface
	pinPath string
}

// NewManager creates a new FIB manager.
func NewManager(pinPath string) *Manager {
	return &Manager{
		pinPath: pinPath,
	}
}

// Load loads the XDP program and maps.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs != nil {
		return fmt.Errorf("program already loaded")
	}

	// Ensure pin path directory exists.
	if err := os.MkdirAll(m.pinPath, 0755); err != nil {
		return fmt.Errorf("creating pin path: %w", err)
	}

	objs := &bpfObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: m.pinPath,
		},
	}

	if err := loadBpfObjects(objs, opts); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	// Initialize config with caching enabled by default.
	cfg := Config{CacheEnabled: 1}
	if err := objs.ConfigMap.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		objs.Close()
		return fmt.Errorf("initializing config: %w", err)
	}

	m.objs = objs
	return nil
}

// LoadFromPin loads already-pinned maps without loading the program.
// Used for commands that operate on maps after the program is loaded.
func (m *Manager) LoadFromPin() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs != nil {
		return nil // Already loaded.
	}

	// Try to load pinned maps.
	objs := &bpfObjects{}

	fibTrie, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "fib_trie"), nil)
	if err != nil {
		return fmt.Errorf("loading pinned fib_trie: %w", err)
	}
	objs.FibTrie = fibTrie

	fibCache, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "fib_cache"), nil)
	if err != nil {
		fibTrie.Close()
		return fmt.Errorf("loading pinned fib_cache: %w", err)
	}
	objs.FibCache = fibCache

	statsMap, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "stats_map"), nil)
	if err != nil {
		fibTrie.Close()
		fibCache.Close()
		return fmt.Errorf("loading pinned stats_map: %w", err)
	}
	objs.StatsMap = statsMap

	configMap, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "config_map"), nil)
	if err != nil {
		fibTrie.Close()
		fibCache.Close()
		statsMap.Close()
		return fmt.Errorf("loading pinned config_map: %w", err)
	}
	objs.ConfigMap = configMap

	txPorts, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "tx_ports"), nil)
	if err != nil {
		fibTrie.Close()
		fibCache.Close()
		statsMap.Close()
		configMap.Close()
		return fmt.Errorf("loading pinned tx_ports: %w", err)
	}
	objs.TxPorts = txPorts

	m.objs = objs
	return nil
}

// Attach attaches the XDP program to the specified interface.
func (m *Manager) Attach(ifaceName string, mode link.XDPAttachFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.XdpFibLookup,
		Interface: iface.Index,
		Flags:     mode,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}

	// Pin the link for persistence.
	linkPath := filepath.Join(m.pinPath, "xdp_link")
	if err := l.Pin(linkPath); err != nil {
		// Non-fatal: link pinning may not be supported.
		fmt.Printf("Warning: could not pin XDP link: %v\n", err)
	}

	m.xdpLink = l
	m.iface = iface
	return nil
}

// Detach detaches the XDP program from the interface.
func (m *Manager) Detach() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.xdpLink == nil {
		// Try to load pinned link.
		linkPath := filepath.Join(m.pinPath, "xdp_link")
		l, err := link.LoadPinnedLink(linkPath, nil)
		if err == nil {
			m.xdpLink = l
		}
	}

	if m.xdpLink != nil {
		if err := m.xdpLink.Close(); err != nil {
			return fmt.Errorf("closing XDP link: %w", err)
		}
		m.xdpLink = nil
	}

	// Remove pinned link file.
	linkPath := filepath.Join(m.pinPath, "xdp_link")
	os.Remove(linkPath)

	return nil
}

// Unload detaches XDP and closes all resources.
func (m *Manager) Unload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	if m.xdpLink != nil {
		if err := m.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP link: %w", err))
		}
		m.xdpLink = nil
	}

	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing BPF objects: %w", err))
		}
		m.objs = nil
	}

	// Clean up pinned files.
	os.RemoveAll(m.pinPath)

	if len(errs) > 0 {
		return fmt.Errorf("unload errors: %v", errs)
	}
	return nil
}

// Close closes the manager without removing pinned maps.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			return fmt.Errorf("closing BPF objects: %w", err)
		}
		m.objs = nil
	}
	return nil
}

// Objects returns the underlying BPF objects for direct access.
func (m *Manager) Objects() *bpfObjects {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objs
}

// IsLoaded returns true if the program is loaded.
func (m *Manager) IsLoaded() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objs != nil
}
