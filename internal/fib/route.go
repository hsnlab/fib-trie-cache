package fib

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"

	"fibctl/internal/netutil"
)

// AddRoute adds a single route to the FIB trie.
func (m *Manager) AddRoute(prefix net.IPNet, nextHop net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	// Resolve forwarding info from next-hop.
	fwd, err := netutil.ResolveNextHop(nextHop)
	if err != nil {
		return fmt.Errorf("resolving next-hop %s: %w", nextHop, err)
	}

	// Build LPM key.
	ones, _ := prefix.Mask.Size()
	key := bpfLpmKey{
		Prefixlen: uint32(ones),
		Addr:      netutil.IPToU32(prefix.IP),
	}

	// Convert netutil.FwdInfo to BPF fwd_info type.
	fwdInfo := bpfFwdInfo{
		NextHop: fwd.NextHop,
		Ifindex: fwd.Ifindex,
	}
	copy(fwdInfo.SrcMac[:], fwd.SrcMac[:])
	copy(fwdInfo.DstMac[:], fwd.DstMac[:])

	// Update the trie.
	if err := m.objs.FibTrie.Update(key, fwdInfo, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating FIB trie: %w", err)
	}

	// Register interface in DEVMAP for redirect.
	if err := m.objs.TxPorts.Update(fwdInfo.Ifindex, fwdInfo.Ifindex, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating tx_ports: %w", err)
	}

	// Invalidate cache on any trie modification.
	if err := m.invalidateCacheLocked(); err != nil {
		return fmt.Errorf("invalidating cache: %w", err)
	}

	return nil
}

// AddRouteWithInfo adds a route with pre-resolved forwarding info.
// Useful for bulk imports where we want to batch ARP resolution.
func (m *Manager) AddRouteWithInfo(prefix net.IPNet, fwdInfo bpfFwdInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	// Build LPM key.
	ones, _ := prefix.Mask.Size()
	key := bpfLpmKey{
		Prefixlen: uint32(ones),
		Addr:      netutil.IPToU32(prefix.IP),
	}

	// Update the trie.
	if err := m.objs.FibTrie.Update(key, fwdInfo, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating FIB trie: %w", err)
	}

	// Register interface in DEVMAP for redirect.
	if err := m.objs.TxPorts.Update(fwdInfo.Ifindex, fwdInfo.Ifindex, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating tx_ports: %w", err)
	}

	return nil
}

// RemoveRoute removes a route from the FIB trie.
func (m *Manager) RemoveRoute(prefix net.IPNet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return fmt.Errorf("program not loaded")
	}

	ones, _ := prefix.Mask.Size()
	key := bpfLpmKey{
		Prefixlen: uint32(ones),
		Addr:      netutil.IPToU32(prefix.IP),
	}

	if err := m.objs.FibTrie.Delete(key); err != nil {
		return fmt.Errorf("deleting from FIB trie: %w", err)
	}

	// Invalidate cache on any trie modification.
	if err := m.invalidateCacheLocked(); err != nil {
		return fmt.Errorf("invalidating cache: %w", err)
	}

	return nil
}

// ImportRoutes imports routes from a file.
// Format: "prefix/prefix-len next-hop-IP" per line.
// Returns the number of routes successfully imported.
func (m *Manager) ImportRoutes(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// First pass: collect all unique next-hops and resolve them.
	nextHops := make(map[string]net.IP)
	type routeEntry struct {
		prefix  net.IPNet
		nextHop string
	}
	var routes []routeEntry

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			return 0, fmt.Errorf("invalid line format: %s", line)
		}

		_, prefix, err := net.ParseCIDR(parts[0])
		if err != nil {
			return 0, fmt.Errorf("parsing prefix %s: %w", parts[0], err)
		}

		nextHop := net.ParseIP(parts[1])
		if nextHop == nil {
			return 0, fmt.Errorf("parsing next-hop %s", parts[1])
		}

		nextHopStr := nextHop.String()
		nextHops[nextHopStr] = nextHop
		routes = append(routes, routeEntry{prefix: *prefix, nextHop: nextHopStr})
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scanning file: %w", err)
	}

	// Resolve all unique next-hops.
	fmt.Printf("Resolving %d unique next-hops...\n", len(nextHops))
	fwdInfos := make(map[string]*netutil.FwdInfo)
	for nhStr, nh := range nextHops {
		fwd, err := netutil.ResolveNextHop(nh)
		if err != nil {
			return 0, fmt.Errorf("resolving next-hop %s: %w", nh, err)
		}
		fwdInfos[nhStr] = fwd
	}

	// Lock and add all routes.
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return 0, fmt.Errorf("program not loaded")
	}

	// Register all interfaces in DEVMAP first.
	for _, fwd := range fwdInfos {
		if err := m.objs.TxPorts.Update(fwd.Ifindex, fwd.Ifindex, ebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("updating tx_ports for ifindex %d: %w", fwd.Ifindex, err)
		}
	}

	// Add all routes.
	var count int
	for _, r := range routes {
		fwd := fwdInfos[r.nextHop]
		ones, _ := r.prefix.Mask.Size()
		key := bpfLpmKey{
			Prefixlen: uint32(ones),
			Addr:      netutil.IPToU32(r.prefix.IP),
		}

		fwdInfo := bpfFwdInfo{
			NextHop: fwd.NextHop,
			Ifindex: fwd.Ifindex,
		}
		copy(fwdInfo.SrcMac[:], fwd.SrcMac[:])
		copy(fwdInfo.DstMac[:], fwd.DstMac[:])

		if err := m.objs.FibTrie.Update(key, fwdInfo, ebpf.UpdateAny); err != nil {
			return count, fmt.Errorf("adding route %s: %w", r.prefix.String(), err)
		}
		count++

		if count%10000 == 0 {
			fmt.Printf("Imported %d routes...\n", count)
		}
	}

	// Invalidate cache after all routes are added.
	if err := m.invalidateCacheLocked(); err != nil {
		return count, fmt.Errorf("invalidating cache: %w", err)
	}

	return count, nil
}

// GetRouteCount returns the number of routes in the FIB trie.
func (m *Manager) GetRouteCount() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.objs == nil {
		return 0, fmt.Errorf("program not loaded")
	}

	var count int
	var key bpfLpmKey
	var value bpfFwdInfo
	iter := m.objs.FibTrie.Iterate()
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}
