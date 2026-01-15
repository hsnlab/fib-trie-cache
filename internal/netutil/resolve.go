// Package netutil provides network utilities for next-hop resolution.
package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

// FwdInfo contains forwarding information for a next-hop.
type FwdInfo struct {
	NextHop uint32
	Ifindex uint32
	SrcMac  [6]byte
	DstMac  [6]byte
}

// ResolveNextHop resolves a next-hop IP to full forwarding information.
// Steps: next-hop -> route lookup -> interface -> interface MAC + ARP for next-hop MAC.
func ResolveNextHop(nextHop net.IP) (*FwdInfo, error) {
	nextHop = nextHop.To4()
	if nextHop == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	// Step 1: Find route to next-hop to determine output interface.
	routes, err := netlink.RouteGet(nextHop)
	if err != nil {
		return nil, fmt.Errorf("route lookup for %s: %w", nextHop, err)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no route to %s", nextHop)
	}

	route := routes[0]
	ifindex := route.LinkIndex

	// Step 2: Get interface details for source MAC.
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, fmt.Errorf("getting interface %d: %w", ifindex, err)
	}

	srcMAC := link.Attrs().HardwareAddr
	if len(srcMAC) != 6 {
		return nil, fmt.Errorf("invalid interface MAC on %s", link.Attrs().Name)
	}

	// Step 3: Resolve next-hop MAC via ARP.
	dstMAC, err := resolveARP(nextHop, ifindex)
	if err != nil {
		return nil, fmt.Errorf("ARP resolution for %s: %w", nextHop, err)
	}

	fwd := &FwdInfo{
		NextHop: IPToU32(nextHop),
		Ifindex: uint32(ifindex),
	}
	copy(fwd.SrcMac[:], srcMAC)
	copy(fwd.DstMac[:], dstMAC)

	return fwd, nil
}

// resolveARP resolves an IP to MAC via the neighbor cache (ARP table).
func resolveARP(ip net.IP, ifindex int) (net.HardwareAddr, error) {
	// First, check existing ARP cache.
	neighs, err := netlink.NeighList(ifindex, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing neighbors: %w", err)
	}

	for _, n := range neighs {
		if n.IP.Equal(ip) && len(n.HardwareAddr) == 6 {
			// Check if entry is reachable.
			if n.State&(netlink.NUD_REACHABLE|netlink.NUD_PERMANENT|netlink.NUD_STALE) != 0 {
				return n.HardwareAddr, nil
			}
		}
	}

	// ARP entry not found - trigger resolution by adding incomplete neighbor.
	if err := triggerARPResolution(ip, ifindex); err != nil {
		// Non-fatal, continue to wait and retry.
		fmt.Printf("Warning: could not trigger ARP resolution: %v\n", err)
	}

	// Wait and retry.
	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)

		neighs, err = netlink.NeighList(ifindex, netlink.FAMILY_V4)
		if err != nil {
			continue
		}

		for _, n := range neighs {
			if n.IP.Equal(ip) && len(n.HardwareAddr) == 6 {
				if n.State&(netlink.NUD_REACHABLE|netlink.NUD_PERMANENT|netlink.NUD_STALE) != 0 {
					return n.HardwareAddr, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("ARP resolution timeout for %s", ip)
}

// triggerARPResolution sends a packet to trigger ARP resolution.
func triggerARPResolution(ip net.IP, ifindex int) error {
	// Add incomplete neighbor entry to trigger kernel ARP.
	neigh := &netlink.Neigh{
		LinkIndex: ifindex,
		IP:        ip,
		State:     netlink.NUD_INCOMPLETE,
	}

	// Ignore error if entry exists.
	_ = netlink.NeighAdd(neigh)

	return nil
}

// IPToU32 converts an IPv4 address to uint32 in network byte order.
func IPToU32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// U32ToIP converts a uint32 in network byte order to an IPv4 address.
func U32ToIP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}
