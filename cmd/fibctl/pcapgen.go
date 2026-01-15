package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

var (
	pcapFlowSize    int
	pcapPacketCount int
	pcapDist        string
	pcapSrcIP       string
	pcapSrcMAC      string
	pcapDstMAC      string
	pcapZipfS       float64
)

var pcapGenCmd = &cobra.Command{
	Use:   "pcap-gen <fib-file> <output.pcap>",
	Short: "Generate a PCAP file based on FIB prefixes",
	Long: `Generate a PCAP file with UDP packets targeting prefixes from a FIB file.

This tool reads a FIB file, randomly selects N prefixes (flow-size), and
generates packets with destination IPs from those prefixes according to
the specified distribution.

For each selected prefix, the first valid host IP is used (prefix + 1).
For example, 10.0.0.0/24 becomes 10.0.0.1.

Distributions:
  uniform - Equal probability for each destination IP
  zipf    - Zipf distribution (skewed, some IPs much more frequent)

Example:
  fibctl pcap-gen routes.txt traffic.pcap --flow-size 1000 --packets 1000000
  fibctl pcap-gen routes.txt traffic.pcap --flow-size 100 --packets 1000000 --dist zipf`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fibFile := args[0]
		outputFile := args[1]

		if pcapFlowSize <= 0 {
			return fmt.Errorf("--flow-size must be positive")
		}
		if pcapPacketCount <= 0 {
			return fmt.Errorf("--packets must be positive")
		}

		// Parse source IP.
		srcIP := net.ParseIP(pcapSrcIP).To4()
		if srcIP == nil {
			return fmt.Errorf("invalid source IP: %s", pcapSrcIP)
		}

		// Parse MACs.
		srcMAC, err := net.ParseMAC(pcapSrcMAC)
		if err != nil {
			return fmt.Errorf("invalid source MAC: %w", err)
		}
		dstMAC, err := net.ParseMAC(pcapDstMAC)
		if err != nil {
			return fmt.Errorf("invalid destination MAC: %w", err)
		}

		// Read FIB and extract prefixes.
		prefixes, err := readFIBPrefixes(fibFile)
		if err != nil {
			return fmt.Errorf("reading FIB: %w", err)
		}

		if len(prefixes) == 0 {
			return fmt.Errorf("no prefixes found in FIB file")
		}

		fmt.Printf("Loaded %d prefixes from %s\n", len(prefixes), fibFile)

		// Select random prefixes for flow.
		flowSize := pcapFlowSize
		if flowSize > len(prefixes) {
			fmt.Printf("Warning: flow-size %d > prefix count %d, using all prefixes\n",
				flowSize, len(prefixes))
			flowSize = len(prefixes)
		}

		// Shuffle and select.
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(prefixes), func(i, j int) {
			prefixes[i], prefixes[j] = prefixes[j], prefixes[i]
		})

		selectedPrefixes := prefixes[:flowSize]

		// Convert prefixes to destination IPs (first valid host).
		dstIPs := make([]net.IP, len(selectedPrefixes))
		for i, prefix := range selectedPrefixes {
			dstIPs[i] = firstHostIP(prefix)
		}

		fmt.Printf("Selected %d destination IPs for traffic generation\n", len(dstIPs))

		// Create distribution sampler.
		var sampler func() int
		switch pcapDist {
		case "uniform":
			sampler = func() int {
				return rng.Intn(len(dstIPs))
			}
		case "zipf":
			zipf := rand.NewZipf(rng, pcapZipfS, 1.0, uint64(len(dstIPs)-1))
			sampler = func() int {
				return int(zipf.Uint64())
			}
		default:
			return fmt.Errorf("unknown distribution: %s (use 'uniform' or 'zipf')", pcapDist)
		}

		// Create PCAP file.
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()

		writer := pcapgo.NewWriter(f)
		if err := writer.WriteFileHeader(1500, layers.LinkTypeEthernet); err != nil {
			return fmt.Errorf("writing PCAP header: %w", err)
		}

		// Generate packets.
		fmt.Printf("Generating %d packets with %s distribution...\n", pcapPacketCount, pcapDist)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		startTime := time.Now()
		for i := 0; i < pcapPacketCount; i++ {
			// Select destination IP based on distribution.
			dstIP := dstIPs[sampler()]

			// Build packet.
			eth := &layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			}

			ip := &layers.IPv4{
				Version:  4,
				IHL:      5,
				TTL:      64,
				Protocol: layers.IPProtocolUDP,
				SrcIP:    srcIP,
				DstIP:    dstIP,
			}

			udp := &layers.UDP{
				SrcPort: layers.UDPPort(10000 + (i % 50000)),
				DstPort: layers.UDPPort(9999),
			}
			udp.SetNetworkLayerForChecksum(ip)

			// Small payload.
			payload := []byte("fibctl-test")

			if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
				return fmt.Errorf("serializing packet %d: %w", i, err)
			}

			// Write packet to PCAP.
			ci := gopacket.CaptureInfo{
				Timestamp:     startTime.Add(time.Duration(i) * time.Microsecond),
				CaptureLength: len(buf.Bytes()),
				Length:        len(buf.Bytes()),
			}

			if err := writer.WritePacket(ci, buf.Bytes()); err != nil {
				return fmt.Errorf("writing packet %d: %w", i, err)
			}

			buf.Clear()

			// Progress report.
			if (i+1)%100000 == 0 {
				fmt.Printf("  Generated %d packets...\n", i+1)
			}
		}

		elapsed := time.Since(startTime)
		fmt.Printf("Generated %d packets in %s (%.0f pps)\n",
			pcapPacketCount, elapsed, float64(pcapPacketCount)/elapsed.Seconds())
		fmt.Printf("Output: %s\n", outputFile)

		return nil
	},
}

// readFIBPrefixes reads prefixes from a FIB file.
func readFIBPrefixes(filename string) ([]*net.IPNet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var prefixes []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		_, prefix, err := net.ParseCIDR(parts[0])
		if err != nil {
			continue // Skip invalid lines.
		}

		// Only include prefixes that can have valid hosts.
		ones, bits := prefix.Mask.Size()
		if ones < bits { // Has host bits.
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes, scanner.Err()
}

// firstHostIP returns the first valid host IP in a prefix.
// For 10.0.0.0/24, returns 10.0.0.1.
func firstHostIP(prefix *net.IPNet) net.IP {
	ip := make(net.IP, len(prefix.IP))
	copy(ip, prefix.IP)

	// Add 1 to get first host.
	ip4 := ip.To4()
	if ip4 == nil {
		return ip
	}

	val := binary.BigEndian.Uint32(ip4)
	val++
	binary.BigEndian.PutUint32(ip4, val)

	return ip4
}

// zipfPMF returns the probability mass function for Zipf distribution.
func zipfPMF(k int, s float64, n int) float64 {
	// H_n,s = sum(1/k^s for k in 1..n)
	var h float64
	for i := 1; i <= n; i++ {
		h += 1.0 / math.Pow(float64(i), s)
	}
	return (1.0 / math.Pow(float64(k), s)) / h
}

func init() {
	pcapGenCmd.Flags().IntVar(&pcapFlowSize, "flow-size", 1000, "Number of unique destination IPs (flow size)")
	pcapGenCmd.Flags().IntVar(&pcapPacketCount, "packets", 1000000, "Number of packets to generate")
	pcapGenCmd.Flags().StringVar(&pcapDist, "dist", "uniform", "Distribution: uniform, zipf")
	pcapGenCmd.Flags().StringVar(&pcapSrcIP, "src-ip", "10.0.0.1", "Source IP for generated packets")
	pcapGenCmd.Flags().StringVar(&pcapSrcMAC, "src-mac", "00:00:00:00:00:01", "Source MAC for generated packets")
	pcapGenCmd.Flags().StringVar(&pcapDstMAC, "dst-mac", "00:00:00:00:00:02", "Destination MAC for generated packets")
	pcapGenCmd.Flags().Float64Var(&pcapZipfS, "zipf-s", 1.5, "Zipf distribution skew parameter (s > 1)")
	rootCmd.AddCommand(pcapGenCmd)
}
