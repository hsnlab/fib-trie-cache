package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	rewriteNextHop string
)

var fibRewriteCmd = &cobra.Command{
	Use:   "fib-rewrite <input-fib> <output-fib>",
	Short: "Rewrite all next-hops in a FIB file",
	Long: `Rewrite all next-hops in a FIB file to a single configured next-hop.

This is useful for hairpin testing setups where all traffic should be
forwarded to the same next-hop (typically back out the same interface).

Example:
  fibctl fib-rewrite data/dag_test1.txt routes.txt --next-hop 192.168.1.1

Input format (one route per line):
  # comments start with #
  0.0.0.0/3    0.0.0.1
  32.0.0.0/3   0.0.0.2

Output format:
  0.0.0.0/3 192.168.1.1
  32.0.0.0/3 192.168.1.1`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputFile := args[0]
		outputFile := args[1]

		if rewriteNextHop == "" {
			return fmt.Errorf("--next-hop is required")
		}

		// Validate next-hop IP.
		nextHop := net.ParseIP(rewriteNextHop)
		if nextHop == nil {
			return fmt.Errorf("invalid next-hop IP: %s", rewriteNextHop)
		}

		// Open input file.
		inFile, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("opening input file: %w", err)
		}
		defer inFile.Close()

		// Create output file.
		outFile, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer outFile.Close()

		var count int
		scanner := bufio.NewScanner(inFile)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Skip empty lines and comments.
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Parse the line to extract prefix.
			parts := strings.Fields(line)
			if len(parts) < 1 {
				continue
			}

			prefix := parts[0]

			// Validate prefix.
			_, _, err := net.ParseCIDR(prefix)
			if err != nil {
				return fmt.Errorf("invalid prefix %s: %w", prefix, err)
			}

			// Write rewritten route.
			fmt.Fprintf(outFile, "%s %s\n", prefix, nextHop.String())
			count++
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading input file: %w", err)
		}

		fmt.Printf("Rewrote %d routes from %s to %s (next-hop: %s)\n",
			count, inputFile, outputFile, nextHop)
		return nil
	},
}

func init() {
	fibRewriteCmd.Flags().StringVar(&rewriteNextHop, "next-hop", "", "Next-hop IP to use for all routes (required)")
	fibRewriteCmd.MarkFlagRequired("next-hop")
	rootCmd.AddCommand(fibRewriteCmd)
}
