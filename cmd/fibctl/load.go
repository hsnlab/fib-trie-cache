package main

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"

	"fibctl/internal/fib"
)

var (
	xdpMode string
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load and attach the XDP FIB program",
	Long: `Load the XDP FIB lookup program and attach it to the specified interface.

The program will be pinned to the BPF filesystem for persistence.
Maps will also be pinned so other commands can access them.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if ifaceName == "" {
			return fmt.Errorf("interface name required (-i)")
		}

		mgr := fib.NewManager(pinPath)
		if err := mgr.Load(); err != nil {
			return fmt.Errorf("loading program: %w", err)
		}

		// Determine XDP attach mode.
		var mode link.XDPAttachFlags
		switch xdpMode {
		case "native", "driver":
			mode = link.XDPDriverMode
		case "offload":
			mode = link.XDPOffloadMode
		case "generic", "skb":
			mode = link.XDPGenericMode
		default:
			// Try native first, fall back to generic.
			mode = 0 // Auto mode.
		}

		if err := mgr.Attach(ifaceName, mode); err != nil {
			mgr.Unload()
			return fmt.Errorf("attaching to %s: %w", ifaceName, err)
		}

		fmt.Printf("XDP program loaded and attached to %s\n", ifaceName)
		fmt.Printf("Maps pinned at %s\n", pinPath)
		return nil
	},
}

func init() {
	loadCmd.Flags().StringVarP(&xdpMode, "mode", "m", "auto", "XDP attach mode: auto, native, generic, offload")
	rootCmd.AddCommand(loadCmd)
}
