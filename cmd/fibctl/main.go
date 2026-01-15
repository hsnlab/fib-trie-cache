// fibctl is a CLI tool for managing the eBPF-based cached FIB lookup system.
package main

import (
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
