package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dp-udp",
	Short: "Dual-Path UDP",
	Long:  "Dual-Path UDP is a layer 5 application for Dual-Path UDP with iperf3 sequence number deduplication.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
