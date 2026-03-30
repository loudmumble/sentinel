// Package cmd implements the Sentinel CLI using Cobra.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "v1.0.0"

var rootCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "Sentinel — eBPF-powered security monitoring with hybrid LLM analysis",
	Long: `Sentinel monitors Linux systems for security threats using eBPF probes
(with /proc fallback) and optional LLM-powered analysis via Ollama.

Probes: process, syscall, file, network
Output: JSON, CEF, human-readable
LLM: Ollama-backed triage, deep analysis, and correlation narratives`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print sentinel version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "sentinel %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// GetRootCmd returns the root command for testing.
func GetRootCmd() *cobra.Command {
	return rootCmd
}
