package cmd

import (
	"fmt"
	"os"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/mcp"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start MCP server for agentic control",
	Long:  "Start the MCP (Model Context Protocol) JSON-RPC server on stdio for agentic integration.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.DefaultSentinelConfig()

		if format, _ := cmd.Flags().GetString("output"); format != "" {
			cfg.OutputFormat = format
		}

		server := mcp.NewServer(cfg)
		fmt.Fprintln(os.Stderr, "sentinel MCP server starting on stdio...")
		return server.Run(os.Stdin, os.Stdout)
	},
}

func init() {
	serveCmd.Flags().String("output", "json", "Output format (json, cef, human)")
	rootCmd.AddCommand(serveCmd)
}
