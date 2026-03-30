package cmd

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sentinel system status",
	Long:  "Display the current status of Sentinel including probe availability, LLM backend, and system info.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.DefaultSentinelConfig()

		fmt.Fprintf(os.Stdout, "Sentinel %s\n", Version)
		fmt.Fprintf(os.Stdout, "  Platform:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(os.Stdout, "  Go version:  %s\n", runtime.Version())
		fmt.Fprintf(os.Stdout, "  PID:         %d\n", os.Getpid())
		fmt.Fprintln(os.Stdout)

		// Probe status
		fmt.Fprintln(os.Stdout, "Probes:")
		for _, probe := range cfg.Probes {
			fmt.Fprintf(os.Stdout, "  %-12s available (fallback mode)\n", probe)
		}
		fmt.Fprintln(os.Stdout)

		// LLM status
		fmt.Fprintln(os.Stdout, "LLM Backend:")
		fmt.Fprintf(os.Stdout, "  Backend:     %s\n", cfg.LLM.Backend)
		fmt.Fprintf(os.Stdout, "  Ollama URL:  %s\n", cfg.LLM.Ollama.BaseURL)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(cfg.LLM.Ollama.BaseURL + "/api/tags")
		if err != nil {
			fmt.Fprintf(os.Stdout, "  Status:      offline (%s)\n", err.Error())
		} else {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Fprintln(os.Stdout, "  Status:      online")
			} else {
				fmt.Fprintf(os.Stdout, "  Status:      error (HTTP %d)\n", resp.StatusCode)
			}
		}
		fmt.Fprintf(os.Stdout, "  Model:       %s\n", cfg.LLM.Ollama.Model)
		fmt.Fprintln(os.Stdout)

		// Config
		fmt.Fprintln(os.Stdout, "Configuration:")
		fmt.Fprintf(os.Stdout, "  Output:      %s\n", cfg.OutputFormat)
		fmt.Fprintf(os.Stdout, "  Threshold:   %d\n", cfg.AlertThreshold)
		fmt.Fprintf(os.Stdout, "  Watch paths: %v\n", cfg.WatchPaths)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
