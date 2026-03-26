package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/loudmumble/sentinel/internal/analysis"
	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/output"
	"github.com/loudmumble/sentinel/internal/probes"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor processes in real-time",
	Long:  "Start real-time process monitoring using /proc polling with anomaly detection.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.DefaultSentinelConfig()
		if format, _ := cmd.Flags().GetString("output"); format != "" {
			cfg.OutputFormat = format
		}
		interval, _ := cmd.Flags().GetInt("interval")
		if interval <= 0 {
			interval = 1
		}

		engine := analysis.NewAnalysisEngine(cfg, nil)
		pipeline := output.NewOutputPipeline(cfg, nil)
		probe := probes.NewProcessProbe(cfg)
		probe.Start()
		defer probe.Stop()

		fmt.Fprintln(os.Stderr, "sentinel process monitor started (Ctrl+C to stop)")

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-sig:
				fmt.Fprintln(os.Stderr, "\nsentinel monitor stopped")
				return nil
			case <-ticker.C:
				events := probe.Poll()
				if len(events) > 0 {
					results := engine.Process(events)
					for _, r := range results {
						pipeline.Send(r)
					}
				}
			}
		}
	},
}

func init() {
	monitorCmd.Flags().String("output", "json", "Output format (json, cef, human)")
	monitorCmd.Flags().Int("interval", 1, "Poll interval in seconds")
	rootCmd.AddCommand(monitorCmd)
}
