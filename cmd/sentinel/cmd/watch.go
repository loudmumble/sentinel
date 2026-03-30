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

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch filesystem changes",
	Long:  "Monitor filesystem changes using inotify with anomaly detection for critical file modifications.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.DefaultSentinelConfig()
		if format, _ := cmd.Flags().GetString("output"); format != "" {
			cfg.OutputFormat = format
		}
		paths, _ := cmd.Flags().GetStringSlice("paths")
		if len(paths) > 0 {
			cfg.WatchPaths = paths
		}
		interval, _ := cmd.Flags().GetInt("interval")
		if interval <= 0 {
			interval = 1
		}

		engine := analysis.NewAnalysisEngine(cfg, nil)
		pipeline := output.NewOutputPipeline(cfg, nil)
		probe := probes.NewFileProbe(cfg)
		probe.Start()
		defer probe.Stop()

		fmt.Fprintf(os.Stderr, "sentinel file watcher started on %v (Ctrl+C to stop)\n", cfg.WatchPaths)

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-sig:
				fmt.Fprintln(os.Stderr, "\nsentinel watcher stopped")
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
	watchCmd.Flags().String("output", "json", "Output format (json, cef, human)")
	watchCmd.Flags().StringSlice("paths", nil, "Paths to watch (comma-separated)")
	watchCmd.Flags().Int("interval", 1, "Poll interval in seconds")
	rootCmd.AddCommand(watchCmd)
}
