package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/loudmumble/sentinel/internal/analysis"
	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze a security event",
	Long:  "Run anomaly detection and optional LLM analysis on a described event.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.DefaultSentinelConfig()

		eventType, _ := cmd.Flags().GetString("type")
		pid, _ := cmd.Flags().GetInt("pid")
		comm, _ := cmd.Flags().GetString("comm")
		path, _ := cmd.Flags().GetString("path")
		operation, _ := cmd.Flags().GetString("operation")
		uid, _ := cmd.Flags().GetInt("uid")
		dport, _ := cmd.Flags().GetInt("dport")

		engine := analysis.NewAnalysisEngine(cfg, nil)
		var eventList []events.EventInterface

		switch eventType {
		case "process":
			e := events.NewProcessEvent()
			e.Action = "exec"
			e.PID = pid
			e.Comm = comm
			e.UID = uid
			eventList = append(eventList, e)
		case "file":
			e := events.NewFileEvent()
			e.Path = path
			e.Operation = operation
			eventList = append(eventList, e)
		case "network":
			e := events.NewNetworkEvent()
			e.DPort = dport
			e.PID = pid
			eventList = append(eventList, e)
		case "syscall":
			e := events.NewSyscallEvent()
			e.PID = pid
			e.Comm = comm
			eventList = append(eventList, e)
		default:
			return fmt.Errorf("unknown event type %q (use: process, file, network, syscall)", eventType)
		}

		results := engine.Process(eventList)
		output, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal results: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(output))
		return nil
	},
}

func init() {
	analyzeCmd.Flags().String("type", "process", "Event type (process, file, network, syscall)")
	analyzeCmd.Flags().Int("pid", 0, "Process ID")
	analyzeCmd.Flags().String("comm", "", "Process command name")
	analyzeCmd.Flags().String("path", "", "File path (for file events)")
	analyzeCmd.Flags().String("operation", "", "File operation (create, modify, delete)")
	analyzeCmd.Flags().Int("uid", 0, "User ID")
	analyzeCmd.Flags().Int("dport", 0, "Destination port (for network events)")
	rootCmd.AddCommand(analyzeCmd)
}
