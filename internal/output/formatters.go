// Package output provides event formatting and output pipeline.
package output

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Formatter formats events for output.
type Formatter interface {
	Format(event map[string]interface{}) string
}

// JSONFormatter outputs events as JSON.
type JSONFormatter struct{}

// Format returns a JSON representation of the event.
func (f *JSONFormatter) Format(event map[string]interface{}) string {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Sprintf(`{"error": "marshal failed: %s"}`, err)
	}
	return string(data)
}

// CEFFormatter outputs events in Common Event Format.
type CEFFormatter struct{}

// Format returns CEF-formatted event string.
func (f *CEFFormatter) Format(event map[string]interface{}) string {
	score := 0
	if s, ok := event["score"].(int); ok {
		score = s
	} else if s, ok := event["score"].(float64); ok {
		score = int(s)
	}
	severity := score / 10

	eventType, _ := event["event_type"].(string)

	var parts []string
	for k, v := range event {
		if k == "event_type" || k == "score" || k == "timestamp_str" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	extension := strings.Join(parts, " ")

	if llmSummary, ok := event["llm_summary"].(string); ok && llmSummary != "" {
		extension += fmt.Sprintf(" llmSummary=%s", llmSummary)
	}

	return fmt.Sprintf("CEF:0|Sentinel|Sentinel-eBPF|0.3.0b1|%s|%s event|%d|%s",
		eventType, eventType, severity, extension)
}

// HumanFormatter outputs events in human-readable colored format.
type HumanFormatter struct{}

// Format returns a Rich-style colored output string.
func (f *HumanFormatter) Format(event map[string]interface{}) string {
	eventType, _ := event["event_type"].(string)
	desc := ""

	switch eventType {
	case "process":
		desc = fmt.Sprintf("%v pid=%v comm=%v", event["action"], event["pid"], event["comm"])
	case "syscall":
		desc = fmt.Sprintf("sys_%v pid=%v args=%v", event["syscall_nr"], event["pid"], event["args"])
	case "file":
		desc = fmt.Sprintf("%v %v", event["operation"], event["path"])
	case "network":
		desc = fmt.Sprintf("connect %v:%v -> %v:%v", event["saddr"], event["sport"], event["daddr"], event["dport"])
	}

	score := 0
	if s, ok := event["score"].(int); ok {
		score = s
	} else if s, ok := event["score"].(float64); ok {
		score = int(s)
	}

	color := "white"
	if score > 75 {
		color = "red"
	} else if score > 40 {
		color = "yellow"
	}

	output := fmt.Sprintf("[%s][%v] %s: %s (Score: %d)[/%s]",
		color, event["timestamp_str"], strings.ToUpper(eventType), desc, score, color)

	llmText := ""
	if v, ok := event["llm_analysis"].(string); ok && v != "" {
		llmText = v
	} else if v, ok := event["llm_summary"].(string); ok && v != "" {
		llmText = v
	}
	if llmText != "" {
		output += fmt.Sprintf("\n  └─ AI: %s", llmText)
	}

	return output
}
