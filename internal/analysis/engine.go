// Package analysis provides threat detection and event correlation.
package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
	"github.com/loudmumble/sentinel/internal/llm"
)

// AnalysisEngine processes events and detects anomalies.
type AnalysisEngine struct {
	Config     config.SentinelConfig
	LLM        *llm.HybridLLMClient
	Correlator *Correlator
}

// NewAnalysisEngine creates an engine with optional LLM support.
func NewAnalysisEngine(cfg config.SentinelConfig, llmClient *llm.HybridLLMClient) *AnalysisEngine {
	return &AnalysisEngine{
		Config:     cfg,
		LLM:        llmClient,
		Correlator: NewCorrelator(cfg, llmClient),
	}
}

// Process analyzes events and returns enriched results with anomaly scores.
func (e *AnalysisEngine) Process(eventList []events.EventInterface) []map[string]interface{} {
	var results []map[string]interface{}
	for _, evt := range eventList {
		enriched := e.Enrich(evt)
		anomalies := e.DetectAnomalies(enriched)
		enriched["anomalies"] = anomalies

		totalScore := 0
		for _, a := range anomalies {
			if s, ok := a["score"].(int); ok {
				totalScore += s
			}
		}
		enriched["score"] = totalScore

		// Correlator check
		correlated := e.Correlator.AddEvent(enriched)
		if correlated != nil {
			results = append(results, correlated)
		}

		// LLM enrichment for high-score events
		if totalScore >= 50 && e.LLM != nil && e.LLM.IsAvailable() {
			resp, err := e.LLM.Generate(
				fmt.Sprintf("Analyze this security event (score %d/100): type=%v, anomalies=%v. Provide a 1-sentence threat assessment.",
					totalScore, enriched["event_type"], enriched["anomalies"]),
				"You are a SOC analyst. Be concise and actionable.",
				llm.WithTimeout(e.Config.LLM.Ollama.TriageTimeout),
				llm.WithMaxTokens(128),
			)
			if err == nil {
				enriched["llm_analysis"] = resp.Content
			}
		}

		results = append(results, enriched)
	}
	return results
}

// Enrich converts an event to a map with additional metadata.
func (e *AnalysisEngine) Enrich(evt events.EventInterface) map[string]interface{} {
	var data map[string]interface{}

	switch v := evt.(type) {
	case *events.ProcessEvent:
		data = v.ToMap()
	case *events.SyscallEvent:
		data = v.ToMap()
	case *events.FileEvent:
		data = v.ToMap()
	case *events.NetworkEvent:
		data = v.ToMap()
	default:
		data = map[string]interface{}{
			"timestamp":  evt.GetTimestamp(),
			"event_type": evt.GetType(),
		}
	}

	data["event_type"] = evt.GetType()
	ts := time.Unix(int64(evt.GetTimestamp()), int64((evt.GetTimestamp()-float64(int64(evt.GetTimestamp())))*1e9))
	data["timestamp_str"] = ts.Format(time.RFC3339)

	return data
}

// DetectAnomalies checks an enriched event against all detection rules.
func (e *AnalysisEngine) DetectAnomalies(event map[string]interface{}) []map[string]interface{} {
	var anomalies []map[string]interface{}
	eventType, _ := event["event_type"].(string)

	// File rules
	if eventType == "file" {
		op, _ := event["operation"].(string)
		if op == "modify" || op == "delete" || op == "rename_from" {
			path, _ := event["path"].(string)
			if strings.HasPrefix(path, "/etc/passwd") || strings.HasPrefix(path, "/etc/shadow") {
				anomalies = append(anomalies, map[string]interface{}{
					"rule":  "critical_file_mod",
					"score": 90,
					"desc":  fmt.Sprintf("Modification to critical file %s", path),
				})
			} else if strings.HasPrefix(path, "/bin") || strings.HasPrefix(path, "/usr/bin") {
				anomalies = append(anomalies, map[string]interface{}{
					"rule":  "bin_file_mod",
					"score": 80,
					"desc":  fmt.Sprintf("Modification to binary %s", path),
				})
			}
		}
	}

	// Process rules
	if eventType == "process" {
		action, _ := event["action"].(string)
		if action == "exec" {
			comm, _ := event["comm"].(string)
			shells := map[string]bool{"bash": true, "sh": true, "dash": true, "zsh": true}
			if shells[comm] {
				uid := getInt(event, "uid")
				if uid == 0 {
					anomalies = append(anomalies, map[string]interface{}{
						"rule":  "root_shell",
						"score": 50,
						"desc":  "Root shell spawned",
					})
				}
			}
			// LLM process classification
			llmResult := e.LLMClassifyProcess(event)
			if llmResult != nil {
				anomalies = append(anomalies, llmResult)
			}
		}
	}

	// Network rules
	if eventType == "network" {
		dport := getInt(event, "dport")
		standardPorts := map[int]bool{80: true, 443: true, 22: true, 53: true, 123: true}
		if !standardPorts[dport] && dport < 1024 && dport > 0 {
			anomalies = append(anomalies, map[string]interface{}{
				"rule":  "unusual_port",
				"score": 30,
				"desc":  fmt.Sprintf("Connection to unusual privileged port %d", dport),
			})
		}
	}

	// Syscall rules
	if eventType == "syscall" {
		syscallNr := getInt(event, "syscall_nr")

		// memfd_create (syscall 319) — anonymous in-memory file creation
		if syscallNr == 319 {
			anomalies = append(anomalies, map[string]interface{}{
				"rule":  "memfd_create_anonymous",
				"score": 85,
				"desc":  fmt.Sprintf("memfd_create detected (pid=%v, comm=%v) — in-memory payload staging", event["pid"], event["comm"]),
			})
		} else if syscallNr == 157 {
			// prctl PR_SET_NAME (syscall 157, arg0=15)
			args := getIntSlice(event, "args")
			if len(args) > 0 && args[0] == 15 {
				comm, _ := event["comm"].(string)
				kernelNames := []string{"kworker", "migration", "watchdog", "rcu_sched", "ksoftirqd", "kthread"}
				for _, k := range kernelNames {
					if strings.Contains(comm, k) {
						anomalies = append(anomalies, map[string]interface{}{
							"rule":  "process_masquerade",
							"score": 75,
							"desc":  fmt.Sprintf("prctl(PR_SET_NAME) with kernel-thread name '%s' from userspace process (pid=%v)", comm, event["pid"]),
						})
						break
					}
				}
			}
		}
	}

	// LLM explanation for file anomalies
	if eventType == "file" && len(anomalies) > 0 {
		path, _ := event["path"].(string)
		op, _ := event["operation"].(string)
		explanation := e.LLMExplainFileAnomaly(path, op)
		if explanation != "" {
			for _, a := range anomalies {
				a["llm_explanation"] = explanation
			}
		}
	}

	return anomalies
}

// LLMClassifyProcess uses the LLM to classify a process execution event.
func (e *AnalysisEngine) LLMClassifyProcess(event map[string]interface{}) map[string]interface{} {
	if e.LLM == nil || !e.LLM.IsAvailable() {
		return nil
	}
	argv := ""
	if argvList, ok := event["argv"].([]string); ok {
		argv = strings.Join(argvList, " ")
	} else if comm, ok := event["comm"].(string); ok {
		argv = comm
	}

	prompt := fmt.Sprintf(
		"Evaluate this Linux process execution:\nCommand: %s\nUser: uid=%v, comm=%v\nPID: %v, PPID: %v\n\n"+
			`Respond with JSON: {"suspicious": bool, "score": 0-100, "reason": "str", "mitre": "str or null"}`,
		argv, event["uid"], event["comm"], event["pid"], event["ppid"])

	result, err := e.LLM.GenerateJSON(prompt,
		"You are a Linux security analyst. Evaluate process execution for malicious indicators. Be concise. Score 0=benign, 100=confirmed attack.",
		llm.WithTimeout(e.Config.LLM.Ollama.TriageTimeout),
		llm.WithMaxTokens(e.Config.LLM.Ollama.TriageMaxTokens),
	)
	if err != nil {
		return nil
	}

	suspicious, _ := result["suspicious"].(bool)
	score := 0
	if s, ok := result["score"].(float64); ok {
		score = int(s)
	}
	if suspicious && score > 30 {
		reason, _ := result["reason"].(string)
		if reason == "" {
			reason = "LLM flagged process"
		}
		mitre, _ := result["mitre"].(string)
		return map[string]interface{}{
			"rule":  "llm_process_triage",
			"score": score,
			"desc":  reason,
			"mitre": mitre,
		}
	}
	return nil
}

// LLMExplainFileAnomaly uses the LLM to explain a file anomaly.
func (e *AnalysisEngine) LLMExplainFileAnomaly(path, operation string) string {
	if e.LLM == nil || !e.LLM.IsAvailable() {
		return ""
	}
	resp, err := e.LLM.Generate(
		fmt.Sprintf("In 1 sentence, explain the security risk of: %s on %s", operation, path),
		"You are a Linux security analyst. Be concise.",
		llm.WithTimeout(e.Config.LLM.Ollama.TriageTimeout),
		llm.WithMaxTokens(128),
	)
	if err != nil {
		return ""
	}
	return resp.Content
}

// Helper: get int from map (handles both int and float64 from JSON)
func getInt(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}

// Helper: get int slice from map
func getIntSlice(m map[string]interface{}, key string) []int {
	switch v := m[key].(type) {
	case []int:
		return v
	case []interface{}:
		var result []int
		for _, item := range v {
			switch i := item.(type) {
			case int:
				result = append(result, i)
			case float64:
				result = append(result, int(i))
			}
		}
		return result
	}
	return nil
}
