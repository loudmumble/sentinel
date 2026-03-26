package analysis

import (
	"fmt"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/llm"
)

// Correlator detects multi-event attack patterns using a sliding window.
type Correlator struct {
	Config     config.SentinelConfig
	LLM        *llm.HybridLLMClient
	WindowSize float64
	Events     []map[string]interface{}
}

// NewCorrelator creates a Correlator with a 5-second sliding window.
func NewCorrelator(cfg config.SentinelConfig, llmClient *llm.HybridLLMClient) *Correlator {
	return &Correlator{
		Config:     cfg,
		LLM:        llmClient,
		WindowSize: 5.0,
		Events:     []map[string]interface{}{},
	}
}

// AddEvent adds an event to the window and checks for correlation patterns.
func (c *Correlator) AddEvent(event map[string]interface{}) map[string]interface{} {
	c.Events = append(c.Events, event)

	now := getFloat(event, "timestamp")

	// Trim events outside window
	var trimmed []map[string]interface{}
	for _, e := range c.Events {
		ts := getFloat(e, "timestamp")
		if now-ts <= c.WindowSize {
			trimmed = append(trimmed, e)
		}
	}
	c.Events = trimmed

	eventType, _ := event["event_type"].(string)

	// exec_then_connect: process exec + network connect from same PID
	if eventType == "network" {
		pid := getInt(event, "pid")
		for _, e := range c.Events {
			eType, _ := e["event_type"].(string)
			eAction, _ := e["action"].(string)
			ePID := getInt(e, "pid")
			if eType == "process" && eAction == "exec" && ePID == pid {
				correlation := map[string]interface{}{
					"type":   "correlation",
					"rule":   "exec_then_connect",
					"score":  60,
					"desc":   fmt.Sprintf("Process %d (%v) started then immediately connected to %v:%v", pid, e["comm"], event["daddr"], event["dport"]),
					"events": []map[string]interface{}{e, event},
				}
				narrative := c.LLMNarrateCorrelation(e, event)
				if narrative != "" {
					correlation["llm_narrative"] = narrative
				}
				return correlation
			}
		}
	}

	// fork_then_memfd: fork/exec + memfd_create within same process lineage
	if eventType == "syscall" && getInt(event, "syscall_nr") == 319 {
		pid := getInt(event, "pid")
		for _, e := range c.Events {
			eType, _ := e["event_type"].(string)
			eAction, _ := e["action"].(string)
			ePID := getInt(e, "pid")
			eSyscallNr := getInt(e, "syscall_nr")

			isMatch := false
			if eType == "process" && eAction == "exec" {
				isMatch = true
			} else if eType == "syscall" && eSyscallNr == 57 { // fork
				isMatch = true
			}

			if isMatch {
				ppid := getInt(event, "ppid")
				if ePID == pid || ePID == ppid {
					correlation := map[string]interface{}{
						"type":   "correlation",
						"rule":   "fork_then_memfd",
						"score":  90,
						"desc":   fmt.Sprintf("VoidLink chain: process %d (%v) → memfd_create by pid %d — in-memory payload execution", ePID, e["comm"], pid),
						"events": []map[string]interface{}{e, event},
					}
					narrative := c.LLMNarrateCorrelation(e, event)
					if narrative != "" {
						correlation["llm_narrative"] = narrative
					}
					return correlation
				}
			}
		}
	}

	return nil
}

// LLMNarrateCorrelation generates an attack narrative using the LLM.
func (c *Correlator) LLMNarrateCorrelation(procEvent, netEvent map[string]interface{}) string {
	if c.LLM == nil || !c.LLM.IsAvailable() {
		return ""
	}
	prompt := fmt.Sprintf(
		"Process: pid=%v, comm=%v, uid=%v, argv=%v\n"+
			"Network: daddr=%v, dport=%v, protocol=%v\n\n"+
			"Provide a 2-sentence attack narrative and MITRE ATT&CK technique ID.",
		procEvent["pid"], procEvent["comm"], procEvent["uid"], procEvent["argv"],
		netEvent["daddr"], netEvent["dport"], netEvent["protocol"])

	resp, err := c.LLM.Generate(prompt,
		"You are a threat intelligence analyst. Be precise and actionable.",
		llm.WithTimeout(c.Config.LLM.Ollama.DeepTimeout),
		llm.WithMaxTokens(c.Config.LLM.Ollama.TriageMaxTokens),
	)
	if err != nil {
		return ""
	}
	return resp.Content
}

func getFloat(m map[string]interface{}, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}
