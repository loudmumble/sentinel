package output

import (
	"fmt"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/llm"
)

// OutputPipeline routes events through a formatter and outputs them.
type OutputPipeline struct {
	Config    config.SentinelConfig
	LLM       *llm.HybridLLMClient
	Formatter Formatter
	Sidekick  *SidekickOutput
}

// NewOutputPipeline creates a pipeline with the configured formatter.
// If cfg.Sidekick.Enabled is true, a SidekickOutput is started automatically.
func NewOutputPipeline(cfg config.SentinelConfig, llmClient *llm.HybridLLMClient) *OutputPipeline {
	var formatter Formatter
	switch cfg.OutputFormat {
	case "json":
		formatter = &JSONFormatter{}
	case "cef":
		formatter = &CEFFormatter{}
	default:
		formatter = &HumanFormatter{}
	}

	p := &OutputPipeline{
		Config:    cfg,
		LLM:       llmClient,
		Formatter: formatter,
	}

	if cfg.Sidekick.Enabled {
		p.Sidekick = NewSidekickOutput(cfg.Sidekick)
		p.Sidekick.Start()
	}

	return p
}

// Send formats and outputs an event. High-score events get LLM summaries.
func (p *OutputPipeline) Send(event map[string]interface{}) {
	score := 0
	if s, ok := event["score"].(int); ok {
		score = s
	} else if s, ok := event["score"].(float64); ok {
		score = int(s)
	}

	// LLM summary for high-score events
	if score >= p.Config.AlertThreshold && p.LLM != nil && p.LLM.IsAvailable() {
		resp, err := p.LLM.Generate(
			fmt.Sprintf("Summarize this security alert in 1 sentence for a SOC analyst: type=%v, score=%v, anomalies=%v",
				event["event_type"], event["score"], event["anomalies"]),
			"You are a SOC analyst writing alert summaries. Be concise.",
			llm.WithTimeout(p.Config.LLM.Ollama.TriageTimeout),
			llm.WithMaxTokens(128),
		)
		if err == nil {
			event["llm_summary"] = resp.Content
		}
	}

	// Forward every event to Sidekick (it applies its own classification logic).
	if p.Sidekick != nil {
		p.Sidekick.HandleEvent(event)
	}

	formatted := p.Formatter.Format(event)

	// Skip low-score events in JSON/CEF mode
	if score < p.Config.AlertThreshold && p.Config.OutputFormat != "human" {
		return
	}
	fmt.Println(formatted)
}
