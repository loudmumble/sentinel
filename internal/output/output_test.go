package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
)

// --- JSON Formatter Tests ---

func TestJSONFormatterValidJSON(t *testing.T) {
	f := &JSONFormatter{}
	event := map[string]interface{}{
		"event_type": "process",
		"pid":        1,
		"comm":       "test",
		"score":      50,
		"timestamp":  time.Now().Unix(),
	}
	output := f.Format(event)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if parsed["comm"] != "test" {
		t.Errorf("expected comm 'test', got %v", parsed["comm"])
	}
}

func TestJSONFormatterHandlesAllTypes(t *testing.T) {
	f := &JSONFormatter{}
	for _, etype := range []string{"process", "syscall", "file", "network"} {
		event := map[string]interface{}{"event_type": etype, "score": 0}
		output := f.Format(event)
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			t.Fatalf("invalid JSON for type %s: %v", etype, err)
		}
		if parsed["event_type"] != etype {
			t.Errorf("expected event_type %q, got %v", etype, parsed["event_type"])
		}
	}
}

func TestJSONFormatterWithComplexEvent(t *testing.T) {
	f := &JSONFormatter{}
	event := map[string]interface{}{
		"event_type": "syscall",
		"pid":        42,
		"syscall_nr": 319,
		"args":       []int{0, 0, 0},
		"score":      85,
		"anomalies":  []map[string]interface{}{{"rule": "memfd_create", "score": 85}},
	}
	output := f.Format(event)
	if !strings.Contains(output, "319") {
		t.Error("expected syscall_nr 319 in output")
	}
}

// --- CEF Formatter Tests ---

func TestCEFFormatterPrefix(t *testing.T) {
	f := &CEFFormatter{}
	event := map[string]interface{}{"event_type": "process", "score": 80, "pid": 1}
	output := f.Format(event)
	if !strings.HasPrefix(output, "CEF:0|Sentinel|Sentinel-eBPF|0.3.0b1|") {
		t.Errorf("expected CEF prefix, got %q", output[:50])
	}
	if !strings.Contains(output, "process") {
		t.Error("expected 'process' in CEF output")
	}
}

func TestCEFSeverityFromScore(t *testing.T) {
	f := &CEFFormatter{}
	event := map[string]interface{}{"event_type": "file", "score": 90}
	output := f.Format(event)
	if !strings.Contains(output, "|9|") {
		t.Errorf("expected severity |9| in output, got %q", output)
	}
}

func TestCEFSeverityLow(t *testing.T) {
	f := &CEFFormatter{}
	event := map[string]interface{}{"event_type": "network", "score": 10}
	output := f.Format(event)
	if !strings.Contains(output, "|1|") {
		t.Errorf("expected severity |1| in output, got %q", output)
	}
}

func TestCEFWithLLMSummary(t *testing.T) {
	f := &CEFFormatter{}
	event := map[string]interface{}{
		"event_type":  "file",
		"score":       90,
		"llm_summary": "Critical file modification detected",
	}
	output := f.Format(event)
	if !strings.Contains(output, "llmSummary=") {
		t.Error("expected llmSummary in CEF output")
	}
}

// --- Human Formatter Tests ---

func TestHumanFormatterProcess(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type":    "process",
		"action":        "exec",
		"pid":           42,
		"comm":          "bash",
		"score":         50,
		"timestamp_str": "2026-01-01T00:00:00",
	}
	output := f.Format(event)
	if !strings.Contains(output, "PROCESS") {
		t.Error("expected 'PROCESS' in output")
	}
	if !strings.Contains(output, "bash") {
		t.Error("expected 'bash' in output")
	}
	if !strings.Contains(output, "pid=42") {
		t.Error("expected 'pid=42' in output")
	}
}

func TestHumanFormatterFile(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type":    "file",
		"operation":     "modify",
		"path":          "/etc/passwd",
		"score":         90,
		"timestamp_str": "2026-01-01T00:00:00",
	}
	output := f.Format(event)
	if !strings.Contains(output, "FILE") {
		t.Error("expected 'FILE' in output")
	}
	if !strings.Contains(output, "/etc/passwd") {
		t.Error("expected '/etc/passwd' in output")
	}
}

func TestHumanFormatterNetwork(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type":    "network",
		"saddr":         "10.0.0.1",
		"sport":         1234,
		"daddr":         "8.8.8.8",
		"dport":         443,
		"score":         0,
		"timestamp_str": "2026-01-01T00:00:00",
	}
	output := f.Format(event)
	if !strings.Contains(output, "NETWORK") {
		t.Error("expected 'NETWORK' in output")
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("expected '10.0.0.1' in output")
	}
	if !strings.Contains(output, "8.8.8.8") {
		t.Error("expected '8.8.8.8' in output")
	}
}

func TestHumanFormatterSyscall(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type":    "syscall",
		"syscall_nr":    319,
		"pid":           42,
		"args":          []int{0},
		"score":         85,
		"timestamp_str": "2026-01-01T00:00:00",
	}
	output := f.Format(event)
	if !strings.Contains(output, "SYSCALL") {
		t.Error("expected 'SYSCALL' in output")
	}
}

func TestHumanFormatterColorRed(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type": "file", "score": 90, "operation": "modify",
		"path": "/x", "timestamp_str": "t",
	}
	output := f.Format(event)
	if !strings.Contains(output, "[red]") {
		t.Error("expected [red] for score 90")
	}
}

func TestHumanFormatterColorYellow(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type": "file", "score": 50, "operation": "modify",
		"path": "/x", "timestamp_str": "t",
	}
	output := f.Format(event)
	if !strings.Contains(output, "[yellow]") {
		t.Error("expected [yellow] for score 50")
	}
}

func TestHumanFormatterColorWhite(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type": "file", "score": 10, "operation": "modify",
		"path": "/x", "timestamp_str": "t",
	}
	output := f.Format(event)
	if !strings.Contains(output, "[white]") {
		t.Error("expected [white] for score 10")
	}
}

func TestHumanFormatterWithLLM(t *testing.T) {
	f := &HumanFormatter{}
	event := map[string]interface{}{
		"event_type":    "file",
		"score":         90,
		"operation":     "modify",
		"path":          "/etc/passwd",
		"timestamp_str": "t",
		"llm_analysis":  "Critical file modification detected",
	}
	output := f.Format(event)
	if !strings.Contains(output, "AI:") {
		t.Error("expected AI annotation in output")
	}
}

// --- Pipeline Tests ---

func TestPipelineInitJSON(t *testing.T) {
	c := config.DefaultSentinelConfig()
	c.OutputFormat = "json"
	p := NewOutputPipeline(c, nil)
	if _, ok := p.Formatter.(*JSONFormatter); !ok {
		t.Error("expected JSONFormatter")
	}
}

func TestPipelineInitCEF(t *testing.T) {
	c := config.DefaultSentinelConfig()
	c.OutputFormat = "cef"
	p := NewOutputPipeline(c, nil)
	if _, ok := p.Formatter.(*CEFFormatter); !ok {
		t.Error("expected CEFFormatter")
	}
}

func TestPipelineInitHuman(t *testing.T) {
	c := config.DefaultSentinelConfig()
	c.OutputFormat = "human"
	p := NewOutputPipeline(c, nil)
	if _, ok := p.Formatter.(*HumanFormatter); !ok {
		t.Error("expected HumanFormatter")
	}
}

func TestPipelineAcceptsNilLLM(t *testing.T) {
	c := config.DefaultSentinelConfig()
	c.OutputFormat = "json"
	p := NewOutputPipeline(c, nil)
	if p.LLM != nil {
		t.Error("expected nil LLM")
	}
}
