package analysis

import (
	"testing"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
)

// --- Analysis Engine Tests ---

func TestEnrichAddsEventType(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	e := events.NewProcessEvent()
	e.Action = "exec"
	e.PID = 1
	e.Comm = "test"
	enriched := engine.Enrich(e)
	if enriched["event_type"] != "process" {
		t.Errorf("expected event_type 'process', got %v", enriched["event_type"])
	}
	if _, ok := enriched["timestamp_str"]; !ok {
		t.Error("expected timestamp_str in enriched event")
	}
}

func TestEnrichAddsTimestampStr(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	e := events.NewFileEvent()
	e.Path = "/tmp/x"
	e.Operation = "create"
	enriched := engine.Enrich(e)
	ts, ok := enriched["timestamp_str"].(string)
	if !ok {
		t.Fatal("expected timestamp_str to be string")
	}
	if len(ts) == 0 {
		t.Error("expected non-empty timestamp_str")
	}
}

func TestAnomalyCriticalFilePasswd(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "file", "operation": "modify", "path": "/etc/passwd"}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "critical_file_mod" {
		t.Errorf("expected rule 'critical_file_mod', got %v", anomalies[0]["rule"])
	}
	if anomalies[0]["score"] != 90 {
		t.Errorf("expected score 90, got %v", anomalies[0]["score"])
	}
}

func TestAnomalyCriticalFileShadow(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "file", "operation": "delete", "path": "/etc/shadow"}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "critical_file_mod" {
		t.Errorf("expected rule 'critical_file_mod', got %v", anomalies[0]["rule"])
	}
}

func TestAnomalyBinFileMod(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "file", "operation": "modify", "path": "/bin/sh"}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "bin_file_mod" {
		t.Errorf("expected rule 'bin_file_mod', got %v", anomalies[0]["rule"])
	}
	if anomalies[0]["score"] != 80 {
		t.Errorf("expected score 80, got %v", anomalies[0]["score"])
	}
}

func TestAnomalyUsrBinMod(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "file", "operation": "modify", "path": "/usr/bin/python3"}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "bin_file_mod" {
		t.Errorf("expected rule 'bin_file_mod', got %v", anomalies[0]["rule"])
	}
}

func TestAnomalyRootShell(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "process", "action": "exec", "comm": "bash", "uid": 0}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "root_shell" {
		t.Errorf("expected rule 'root_shell', got %v", anomalies[0]["rule"])
	}
	if anomalies[0]["score"] != 50 {
		t.Errorf("expected score 50, got %v", anomalies[0]["score"])
	}
}

func TestAnomalyRootShellOtherShells(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	for _, shell := range []string{"sh", "dash", "zsh"} {
		event := map[string]interface{}{"event_type": "process", "action": "exec", "comm": shell, "uid": 0}
		anomalies := engine.DetectAnomalies(event)
		if len(anomalies) < 1 {
			t.Errorf("expected anomaly for shell %q, got none", shell)
		}
	}
}

func TestNoAnomalyNonrootShell(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "process", "action": "exec", "comm": "bash", "uid": 1000}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies for non-root shell, got %d", len(anomalies))
	}
}

func TestAnomalyUnusualPort(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "network", "dport": 25}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "unusual_port" {
		t.Errorf("expected rule 'unusual_port', got %v", anomalies[0]["rule"])
	}
	if anomalies[0]["score"] != 30 {
		t.Errorf("expected score 30, got %v", anomalies[0]["score"])
	}
}

func TestNoAnomalyStandardPorts(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	for _, port := range []int{80, 443, 22, 53, 123} {
		event := map[string]interface{}{"event_type": "network", "dport": port}
		anomalies := engine.DetectAnomalies(event)
		if len(anomalies) != 0 {
			t.Errorf("false positive for port %d", port)
		}
	}
}

func TestNoAnomalyHighPort(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "network", "dport": 8080}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies for high port, got %d", len(anomalies))
	}
}

func TestNoAnomalyFileCreate(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "file", "operation": "create", "path": "/tmp/harmless.txt"}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies for safe file create, got %d", len(anomalies))
	}
}

func TestAnomalyMemfdCreate(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{"event_type": "syscall", "syscall_nr": 319, "pid": 42, "comm": "suspicious"}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly for memfd_create, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "memfd_create_anonymous" {
		t.Errorf("expected rule 'memfd_create_anonymous', got %v", anomalies[0]["rule"])
	}
	if anomalies[0]["score"] != 85 {
		t.Errorf("expected score 85, got %v", anomalies[0]["score"])
	}
}

func TestAnomalyProcessMasquerade(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{
		"event_type": "syscall",
		"syscall_nr": 157,
		"args":       []int{15},
		"comm":       "kworker/0:0",
		"pid":        42,
	}
	anomalies := engine.DetectAnomalies(event)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly for process masquerade, got %d", len(anomalies))
	}
	if anomalies[0]["rule"] != "process_masquerade" {
		t.Errorf("expected rule 'process_masquerade', got %v", anomalies[0]["rule"])
	}
	if anomalies[0]["score"] != 75 {
		t.Errorf("expected score 75, got %v", anomalies[0]["score"])
	}
}

func TestProcessReturnsEnrichedWithScore(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	e := events.NewFileEvent()
	e.Path = "/etc/passwd"
	e.Operation = "modify"
	results := engine.Process([]events.EventInterface{e})
	if len(results) < 1 {
		t.Fatal("expected at least 1 result")
	}
	scored := false
	for _, r := range results {
		if s, ok := r["score"].(int); ok && s == 90 {
			scored = true
			break
		}
	}
	if !scored {
		t.Error("expected a result with score 90")
	}
}

func TestEngineAcceptsNilLLM(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	if engine.LLM != nil {
		t.Error("expected nil LLM")
	}
}

func TestLLMClassifyProcessNoLLM(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	result := engine.LLMClassifyProcess(map[string]interface{}{"comm": "bash", "uid": 0, "action": "exec"})
	if result != nil {
		t.Error("expected nil result with no LLM")
	}
}

func TestLLMExplainFileNoLLM(t *testing.T) {
	engine := NewAnalysisEngine(config.DefaultSentinelConfig(), nil)
	result := engine.LLMExplainFileAnomaly("/etc/passwd", "modify")
	if result != "" {
		t.Errorf("expected empty string with no LLM, got %q", result)
	}
}

// --- Correlator Tests ---

func TestCorrelatorInit(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	if c.WindowSize != 5.0 {
		t.Errorf("expected window_size 5.0, got %f", c.WindowSize)
	}
	if len(c.Events) != 0 {
		t.Errorf("expected empty events, got %d", len(c.Events))
	}
}

func TestCorrelatorAddEventStores(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	event := map[string]interface{}{
		"event_type": "process",
		"action":     "exec",
		"pid":        1,
		"timestamp":  float64(time.Now().Unix()),
	}
	c.AddEvent(event)
	if len(c.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(c.Events))
	}
}

func TestCorrelatorWindowCleanup(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	oldTime := float64(time.Now().Unix()) - 10
	c.AddEvent(map[string]interface{}{"event_type": "process", "timestamp": oldTime, "pid": 1})
	c.AddEvent(map[string]interface{}{"event_type": "process", "timestamp": float64(time.Now().Unix()), "pid": 2})
	if len(c.Events) != 1 {
		t.Errorf("expected 1 event after window cleanup, got %d", len(c.Events))
	}
}

func TestExecThenConnectCorrelation(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	now := float64(time.Now().Unix())
	execEvent := map[string]interface{}{
		"event_type": "process",
		"action":     "exec",
		"pid":        42,
		"comm":       "curl",
		"timestamp":  now,
	}
	c.AddEvent(execEvent)
	netEvent := map[string]interface{}{
		"event_type": "network",
		"pid":        42,
		"daddr":      "1.2.3.4",
		"dport":      443,
		"timestamp":  now + 0.1,
	}
	result := c.AddEvent(netEvent)
	if result == nil {
		t.Fatal("expected correlation result")
	}
	if result["type"] != "correlation" {
		t.Errorf("expected type 'correlation', got %v", result["type"])
	}
	if result["rule"] != "exec_then_connect" {
		t.Errorf("expected rule 'exec_then_connect', got %v", result["rule"])
	}
	if result["score"] != 60 {
		t.Errorf("expected score 60, got %v", result["score"])
	}
}

func TestNoCorrelationDifferentPID(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	now := float64(time.Now().Unix())
	c.AddEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 42, "comm": "curl", "timestamp": now,
	})
	result := c.AddEvent(map[string]interface{}{
		"event_type": "network", "pid": 99, "daddr": "1.2.3.4", "dport": 443, "timestamp": now + 0.1,
	})
	if result != nil {
		t.Error("expected no correlation for different PIDs")
	}
}

func TestNoCorrelationForNonNetwork(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	now := float64(time.Now().Unix())
	result := c.AddEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 1, "timestamp": now,
	})
	if result != nil {
		t.Error("expected no correlation for non-network event")
	}
}

func TestForkThenMemfdCorrelation(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	now := float64(time.Now().Unix())
	c.AddEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 42, "comm": "evil", "timestamp": now,
	})
	result := c.AddEvent(map[string]interface{}{
		"event_type": "syscall", "syscall_nr": 319, "pid": 42, "timestamp": now + 0.1,
	})
	if result == nil {
		t.Fatal("expected fork_then_memfd correlation")
	}
	if result["rule"] != "fork_then_memfd" {
		t.Errorf("expected rule 'fork_then_memfd', got %v", result["rule"])
	}
	if result["score"] != 90 {
		t.Errorf("expected score 90, got %v", result["score"])
	}
}

func TestCorrelatorAcceptsNilLLM(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	if c.LLM != nil {
		t.Error("expected nil LLM")
	}
}

func TestCorrelatorNarrateNoLLM(t *testing.T) {
	c := NewCorrelator(config.DefaultSentinelConfig(), nil)
	result := c.LLMNarrateCorrelation(
		map[string]interface{}{"pid": 1, "comm": "curl"},
		map[string]interface{}{"daddr": "1.2.3.4", "dport": 443},
	)
	if result != "" {
		t.Errorf("expected empty string with no LLM, got %q", result)
	}
}
