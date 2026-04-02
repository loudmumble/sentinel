package output

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
)

type mockSidekickServer struct {
	mu       sync.Mutex
	received []struct {
		Path string
		Body map[string]interface{}
	}
	server *httptest.Server
}

func newMockSidekickServer() *mockSidekickServer {
	m := &mockSidekickServer{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.received = append(m.received, struct {
			Path string
			Body map[string]interface{}
		}{r.URL.Path, body})
		m.mu.Unlock()
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	return m
}

func (m *mockSidekickServer) requests() []struct {
	Path string
	Body map[string]interface{}
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]struct {
		Path string
		Body map[string]interface{}
	}, len(m.received))
	copy(cp, m.received)
	return cp
}

func TestSidekickProcessExecPushesHost(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type": "process",
		"action":     "exec",
		"pid":        42,
		"comm":       "bash",
		"uid":        0,
	})

	reqs := mock.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Path != "/api/hosts" {
		t.Errorf("expected POST to /api/hosts, got %s", reqs[0].Path)
	}
	if reqs[0].Body["os"] != "linux" {
		t.Errorf("expected os=linux, got %v", reqs[0].Body["os"])
	}
	if reqs[0].Body["status"] != "up" {
		t.Errorf("expected status=up, got %v", reqs[0].Body["status"])
	}
}

func TestSidekickNetworkPushesService(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type": "network",
		"dport":      float64(443),
		"daddr":      "8.8.8.8",
		"saddr":      "10.0.0.1",
		"sport":      float64(54321),
		"pid":        float64(100),
		"comm":       "curl",
		"protocol":   "tcp",
	})

	reqs := mock.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Path != "/api/services" {
		t.Errorf("expected POST to /api/services, got %s", reqs[0].Path)
	}
	if reqs[0].Body["protocol"] != "tcp" {
		t.Errorf("expected protocol=tcp, got %v", reqs[0].Body["protocol"])
	}
	if reqs[0].Body["state"] != "open" {
		t.Errorf("expected state=open, got %v", reqs[0].Body["state"])
	}
}

func TestSidekickSyscallHighScorePushesVulnerability(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type":  "syscall",
		"syscall_nr":  319,
		"syscall_name": "memfd_create",
		"pid":         42,
		"comm":        "malware",
		"score":       85,
		"anomalies": []map[string]interface{}{
			{"rule": "memfd_create_anonymous", "score": 85, "desc": "memfd_create detected"},
		},
	})

	reqs := mock.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Path != "/api/vulnerabilities" {
		t.Errorf("expected POST to /api/vulnerabilities, got %s", reqs[0].Path)
	}
	if reqs[0].Body["severity"] != "high" {
		t.Errorf("expected severity=high for score 85, got %v", reqs[0].Body["severity"])
	}
	if reqs[0].Body["status"] != "open" {
		t.Errorf("expected status=open, got %v", reqs[0].Body["status"])
	}
}

func TestSidekickFileHighScorePushesVulnerability(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type": "file",
		"operation":  "modify",
		"path":       "/etc/passwd",
		"score":      90,
		"anomalies": []map[string]interface{}{
			{"rule": "critical_file_mod", "score": 90, "desc": "Modification to critical file /etc/passwd"},
		},
	})

	reqs := mock.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Path != "/api/vulnerabilities" {
		t.Errorf("expected POST to /api/vulnerabilities, got %s", reqs[0].Path)
	}
	if reqs[0].Body["severity"] != "critical" {
		t.Errorf("expected severity=critical for score 90, got %v", reqs[0].Body["severity"])
	}
}

func TestSidekickCorrelationPushesVulnerability(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type": "correlation",
		"rule":       "exec_then_connect",
		"score":      60,
		"desc":       "Process 42 started then immediately connected to 1.2.3.4:443",
	})

	reqs := mock.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Path != "/api/vulnerabilities" {
		t.Errorf("expected POST to /api/vulnerabilities, got %s", reqs[0].Path)
	}
}

func TestSidekickLowScoreSyscallNotPushed(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type": "syscall",
		"syscall_nr": 1,
		"pid":        42,
		"score":      0,
	})

	reqs := mock.requests()
	if len(reqs) != 0 {
		t.Errorf("expected 0 requests for low-score syscall, got %d", len(reqs))
	}
}

func TestSidekickBatchFlush(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     3,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	// Send 2 events — should NOT flush (batch size 3)
	s.HandleEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 1, "comm": "a",
	})
	s.HandleEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 2, "comm": "b",
	})
	if len(mock.requests()) != 0 {
		t.Errorf("expected 0 requests before batch full, got %d", len(mock.requests()))
	}

	// Send 3rd event — should trigger flush
	s.HandleEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 3, "comm": "c",
	})
	// Give flush goroutine a moment
	time.Sleep(50 * time.Millisecond)
	if len(mock.requests()) != 3 {
		t.Errorf("expected 3 requests after batch full, got %d", len(mock.requests()))
	}
}

func TestSidekickPeriodicFlush(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     100,
		FlushInterval: 100, // 100ms
	}
	s := NewSidekickOutput(cfg)
	s.Start()
	defer s.Stop()

	s.HandleEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 1, "comm": "test",
	})

	// Wait for periodic flush
	time.Sleep(250 * time.Millisecond)
	if len(mock.requests()) != 1 {
		t.Errorf("expected 1 request after periodic flush, got %d", len(mock.requests()))
	}
}

func TestSidekickEngagementID(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		EngagementID:  "test-engagement-123",
		BatchSize:     1,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)

	s.HandleEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 1, "comm": "test",
	})

	reqs := mock.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Body["engagement_id"] != "test-engagement-123" {
		t.Errorf("expected engagement_id, got %v", reqs[0].Body["engagement_id"])
	}
}

func TestSidekickStopFlushesPending(t *testing.T) {
	mock := newMockSidekickServer()
	defer mock.server.Close()

	cfg := config.SidekickConfig{
		Enabled:       true,
		BaseURL:       mock.server.URL,
		BatchSize:     100,
		FlushInterval: 60000,
	}
	s := NewSidekickOutput(cfg)
	s.Start()

	s.HandleEvent(map[string]interface{}{
		"event_type": "process", "action": "exec", "pid": 1, "comm": "test",
	})

	// No flush yet (batch not full, timer not fired)
	if len(mock.requests()) != 0 {
		t.Errorf("expected 0 requests before stop, got %d", len(mock.requests()))
	}

	s.Stop()

	if len(mock.requests()) != 1 {
		t.Errorf("expected 1 request after stop flush, got %d", len(mock.requests()))
	}
}
