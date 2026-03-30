package web

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/loudmumble/sentinel/internal/config"
)

func newTestServer() *Server {
	cfg := config.DefaultSentinelConfig()
	return NewServer(cfg, nil)
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	if data["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", data["status"])
	}
	if data["service"] != "sentinel" {
		t.Errorf("expected service 'sentinel', got %v", data["service"])
	}
	if data["version"] != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %v", data["version"])
	}
}

func TestGetEventsEmpty(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	count, ok := data["count"].(float64)
	if !ok || count != 0 {
		t.Errorf("expected count 0, got %v", data["count"])
	}
}

func TestPostAndGetEvents(t *testing.T) {
	s := newTestServer()

	// POST event
	event := map[string]interface{}{"event_type": "test", "score": 10}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/events", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("POST expected 200, got %d", w.Code)
	}

	// GET events
	req = httptest.NewRequest("GET", "/api/events", nil)
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	count, _ := data["count"].(float64)
	if count != 1 {
		t.Errorf("expected count 1, got %v", count)
	}
}

func TestEventStats(t *testing.T) {
	s := newTestServer()

	// Add some events
	for _, score := range []int{90, 60, 30, 10} {
		event := map[string]interface{}{"event_type": "test", "score": score}
		body, _ := json.Marshal(event)
		req := httptest.NewRequest("POST", "/api/events", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, req)
	}

	req := httptest.NewRequest("GET", "/api/events/stats", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)

	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	total, _ := data["total"].(float64)
	if total != 4 {
		t.Errorf("expected total 4, got %v", total)
	}
	bySeverity, ok := data["by_severity"].(map[string]interface{})
	if !ok {
		t.Fatal("expected by_severity map")
	}
	if bySeverity["critical"].(float64) != 1 {
		t.Errorf("expected 1 critical, got %v", bySeverity["critical"])
	}
}

func TestEmptyStats(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/api/events/stats", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)

	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	total, _ := data["total"].(float64)
	if total != 0 {
		t.Errorf("expected total 0, got %v", total)
	}
}

func TestProbeStatus(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/api/probes/status", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)

	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	probeMap, ok := data["probes"].(map[string]interface{})
	if !ok {
		t.Fatal("expected probes map")
	}
	for _, probe := range []string{"process", "syscall", "file", "network"} {
		if _, ok := probeMap[probe]; !ok {
			t.Errorf("expected probe %q in status", probe)
		}
	}
}

func TestProbeStartStop(t *testing.T) {
	s := newTestServer()

	// Start process probe
	req := httptest.NewRequest("POST", "/api/probes/process/start", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	if data["status"] != "running" {
		t.Errorf("expected status 'running', got %v", data["status"])
	}

	// Stop process probe
	req = httptest.NewRequest("POST", "/api/probes/process/stop", nil)
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&data)
	if data["status"] != "stopped" {
		t.Errorf("expected status 'stopped', got %v", data["status"])
	}
}

func TestLLMStatus(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/api/llm/status", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)

	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	if _, ok := data["available"]; !ok {
		t.Error("expected 'available' in response")
	}
	if _, ok := data["backend"]; !ok {
		t.Error("expected 'backend' in response")
	}
	if _, ok := data["model"]; !ok {
		t.Error("expected 'model' in response")
	}
}

func TestLLMAnalyzeNoBackend(t *testing.T) {
	s := newTestServer()
	event := map[string]interface{}{"event_type": "test"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/llm/analyze", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestIndexPage(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("SENTINEL")) {
		t.Error("expected HTML dashboard with SENTINEL")
	}
}

func TestEventsMinScore(t *testing.T) {
	s := newTestServer()

	// Add events with different scores
	for _, score := range []int{10, 50, 90} {
		event := map[string]interface{}{"event_type": "test", "score": score}
		body, _ := json.Marshal(event)
		req := httptest.NewRequest("POST", "/api/events", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, req)
	}

	// Get only high-score events
	req := httptest.NewRequest("GET", "/api/events?min_score=50", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	var data map[string]interface{}
	json.NewDecoder(w.Body).Decode(&data)
	count, _ := data["count"].(float64)
	if count != 2 {
		t.Errorf("expected 2 events with min_score=50, got %v", count)
	}
}

func TestServerWithCORS(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected CORS header")
	}
}
