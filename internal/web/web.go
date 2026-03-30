// Package web provides the HTTP API and dashboard for Sentinel.
package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/llm"
)

// Server holds the web server state.
type Server struct {
	Config      config.SentinelConfig
	LLM         *llm.HybridLLMClient
	Events      []map[string]interface{}
	ProbeStatus map[string]string
	mu          sync.RWMutex
	Mux         *http.ServeMux
}

// NewServer creates a web server with all routes.
func NewServer(cfg config.SentinelConfig, llmClient *llm.HybridLLMClient) *Server {
	s := &Server{
		Config: cfg,
		LLM:    llmClient,
		Events: []map[string]interface{}{},
		ProbeStatus: map[string]string{
			"process": "unknown",
			"syscall": "unknown",
			"file":    "unknown",
			"network": "unknown",
		},
		Mux: http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.Mux.HandleFunc("/", s.handleIndex)
	s.Mux.HandleFunc("/health", s.handleHealth)
	s.Mux.HandleFunc("/api/probes/status", s.handleProbeStatus)
	s.Mux.HandleFunc("/api/events", s.handleEvents)
	s.Mux.HandleFunc("/api/events/stats", s.handleEventStats)
	s.Mux.HandleFunc("/api/llm/status", s.handleLLMStatus)
	s.Mux.HandleFunc("/api/llm/analyze", s.handleLLMAnalyze)
	// Probe control - handle both start and stop
	s.Mux.HandleFunc("/api/probes/", s.handleProbeControl)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, webUI)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"status":  "ok",
		"service": "sentinel",
		"version": "1.0.0",
	})
}

func (s *Server) handleProbeStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, 200, map[string]interface{}{"probes": s.ProbeStatus})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.mu.RLock()
		defer s.mu.RUnlock()

		limit := 100
		minScore := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = n
			}
		}
		if v := r.URL.Query().Get("min_score"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				minScore = n
			}
		}

		var filtered []map[string]interface{}
		for _, e := range s.Events {
			score := getScore(e)
			if score >= minScore {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) > limit {
			filtered = filtered[len(filtered)-limit:]
		}
		writeJSON(w, 200, map[string]interface{}{
			"events": filtered,
			"count":  len(filtered),
		})

	case "POST":
		s.mu.Lock()
		defer s.mu.Unlock()

		var event map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			writeJSON(w, 400, map[string]interface{}{"error": "invalid JSON"})
			return
		}
		event["timestamp"] = time.Now().UTC().Format(time.RFC3339)

		// LLM triage for high-score events
		if getScore(event) >= 50 && s.LLM != nil && s.LLM.IsAvailable() {
			resp, err := s.LLM.Generate(
				fmt.Sprintf("Triage this security event in 1 sentence: type=%v, score=%v, details=%v",
					event["event_type"], event["score"], event),
				"You are a SOC analyst. Be concise.",
				llm.WithTimeout(30),
				llm.WithMaxTokens(128),
			)
			if err == nil {
				event["llm_triage"] = resp.Content
			}
		}

		s.Events = append(s.Events, event)
		if len(s.Events) > 10000 {
			s.Events = s.Events[len(s.Events)-5000:]
		}
		writeJSON(w, 200, map[string]interface{}{"status": "added"})

	default:
		w.WriteHeader(405)
	}
}

func (s *Server) handleEventStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.Events) == 0 {
		writeJSON(w, 200, map[string]interface{}{
			"total":       0,
			"by_type":     map[string]int{},
			"by_severity": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
			"avg_score":   0,
		})
		return
	}

	byType := map[string]int{}
	bySeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	totalScore := 0

	for _, e := range s.Events {
		etype, _ := e["event_type"].(string)
		if etype == "" {
			etype = "unknown"
		}
		byType[etype]++

		score := getScore(e)
		totalScore += score
		if score >= 75 {
			bySeverity["critical"]++
		} else if score >= 50 {
			bySeverity["high"]++
		} else if score >= 25 {
			bySeverity["medium"]++
		} else {
			bySeverity["low"]++
		}
	}

	avgScore := float64(totalScore) / float64(len(s.Events))
	writeJSON(w, 200, map[string]interface{}{
		"total":       len(s.Events),
		"by_type":     byType,
		"by_severity": bySeverity,
		"avg_score":   avgScore,
	})
}

func (s *Server) handleLLMStatus(w http.ResponseWriter, r *http.Request) {
	available := s.LLM != nil && s.LLM.IsAvailable()
	backend := "none"
	model := ""
	if s.LLM != nil {
		backend = s.LLM.ActiveBackend()
		model = s.LLM.Config.Ollama.Model
	}
	writeJSON(w, 200, map[string]interface{}{
		"available": available,
		"backend":   backend,
		"model":     model,
	})
}

func (s *Server) handleLLMAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if s.LLM == nil || !s.LLM.IsAvailable() {
		writeJSON(w, 503, map[string]interface{}{"error": "LLM backend unavailable"})
		return
	}

	var event map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeJSON(w, 400, map[string]interface{}{"error": "invalid JSON"})
		return
	}

	eventJSON, _ := json.MarshalIndent(event, "", "  ")
	result, err := s.LLM.GenerateJSON(
		fmt.Sprintf("Analyze this security event:\n%s\n\n"+
			`Respond with JSON: {"threat_class": str, "severity": str, "mitre_technique": str, "confidence": 0-100, "summary": str}`,
			string(eventJSON)),
		"You are a senior SOC analyst. Be precise and actionable.",
		llm.WithTimeout(90),
		llm.WithMaxTokens(1024),
	)
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"analysis": result})
}

func (s *Server) handleProbeControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	// Parse /api/probes/{probe}/start or /api/probes/{probe}/stop
	path := strings.TrimPrefix(r.URL.Path, "/api/probes/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writeJSON(w, 400, map[string]interface{}{"error": "invalid path"})
		return
	}
	probe := parts[0]
	action := parts[1]

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.ProbeStatus[probe]; ok {
		switch action {
		case "start":
			s.ProbeStatus[probe] = "running"
		case "stop":
			s.ProbeStatus[probe] = "stopped"
		}
	}
	writeJSON(w, 200, map[string]interface{}{"probe": probe, "status": s.ProbeStatus[probe]})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func getScore(event map[string]interface{}) int {
	switch v := event["score"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

const webUI = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sentinel — Security Monitoring</title>
<style>*{margin:0;padding:0;box-sizing:border-box}:root{--bg:#0a0a12;--surface:#12121f;--border:#1e1e35;--text:#e0e0f0;--dim:#666;--accent:#ff6b4a;--danger:#ff4466;--warning:#ffaa00;--safe:#00cc66;--cyan:#00ccff}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}.container{max-width:1400px;margin:0 auto;padding:2rem}header{text-align:center;margin-bottom:2rem}header h1{font-size:3rem;background:linear-gradient(135deg,var(--accent),var(--warning));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:800;letter-spacing:4px}header p{color:var(--dim);margin-top:.5rem;font-size:1.1rem}.dashboard{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;text-align:center}.stat-card .value{font-size:2.5rem;font-weight:700}.stat-card .label{color:var(--dim);font-size:.85rem;text-transform:uppercase;letter-spacing:1px}.stat-card.critical .value{color:var(--danger)}.stat-card.medium .value{color:var(--warning)}.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}.card h2{color:var(--accent);margin-bottom:1rem}</style></head><body><div class="container"><header><h1>SENTINEL</h1><p>eBPF-based Security Monitoring Platform</p></header><div class="dashboard"><div class="stat-card"><div class="value" id="totalEvents">0</div><div class="label">Total Events</div></div><div class="stat-card critical"><div class="value" id="criticalCount">0</div><div class="label">Critical</div></div><div class="stat-card"><div class="value" id="highCount">0</div><div class="label">High</div></div><div class="stat-card medium"><div class="value" id="avgScore">0</div><div class="label">Avg Score</div></div></div><div class="card"><h2>Live Events</h2><div id="eventsList"><p style="color:var(--dim)">Waiting for events...</p></div></div></div><script>async function loadStats(){try{const r=await fetch('/api/events/stats');const d=await r.json();document.getElementById('totalEvents').textContent=d.total;document.getElementById('criticalCount').textContent=d.by_severity.critical;document.getElementById('highCount').textContent=d.by_severity.high;document.getElementById('avgScore').textContent=d.avg_score.toFixed(1)}catch(e){}}setInterval(loadStats,3000);loadStats()</script></body></html>`
