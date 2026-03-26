package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
)

// SidekickOutput buffers Sentinel events and pushes them to the Sidekick REST API.
type SidekickOutput struct {
	config config.SidekickConfig
	client *http.Client
	buffer []map[string]interface{}
	mu     sync.Mutex
	done   chan struct{}
}

// NewSidekickOutput creates a SidekickOutput with the given config.
func NewSidekickOutput(cfg config.SidekickConfig) *SidekickOutput {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5000
	}
	return &SidekickOutput{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		buffer: make([]map[string]interface{}, 0, cfg.BatchSize),
		done:   make(chan struct{}),
	}
}

// Start launches the periodic flush goroutine.
func (s *SidekickOutput) Start() {
	interval := time.Duration(s.config.FlushInterval) * time.Millisecond
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Flush()
			case <-s.done:
				return
			}
		}
	}()
}

// HandleEvent classifies the event and adds it to the buffer. Flushes if batch is full.
func (s *SidekickOutput) HandleEvent(event map[string]interface{}) {
	s.mu.Lock()
	s.buffer = append(s.buffer, event)
	shouldFlush := len(s.buffer) >= s.config.BatchSize
	s.mu.Unlock()

	if shouldFlush {
		s.Flush()
	}
}

// Flush drains the buffer and dispatches each event to the appropriate Sidekick endpoint.
func (s *SidekickOutput) Flush() {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.buffer
	s.buffer = make([]map[string]interface{}, 0, s.config.BatchSize)
	s.mu.Unlock()

	for _, event := range batch {
		s.dispatch(event)
	}
}

// Stop flushes remaining events and shuts down the flush goroutine.
func (s *SidekickOutput) Stop() {
	close(s.done)
	s.Flush()
}

// dispatch routes a single event to the correct Sidekick entity endpoint.
func (s *SidekickOutput) dispatch(event map[string]interface{}) {
	eventType, _ := event["event_type"].(string)

	switch eventType {
	case "process":
		action, _ := event["action"].(string)
		if action == "exec" {
			host := s.buildHostFromProcess(event)
			if err := s.pushHost(host); err != nil {
				fmt.Printf("[sidekick] pushHost error: %v\n", err)
			}
		}

	case "network":
		svc := s.buildServiceFromNetwork(event)
		if err := s.pushService(svc); err != nil {
			fmt.Printf("[sidekick] pushService error: %v\n", err)
		}

	case "syscall":
		score := eventScore(event)
		if score > 0 {
			vuln := s.buildVulnFromSyscall(event, score)
			if err := s.pushVulnerability(vuln); err != nil {
				fmt.Printf("[sidekick] pushVulnerability (syscall) error: %v\n", err)
			}
		}

	case "file":
		score := eventScore(event)
		if score > 0 {
			vuln := s.buildVulnFromFile(event, score)
			if err := s.pushVulnerability(vuln); err != nil {
				fmt.Printf("[sidekick] pushVulnerability (file) error: %v\n", err)
			}
		}

	case "correlation":
		vuln := s.buildVulnFromCorrelation(event)
		if err := s.pushVulnerability(vuln); err != nil {
			fmt.Printf("[sidekick] pushVulnerability (correlation) error: %v\n", err)
		}
	}
}

// buildHostFromProcess extracts host fields from a process exec event.
// The monitored host is the local machine — we use the process's uid/comm as metadata.
func (s *SidekickOutput) buildHostFromProcess(event map[string]interface{}) map[string]interface{} {
	host := map[string]interface{}{
		"hostname": localHostname(),
		"ip":       "127.0.0.1",
		"os":       "linux",
		"status":   "up",
		"tags":     []string{"sentinel", "auto-discovered"},
		"metadata": map[string]interface{}{
			"comm":     event["comm"],
			"pid":      event["pid"],
			"uid":      event["uid"],
			"filename": event["filename"],
		},
	}
	if s.config.EngagementID != "" {
		host["engagement_id"] = s.config.EngagementID
	}
	return host
}

// buildServiceFromNetwork maps a network connection event to a Sidekick service entry.
func (s *SidekickOutput) buildServiceFromNetwork(event map[string]interface{}) map[string]interface{} {
	protocol, _ := event["protocol"].(string)
	if protocol == "" {
		protocol = "tcp"
	}
	svc := map[string]interface{}{
		"port":          event["dport"],
		"protocol":      protocol,
		"service_name":  fmt.Sprintf("%v", event["comm"]),
		"state":         "open",
		"discovered_by": "sentinel",
		"metadata": map[string]interface{}{
			"remote_ip": event["daddr"],
			"local_ip":  event["saddr"],
			"sport":     event["sport"],
			"pid":       event["pid"],
		},
	}
	return svc
}

// buildVulnFromSyscall maps a suspicious syscall event to a Sidekick vulnerability.
func (s *SidekickOutput) buildVulnFromSyscall(event map[string]interface{}, score int) map[string]interface{} {
	title := fmt.Sprintf("Suspicious syscall: %v (pid=%v, comm=%v)", event["syscall_name"], event["pid"], event["comm"])
	desc := anomalyDesc(event)

	vuln := map[string]interface{}{
		"title":         title,
		"severity":      scoreToSeverity(score),
		"description":   desc,
		"proof":         fmt.Sprintf("syscall_nr=%v args=%v", event["syscall_nr"], event["args"]),
		"status":        "open",
		"discovered_by": "sentinel",
	}
	if s.config.EngagementID != "" {
		vuln["engagement_id"] = s.config.EngagementID
	}
	return vuln
}

// buildVulnFromFile maps a file integrity change event to a Sidekick vulnerability.
func (s *SidekickOutput) buildVulnFromFile(event map[string]interface{}, score int) map[string]interface{} {
	path, _ := event["path"].(string)
	op, _ := event["operation"].(string)
	title := fmt.Sprintf("Unauthorized file modification: %s (%s)", path, op)
	desc := anomalyDesc(event)

	vuln := map[string]interface{}{
		"title":         title,
		"severity":      scoreToSeverity(score),
		"description":   desc,
		"proof":         fmt.Sprintf("path=%s operation=%s pid=%v uid=%v", path, op, event["pid"], event["uid"]),
		"remediation":   "Investigate process responsible for modification and verify file integrity.",
		"status":        "open",
		"discovered_by": "sentinel",
	}
	if s.config.EngagementID != "" {
		vuln["engagement_id"] = s.config.EngagementID
	}
	return vuln
}

// buildVulnFromCorrelation maps a behavioral correlation event to a high-severity vulnerability.
func (s *SidekickOutput) buildVulnFromCorrelation(event map[string]interface{}) map[string]interface{} {
	rule, _ := event["rule"].(string)
	desc, _ := event["desc"].(string)
	score := eventScore(event)
	if score == 0 {
		score = 80 // correlations are always significant
	}

	title := fmt.Sprintf("Behavioral pattern detected: %s", rule)
	proof := desc
	if narrative, ok := event["llm_narrative"].(string); ok && narrative != "" {
		proof = fmt.Sprintf("%s\n\nAI Narrative: %s", desc, narrative)
	}

	vuln := map[string]interface{}{
		"title":         title,
		"severity":      scoreToSeverity(score),
		"description":   fmt.Sprintf("Sentinel correlation rule '%s' triggered: %s", rule, desc),
		"proof":         proof,
		"remediation":   "Investigate correlated process chain for malicious activity.",
		"status":        "open",
		"discovered_by": "sentinel",
	}
	if s.config.EngagementID != "" {
		vuln["engagement_id"] = s.config.EngagementID
	}
	return vuln
}

// pushHost POSTs a host record to Sidekick /api/hosts.
func (s *SidekickOutput) pushHost(host map[string]interface{}) error {
	return s.post("/api/hosts", host)
}

// pushService POSTs a service record to Sidekick /api/services.
func (s *SidekickOutput) pushService(svc map[string]interface{}) error {
	return s.post("/api/services", svc)
}

// pushVulnerability POSTs a vulnerability record to Sidekick /api/vulnerabilities.
func (s *SidekickOutput) pushVulnerability(vuln map[string]interface{}) error {
	return s.post("/api/vulnerabilities", vuln)
}

// pushCredential POSTs a credential record to Sidekick /api/credentials.
func (s *SidekickOutput) pushCredential(cred map[string]interface{}) error {
	return s.post("/api/credentials", cred)
}

// post marshals payload and POSTs to baseURL+path, returning any HTTP-level error.
func (s *SidekickOutput) post(path string, payload map[string]interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	resp, err := s.client.Post(s.config.BaseURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("http post %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sidekick %s returned %d", path, resp.StatusCode)
	}
	return nil
}

// scoreToSeverity maps a 0-100 heuristic score to a Sidekick severity string.
func scoreToSeverity(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// eventScore extracts the score field from an enriched event map.
func eventScore(event map[string]interface{}) int {
	switch v := event["score"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// anomalyDesc builds a human-readable description from event anomalies.
func anomalyDesc(event map[string]interface{}) string {
	if anomalies, ok := event["anomalies"].([]map[string]interface{}); ok && len(anomalies) > 0 {
		desc, _ := anomalies[0]["desc"].(string)
		if desc != "" {
			return desc
		}
	}
	if desc, ok := event["desc"].(string); ok {
		return desc
	}
	return fmt.Sprintf("Sentinel detected anomalous %v event (score=%v)", event["event_type"], event["score"])
}

// localHostname returns the system hostname, falling back to "localhost".
func localHostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}
