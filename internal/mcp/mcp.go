// Package mcp implements the MCP server tools for Sentinel.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/loudmumble/sentinel/internal/analysis"
	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
	"github.com/loudmumble/sentinel/internal/llm"
	"github.com/loudmumble/sentinel/internal/probes"
)

// Tool describes an MCP tool.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ListTools returns the available MCP tools.
func ListTools() []Tool {
	return []Tool{
		{
			Name:        "monitor",
			Description: "Start all enabled probes (process, syscall, file, network) and collect security events for a specified duration.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"output_format":    map[string]interface{}{"type": "string", "enum": []string{"json", "cef", "human"}, "description": "Output format.", "default": "json"},
					"watch_paths":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Paths to watch."},
					"duration_seconds": map[string]interface{}{"type": "number", "description": "How long to monitor (default: 5).", "default": 5},
				},
				"required": []string{},
			},
		},
		{
			Name:        "trace",
			Description: "Trace syscalls for a specific process ID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pid":              map[string]interface{}{"type": "integer", "description": "Process ID to trace."},
					"syscalls":         map[string]interface{}{"type": "string", "description": "Comma-separated syscalls to filter."},
					"output_format":    map[string]interface{}{"type": "string", "enum": []string{"json", "cef", "human"}, "default": "json"},
					"duration_seconds": map[string]interface{}{"type": "number", "description": "How long to trace (default: 5).", "default": 5},
				},
				"required": []string{"pid"},
			},
		},
		{
			Name:        "watch",
			Description: "Watch filesystem paths for changes and report events.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"paths":            map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Paths to watch."},
					"output_format":    map[string]interface{}{"type": "string", "enum": []string{"json", "cef", "human"}, "default": "json"},
					"duration_seconds": map[string]interface{}{"type": "number", "description": "How long to watch (default: 5).", "default": 5},
				},
				"required": []string{"paths"},
			},
		},
		{
			Name:        "analyze",
			Description: "Analyze a security event using the LLM backend.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"event": map[string]interface{}{"type": "object", "description": "Security event JSON to analyze."},
				},
				"required": []string{"event"},
			},
		},
	}
}

// CollectEvents runs probes for a duration and returns analyzed events.
func CollectEvents(cfg config.SentinelConfig, probeNames []string, pidFilter int, duration float64, llmClient *llm.HybridLLMClient) []map[string]interface{} {
	var activeProbes []interface {
		Poll() []events.EventInterface
		Start()
		Stop()
	}

	for _, name := range probeNames {
		switch name {
		case "process":
			activeProbes = append(activeProbes, probes.NewProcessProbe(cfg))
		case "syscall":
			activeProbes = append(activeProbes, probes.NewSyscallProbe(cfg))
		case "file":
			activeProbes = append(activeProbes, probes.NewFileProbe(cfg))
		case "network":
			activeProbes = append(activeProbes, probes.NewNetworkProbe(cfg))
		}
	}

	engine := analysis.NewAnalysisEngine(cfg, llmClient)
	for _, p := range activeProbes {
		p.Start()
	}

	var allResults []map[string]interface{}
	endTime := time.Now().Add(time.Duration(duration * float64(time.Second)))

	for time.Now().Before(endTime) {
		var allEvents []events.EventInterface
		for _, p := range activeProbes {
			allEvents = append(allEvents, p.Poll()...)
		}
		if pidFilter > 0 {
			var filtered []events.EventInterface
			for _, e := range allEvents {
				if pe, ok := e.(*events.ProcessEvent); ok && pe.PID == pidFilter {
					filtered = append(filtered, e)
				} else if se, ok := e.(*events.SyscallEvent); ok && se.PID == pidFilter {
					filtered = append(filtered, e)
				}
			}
			allEvents = filtered
		}
		results := engine.Process(allEvents)
		for _, res := range results {
			allResults = append(allResults, map[string]interface{}{
				"type":     res["event_type"],
				"severity": res["severity"],
				"message":  fmt.Sprintf("%v", res),
			})
		}
		time.Sleep(500 * time.Millisecond)
	}

	for _, p := range activeProbes {
		p.Stop()
	}
	return allResults
}

// HandleToolCall dispatches a tool call to the appropriate handler.
func HandleToolCall(name string, arguments map[string]interface{}) (map[string]interface{}, error) {
	cfg := config.DefaultSentinelConfig()
	switch name {
	case "monitor":
		return handleMonitor(cfg, arguments)
	case "trace":
		return handleTrace(cfg, arguments)
	case "watch":
		return handleWatch(cfg, arguments)
	case "analyze":
		return handleAnalyze(cfg, arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func handleMonitor(cfg config.SentinelConfig, args map[string]interface{}) (map[string]interface{}, error) {
	if f, ok := args["output_format"].(string); ok {
		cfg.OutputFormat = f
	}
	if paths, ok := args["watch_paths"].([]interface{}); ok {
		var wp []string
		for _, p := range paths {
			if s, ok := p.(string); ok {
				wp = append(wp, s)
			}
		}
		cfg.WatchPaths = wp
	}
	duration := 5.0
	if d, ok := args["duration_seconds"].(float64); ok {
		duration = d
	}
	llmClient := llm.NewHybridLLMClient(cfg.LLM)
	defer llmClient.Close()
	evts := CollectEvents(cfg, []string{"process", "syscall", "file", "network"}, 0, duration, llmClient)
	result := map[string]interface{}{"status": "completed", "duration_seconds": duration, "events_collected": len(evts), "events": evts}
	addLLMAssessment(llmClient, result, evts, duration)
	return result, nil
}

func handleTrace(cfg config.SentinelConfig, args map[string]interface{}) (map[string]interface{}, error) {
	if f, ok := args["output_format"].(string); ok {
		cfg.OutputFormat = f
	}
	pid := 0
	if p, ok := args["pid"].(float64); ok {
		pid = int(p)
	}
	duration := 5.0
	if d, ok := args["duration_seconds"].(float64); ok {
		duration = d
	}
	llmClient := llm.NewHybridLLMClient(cfg.LLM)
	defer llmClient.Close()
	evts := CollectEvents(cfg, []string{"syscall"}, pid, duration, llmClient)
	result := map[string]interface{}{"status": "completed", "pid": pid, "duration_seconds": duration, "events_collected": len(evts), "events": evts}
	addLLMAssessment(llmClient, result, evts, duration)
	return result, nil
}

func handleWatch(cfg config.SentinelConfig, args map[string]interface{}) (map[string]interface{}, error) {
	if f, ok := args["output_format"].(string); ok {
		cfg.OutputFormat = f
	}
	if paths, ok := args["paths"].([]interface{}); ok {
		var wp []string
		for _, p := range paths {
			if s, ok := p.(string); ok {
				wp = append(wp, s)
			}
		}
		cfg.WatchPaths = wp
	}
	duration := 5.0
	if d, ok := args["duration_seconds"].(float64); ok {
		duration = d
	}
	llmClient := llm.NewHybridLLMClient(cfg.LLM)
	defer llmClient.Close()
	evts := CollectEvents(cfg, []string{"file"}, 0, duration, llmClient)
	result := map[string]interface{}{"status": "completed", "watched_paths": cfg.WatchPaths, "duration_seconds": duration, "events_collected": len(evts), "events": evts}
	addLLMAssessment(llmClient, result, evts, duration)
	return result, nil
}

func handleAnalyze(cfg config.SentinelConfig, args map[string]interface{}) (map[string]interface{}, error) {
	eventData, _ := args["event"].(map[string]interface{})
	llmClient := llm.NewHybridLLMClient(cfg.LLM)
	defer llmClient.Close()
	if !llmClient.IsAvailable() {
		return map[string]interface{}{"error": "No LLM backend available"}, nil
	}
	eventJSON, _ := json.Marshal(eventData)
	result, err := llmClient.GenerateJSON(
		fmt.Sprintf("Analyze this security event:\n%s\n\n"+
			`Respond with JSON: {"threat_class": str, "severity": str, "mitre_technique": str, "confidence": 0-100, "summary": str}`,
			string(eventJSON)),
		"You are a senior SOC analyst. Be precise and actionable.",
		llm.WithTimeout(cfg.LLM.Ollama.DeepTimeout),
		llm.WithMaxTokens(cfg.LLM.Ollama.DeepMaxTokens),
	)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}, nil
	}
	return map[string]interface{}{"status": "completed", "analysis": result}, nil
}

func addLLMAssessment(llmClient *llm.HybridLLMClient, result map[string]interface{}, evts []map[string]interface{}, duration float64) {
	if !llmClient.IsAvailable() || len(evts) == 0 {
		return
	}
	topEvents := evts
	if len(topEvents) > 5 {
		topEvents = topEvents[:5]
	}
	topJSON, _ := json.Marshal(topEvents)
	assessment, err := llmClient.GenerateJSON(
		fmt.Sprintf("Summarize %d security events over %.0fs. Top findings: %s. "+
			`Respond with JSON: {"threat_level": str, "summary": str, "top_findings": [str]}`,
			len(evts), duration, string(topJSON)),
		"You are a SOC analyst. Be concise.",
		llm.WithTimeout(45),
		llm.WithMaxTokens(512),
	)
	if err == nil {
		result["llm_assessment"] = assessment
	}
}

// Server wraps the MCP stdio JSON-RPC server.
type Server struct {
	Config config.SentinelConfig
	writer io.Writer
}

// NewServer creates a new MCP server with the given config.
func NewServer(cfg config.SentinelConfig) *Server {
	return &Server{Config: cfg}
}

// Run starts the MCP stdio JSON-RPC server reading from r and writing to w.
func (s *Server) Run(r io.Reader, w io.Writer) error {
	s.writer = w
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var request map[string]interface{}
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			s.writeError(nil, -32700, "Parse error")
			continue
		}

		method, _ := request["method"].(string)
		id := request["id"]

		switch method {
		case "initialize":
			s.writeResult(id, map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "sentinel", "version": "1.0.0"},
			})
		case "notifications/initialized":
			// No response needed
		case "tools/list":
			s.writeResult(id, map[string]interface{}{"tools": ListTools()})
		case "tools/call":
			params, _ := request["params"].(map[string]interface{})
			toolName, _ := params["name"].(string)
			arguments, _ := params["arguments"].(map[string]interface{})
			result, err := HandleToolCall(toolName, arguments)
			if err != nil {
				s.writeError(id, -32602, err.Error())
			} else {
				resultJSON, _ := json.MarshalIndent(result, "", "  ")
				s.writeResult(id, map[string]interface{}{
					"content": []map[string]interface{}{
						{"type": "text", "text": string(resultJSON)},
					},
				})
			}
		default:
			s.writeError(id, -32601, fmt.Sprintf("Method not found: %s", method))
		}
	}
	return scanner.Err()
}

// RunStdioServer runs the MCP stdio JSON-RPC server on stdin/stdout.
func RunStdioServer() {
	cfg := config.DefaultSentinelConfig()
	server := NewServer(cfg)
	server.Run(os.Stdin, os.Stdout)
}

func (s *Server) writeResult(id interface{}, result interface{}) {
	resp := map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result}
	data, _ := json.Marshal(resp)
	fmt.Fprintln(s.writer, string(data))
}

func (s *Server) writeError(id interface{}, code int, message string) {
	resp := map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": code, "message": message}}
	data, _ := json.Marshal(resp)
	fmt.Fprintln(s.writer, string(data))
}
