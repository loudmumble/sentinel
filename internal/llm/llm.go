// Package llm provides the hybrid LLM client for Sentinel.
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
)

// LLMResponse holds the result of an LLM generation.
type LLMResponse struct {
	Content    string `json:"content"`
	Model      string `json:"model"`
	TokensUsed int    `json:"tokens_used"`
	Thinking   string `json:"thinking"`
	Backend    string `json:"backend"`
}

// ExtractThinking parses <think>...</think> tags from content.
func ExtractThinking(content string) (string, string) {
	if !strings.Contains(content, "<think>") {
		return content, ""
	}
	thinkStart := strings.Index(content, "<think>") + len("<think>")
	if strings.Contains(content, "</think>") {
		thinkEnd := strings.Index(content, "</think>")
		thinking := strings.TrimSpace(content[thinkStart:thinkEnd])
		content = strings.TrimSpace(content[thinkEnd+len("</think>"):])
		return content, thinking
	}
	thinking := strings.TrimSpace(content[thinkStart:])
	return "", thinking
}

// Option is a functional option for Generate calls.
type Option func(*generateOpts)

type generateOpts struct {
	model     string
	timeout   int
	maxTokens int
}

// WithModel sets the model for a generate call.
func WithModel(model string) Option {
	return func(o *generateOpts) { o.model = model }
}

// WithTimeout sets the timeout for a generate call.
func WithTimeout(timeout int) Option {
	return func(o *generateOpts) { o.timeout = timeout }
}

// WithMaxTokens sets the max tokens for a generate call.
func WithMaxTokens(maxTokens int) Option {
	return func(o *generateOpts) { o.maxTokens = maxTokens }
}

// HybridLLMClient provides LLM access via Ollama HTTP backend.
type HybridLLMClient struct {
	Config        config.HybridLLMConfig
	httpClient    *http.Client
	activeBackend string
}

// NewHybridLLMClient creates and initializes an LLM client.
func NewHybridLLMClient(cfg config.HybridLLMConfig) *HybridLLMClient {
	c := &HybridLLMClient{
		Config:        cfg,
		activeBackend: "none",
	}
	c.initBackend()
	return c
}

func (c *HybridLLMClient) initBackend() {
	backend := c.Config.Backend
	if backend == "auto" || backend == "ollama" {
		if c.tryInitOllama() {
			return
		}
		if backend == "ollama" {
			log.Println("WARNING: Ollama backend requested but failed to initialize")
		}
	}
	// In Go rewrite, embedded GGUF is not supported
	if backend == "embedded" {
		log.Println("WARNING: Embedded backend not supported in Go build")
	}
}

func (c *HybridLLMClient) tryInitOllama() bool {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.Config.Ollama.BaseURL + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		c.httpClient = &http.Client{
			Timeout: time.Duration(c.Config.Ollama.Timeout) * time.Second,
		}
		c.activeBackend = "ollama"
		return true
	}
	return false
}

// Generate sends a prompt to the LLM and returns the response.
func (c *HybridLLMClient) Generate(prompt, system string, opts ...Option) (*LLMResponse, error) {
	if c.activeBackend != "ollama" {
		return nil, fmt.Errorf("no LLM backend available (ensure Ollama is running at %s)", c.Config.Ollama.BaseURL)
	}
	o := &generateOpts{
		model:     c.Config.Ollama.Model,
		timeout:   c.Config.Ollama.Timeout,
		maxTokens: c.Config.Ollama.MaxTokens,
	}
	for _, opt := range opts {
		opt(o)
	}
	messages := []map[string]string{}
	if system != "" {
		messages = append(messages, map[string]string{"role": "system", "content": system})
	}
	messages = append(messages, map[string]string{"role": "user", "content": prompt})

	body := map[string]interface{}{
		"model":    o.model,
		"messages": messages,
		"stream":   false,
		"options": map[string]interface{}{
			"temperature": c.Config.Ollama.Temperature,
			"num_predict": o.maxTokens,
		},
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{Timeout: time.Duration(o.timeout) * time.Second}
	resp, err := client.Post(c.Config.Ollama.BaseURL+"/api/chat", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	rawContent := ""
	if msg, ok := data["message"].(map[string]interface{}); ok {
		if content, ok := msg["content"].(string); ok {
			rawContent = content
		}
	}

	content, thinking := ExtractThinking(rawContent)
	tokensUsed := 0
	if evalCount, ok := data["eval_count"].(float64); ok {
		tokensUsed = int(evalCount)
	}

	return &LLMResponse{
		Content:    content,
		Model:      o.model,
		TokensUsed: tokensUsed,
		Thinking:   thinking,
		Backend:    "ollama",
	}, nil
}

// GenerateJSON sends a prompt and parses the JSON response.
func (c *HybridLLMClient) GenerateJSON(prompt, system string, opts ...Option) (map[string]interface{}, error) {
	resp, err := c.Generate(prompt, system, opts...)
	if err != nil {
		return nil, err
	}
	return ParseJSON(resp.Content), nil
}

// Reason uses the reasoning model for complex analysis.
func (c *HybridLLMClient) Reason(prompt, system string) (*LLMResponse, error) {
	return c.Generate(prompt, system, WithModel(c.Config.Ollama.ReasoningModel))
}

// ListModels returns available models from the Ollama backend.
func (c *HybridLLMClient) ListModels() []map[string]interface{} {
	models := []map[string]interface{}{}
	if c.httpClient == nil {
		return models
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.Config.Ollama.BaseURL + "/api/tags")
	if err != nil {
		return models
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return models
	}
	if modelList, ok := data["models"].([]interface{}); ok {
		for _, m := range modelList {
			if model, ok := m.(map[string]interface{}); ok {
				model["backend"] = "ollama"
				models = append(models, model)
			}
		}
	}
	return models
}

// Benchmark measures LLM performance.
func (c *HybridLLMClient) Benchmark(model, prompt string, maxTokens, timeout int) map[string]interface{} {
	if prompt == "" {
		prompt = "Reply OK"
	}
	if maxTokens == 0 {
		maxTokens = 16
	}
	if timeout == 0 {
		timeout = 60
	}
	start := time.Now()
	resp, err := c.Generate(prompt, "", WithModel(model), WithTimeout(timeout), WithMaxTokens(maxTokens))
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return map[string]interface{}{
			"model": model,
			"ok":    false,
			"time":  round1(elapsed),
			"error": truncate(err.Error(), 100),
		}
	}
	tps := 0.0
	if elapsed > 0 {
		tps = float64(resp.TokensUsed) / elapsed
	}
	return map[string]interface{}{
		"model":       model,
		"backend":     resp.Backend,
		"ok":          true,
		"time":        round1(elapsed),
		"tokens":      resp.TokensUsed,
		"tok_per_sec": round1(tps),
		"response":    truncate(resp.Content, 100),
	}
}

// IsAvailable returns true if an LLM backend is connected.
func (c *HybridLLMClient) IsAvailable() bool {
	return c.activeBackend != "none"
}

// ActiveBackend returns the name of the active backend.
func (c *HybridLLMClient) ActiveBackend() string {
	return c.activeBackend
}

// Close releases resources.
func (c *HybridLLMClient) Close() {
	c.httpClient = nil
	c.activeBackend = "none"
}

// ParseJSON extracts JSON from LLM text, stripping markdown fences.
func ParseJSON(text string) map[string]interface{} {
	text = strings.TrimSpace(text)
	// Strip markdown code fences
	if strings.HasPrefix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) > 1 {
			end := len(lines)
			if strings.TrimSpace(lines[end-1]) == "```" {
				end = end - 1
			}
			text = strings.Join(lines[1:end], "\n")
		}
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err == nil {
		return result
	}
	// Try to find JSON object in text
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}") + 1
	if start != -1 && end > start {
		if err := json.Unmarshal([]byte(text[start:end]), &result); err == nil {
			return result
		}
	}
	return map[string]interface{}{"raw": text}
}

func round1(v float64) float64 {
	return float64(int(v*10)) / 10
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
