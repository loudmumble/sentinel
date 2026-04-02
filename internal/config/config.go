// Package config provides configuration types for Sentinel.
package config

import "os"

// getEnv returns the environment variable value or a default.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvWithFallbackEnv tries key first, then fallbackKey, then default.
func getEnvWithFallbackEnv(key, fallbackKey, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if v := os.Getenv(fallbackKey); v != "" {
		return v
	}
	return defaultVal
}

// OllamaConfig holds Ollama API configuration.
type OllamaConfig struct {
	BaseURL             string  `json:"base_url"`
	Model               string  `json:"model"`
	TriageModel         string  `json:"triage_model"`
	DeepModel           string  `json:"deep_model"`
	ReasoningModel      string  `json:"reasoning_model"`
	Temperature         float64 `json:"temperature"`
	Timeout             int     `json:"timeout"`
	MaxTokens           int     `json:"max_tokens"`
	TriageTimeout       int     `json:"triage_timeout"`
	DeepTimeout         int     `json:"deep_timeout"`
	ValidationTimeout   int     `json:"validation_timeout"`
	TriageMaxTokens     int     `json:"triage_max_tokens"`
	DeepMaxTokens       int     `json:"deep_max_tokens"`
	ValidationMaxTokens int     `json:"validation_max_tokens"`
}

// DefaultOllamaConfig returns OllamaConfig with environment-aware defaults.
func DefaultOllamaConfig() OllamaConfig {
	defaultModel := getEnv("SENTINEL_MODEL", "llama3.2")
	return OllamaConfig{
		BaseURL:             getEnv("OLLAMA_URL", "http://localhost:11434"),
		Model:               defaultModel,
		TriageModel:         getEnvWithFallbackEnv("SENTINEL_TRIAGE_MODEL", "SENTINEL_MODEL", defaultModel),
		DeepModel:           getEnvWithFallbackEnv("SENTINEL_DEEP_MODEL", "SENTINEL_MODEL", defaultModel),
		ReasoningModel:      getEnvWithFallbackEnv("SENTINEL_REASONING_MODEL", "SENTINEL_MODEL", defaultModel),
		Temperature:         0.1,
		Timeout:             120,
		MaxTokens:           4096,
		TriageTimeout:       45,
		DeepTimeout:         90,
		ValidationTimeout:   90,
		TriageMaxTokens:     512,
		DeepMaxTokens:       2048,
		ValidationMaxTokens: 1024,
	}
}

// EmbeddedModelConfig holds configuration for embedded GGUF model.
// Included for struct compatibility but unused in Go.
type EmbeddedModelConfig struct {
	ModelPath  string `json:"model_path"`
	NCtx       int    `json:"n_ctx"`
	NThreads   int    `json:"n_threads"`
	NGPULayers int    `json:"n_gpu_layers"`
	Verbose    bool   `json:"verbose"`
}

// DefaultEmbeddedModelConfig returns EmbeddedModelConfig with defaults.
func DefaultEmbeddedModelConfig() EmbeddedModelConfig {
	return EmbeddedModelConfig{
		ModelPath:  "",
		NCtx:       2048,
		NThreads:   0,
		NGPULayers: 0,
		Verbose:    false,
	}
}

// HybridLLMConfig configures the hybrid LLM backend.
type HybridLLMConfig struct {
	Backend  string              `json:"backend"` // "auto" | "embedded" | "ollama"
	Embedded EmbeddedModelConfig `json:"embedded"`
	Ollama   OllamaConfig        `json:"ollama"`
}

// DefaultHybridLLMConfig returns HybridLLMConfig with defaults.
func DefaultHybridLLMConfig() HybridLLMConfig {
	return HybridLLMConfig{
		Backend:  "auto",
		Embedded: DefaultEmbeddedModelConfig(),
		Ollama:   DefaultOllamaConfig(),
	}
}

// SidekickConfig configures the Sidekick knowledge-base output backend.
type SidekickConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	BaseURL       string `json:"base_url" yaml:"base_url"`
	EngagementID  string `json:"engagement_id" yaml:"engagement_id"`
	BatchSize     int    `json:"batch_size" yaml:"batch_size"`
	FlushInterval int    `json:"flush_interval_ms" yaml:"flush_interval_ms"`
}

// DefaultSidekickConfig returns SidekickConfig with sensible defaults.
func DefaultSidekickConfig() SidekickConfig {
	return SidekickConfig{
		Enabled:       false,
		BaseURL:       "http://localhost:3002",
		EngagementID:  "",
		BatchSize:     10,
		FlushInterval: 5000,
	}
}

// SentinelConfig is the top-level configuration.
type SentinelConfig struct {
	Probes         []string        `json:"probes"`
	WatchPaths     []string        `json:"watch_paths"`
	SyscallFilter  []string        `json:"syscall_filter"`
	OutputFormat   string          `json:"output_format"`
	AlertThreshold int             `json:"alert_threshold"`
	Ollama         OllamaConfig    `json:"ollama"`
	LLM            HybridLLMConfig `json:"llm"`
	Sidekick       SidekickConfig  `json:"sidekick"`
}

// DefaultSentinelConfig returns SentinelConfig with sensible defaults.
func DefaultSentinelConfig() SentinelConfig {
	return SentinelConfig{
		Probes:         []string{"process", "syscall", "file", "network"},
		WatchPaths:     []string{"/etc", "/usr/bin"},
		SyscallFilter:  []string{"execve", "connect", "open", "unlink"},
		OutputFormat:   "json",
		AlertThreshold: 75,
		Ollama:         DefaultOllamaConfig(),
		LLM:            DefaultHybridLLMConfig(),
		Sidekick:       DefaultSidekickConfig(),
	}
}
