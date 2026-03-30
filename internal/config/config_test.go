package config

import (
	"os"
	"testing"
)

func TestDefaultProbes(t *testing.T) {
	c := DefaultSentinelConfig()
	expected := []string{"process", "syscall", "file", "network"}
	if len(c.Probes) != len(expected) {
		t.Fatalf("expected %d probes, got %d", len(expected), len(c.Probes))
	}
	for i, p := range expected {
		if c.Probes[i] != p {
			t.Errorf("probe[%d] = %q, want %q", i, c.Probes[i], p)
		}
	}
}

func TestDefaultWatchPaths(t *testing.T) {
	c := DefaultSentinelConfig()
	found := map[string]bool{}
	for _, p := range c.WatchPaths {
		found[p] = true
	}
	if !found["/etc"] {
		t.Error("expected /etc in watch_paths")
	}
	if !found["/usr/bin"] {
		t.Error("expected /usr/bin in watch_paths")
	}
}

func TestDefaultSyscallFilter(t *testing.T) {
	c := DefaultSentinelConfig()
	found := map[string]bool{}
	for _, s := range c.SyscallFilter {
		found[s] = true
	}
	if !found["execve"] {
		t.Error("expected execve in syscall_filter")
	}
	if !found["connect"] {
		t.Error("expected connect in syscall_filter")
	}
}

func TestOutputFormatDefault(t *testing.T) {
	c := DefaultSentinelConfig()
	if c.OutputFormat != "json" {
		t.Errorf("expected output_format 'json', got %q", c.OutputFormat)
	}
}

func TestAlertThreshold(t *testing.T) {
	c := DefaultSentinelConfig()
	if c.AlertThreshold != 75 {
		t.Errorf("expected alert_threshold 75, got %d", c.AlertThreshold)
	}
}

func TestOllamaConfigDefaults(t *testing.T) {
	c := DefaultSentinelConfig()
	if c.Ollama.BaseURL != "http://localhost:11434" {
		t.Errorf("expected base_url 'http://localhost:11434', got %q", c.Ollama.BaseURL)
	}
	if c.Ollama.Temperature != 0.1 {
		t.Errorf("expected temperature 0.1, got %f", c.Ollama.Temperature)
	}
	if c.Ollama.Timeout != 120 {
		t.Errorf("expected timeout 120, got %d", c.Ollama.Timeout)
	}
	if c.Ollama.MaxTokens != 4096 {
		t.Errorf("expected max_tokens 4096, got %d", c.Ollama.MaxTokens)
	}
	if c.Ollama.TriageTimeout != 45 {
		t.Errorf("expected triage_timeout 45, got %d", c.Ollama.TriageTimeout)
	}
	if c.Ollama.DeepTimeout != 90 {
		t.Errorf("expected deep_timeout 90, got %d", c.Ollama.DeepTimeout)
	}
}

func TestCustomConfig(t *testing.T) {
	c := DefaultSentinelConfig()
	c.Probes = []string{"process"}
	c.WatchPaths = []string{"/tmp"}
	c.AlertThreshold = 50
	if len(c.Probes) != 1 || c.Probes[0] != "process" {
		t.Errorf("expected probes ['process'], got %v", c.Probes)
	}
	if len(c.WatchPaths) != 1 || c.WatchPaths[0] != "/tmp" {
		t.Errorf("expected watch_paths ['/tmp'], got %v", c.WatchPaths)
	}
	if c.AlertThreshold != 50 {
		t.Errorf("expected alert_threshold 50, got %d", c.AlertThreshold)
	}
}

func TestOllamaEnvOverride(t *testing.T) {
	os.Setenv("OLLAMA_URL", "http://custom:11434")
	os.Setenv("SENTINEL_MODEL", "custom-model")
	defer func() {
		os.Unsetenv("OLLAMA_URL")
		os.Unsetenv("SENTINEL_MODEL")
	}()
	c := DefaultOllamaConfig()
	if c.BaseURL != "http://custom:11434" {
		t.Errorf("expected base_url from env, got %q", c.BaseURL)
	}
	if c.Model != "custom-model" {
		t.Errorf("expected model from env, got %q", c.Model)
	}
}

func TestHybridLLMConfigDefaults(t *testing.T) {
	c := DefaultHybridLLMConfig()
	if c.Backend != "auto" {
		t.Errorf("expected backend 'auto', got %q", c.Backend)
	}
	if c.Embedded.NCtx != 2048 {
		t.Errorf("expected n_ctx 2048, got %d", c.Embedded.NCtx)
	}
}

func TestEmbeddedModelConfigDefaults(t *testing.T) {
	c := DefaultEmbeddedModelConfig()
	if c.ModelPath != "" {
		t.Errorf("expected empty model_path, got %q", c.ModelPath)
	}
	if c.NCtx != 2048 {
		t.Errorf("expected n_ctx 2048, got %d", c.NCtx)
	}
	if c.NThreads != 0 {
		t.Errorf("expected n_threads 0, got %d", c.NThreads)
	}
	if c.NGPULayers != 0 {
		t.Errorf("expected n_gpu_layers 0, got %d", c.NGPULayers)
	}
	if c.Verbose != false {
		t.Error("expected verbose false")
	}
}
