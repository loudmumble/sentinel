package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/loudmumble/sentinel/internal/config"
)

func TestExtractThinkingNoTags(t *testing.T) {
	content, thinking := ExtractThinking("Hello world")
	if content != "Hello world" {
		t.Errorf("expected content 'Hello world', got %q", content)
	}
	if thinking != "" {
		t.Errorf("expected empty thinking, got %q", thinking)
	}
}

func TestExtractThinkingWithTags(t *testing.T) {
	content, thinking := ExtractThinking("<think>reasoning here</think>actual response")
	if thinking != "reasoning here" {
		t.Errorf("expected thinking 'reasoning here', got %q", thinking)
	}
	if content != "actual response" {
		t.Errorf("expected content 'actual response', got %q", content)
	}
}

func TestExtractThinkingUnclosed(t *testing.T) {
	content, thinking := ExtractThinking("<think>unclosed thinking")
	if thinking != "unclosed thinking" {
		t.Errorf("expected thinking 'unclosed thinking', got %q", thinking)
	}
	if content != "" {
		t.Errorf("expected empty content, got %q", content)
	}
}

func TestParseJSONValid(t *testing.T) {
	result := ParseJSON(`{"key": "value", "num": 42}`)
	if result["key"] != "value" {
		t.Errorf("expected key 'value', got %v", result["key"])
	}
	if result["num"].(float64) != 42 {
		t.Errorf("expected num 42, got %v", result["num"])
	}
}

func TestParseJSONWithCodeFence(t *testing.T) {
	input := "```json\n{\"key\": \"value\"}\n```"
	result := ParseJSON(input)
	if result["key"] != "value" {
		t.Errorf("expected key 'value', got %v", result["key"])
	}
}

func TestParseJSONEmbedded(t *testing.T) {
	input := "Here is the JSON: {\"threat\": \"high\"} and more text"
	result := ParseJSON(input)
	if result["threat"] != "high" {
		t.Errorf("expected threat 'high', got %v", result["threat"])
	}
}

func TestParseJSONInvalid(t *testing.T) {
	result := ParseJSON("not json at all")
	if _, ok := result["raw"]; !ok {
		t.Error("expected 'raw' key in result for invalid JSON")
	}
}

func TestNewHybridLLMClientNoOllama(t *testing.T) {
	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = "http://localhost:99999" // unreachable
	client := NewHybridLLMClient(cfg)
	if client.IsAvailable() {
		t.Error("expected client to not be available with unreachable Ollama")
	}
	if client.ActiveBackend() != "none" {
		t.Errorf("expected backend 'none', got %q", client.ActiveBackend())
	}
	client.Close()
}

func TestClientClose(t *testing.T) {
	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = "http://localhost:99999"
	client := NewHybridLLMClient(cfg)
	client.Close()
	if client.ActiveBackend() != "none" {
		t.Errorf("expected backend 'none' after close, got %q", client.ActiveBackend())
	}
}

func TestGenerateNoBackend(t *testing.T) {
	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = "http://localhost:99999"
	client := NewHybridLLMClient(cfg)
	defer client.Close()
	_, err := client.Generate("test", "")
	if err == nil {
		t.Error("expected error when no backend available")
	}
}

func TestListModelsNoBackend(t *testing.T) {
	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = "http://localhost:99999"
	client := NewHybridLLMClient(cfg)
	defer client.Close()
	models := client.ListModels()
	if len(models) != 0 {
		t.Errorf("expected empty models list, got %d", len(models))
	}
}

func TestBenchmarkNoBackend(t *testing.T) {
	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = "http://localhost:99999"
	client := NewHybridLLMClient(cfg)
	defer client.Close()
	result := client.Benchmark("test-model", "hello", 16, 5)
	if result["ok"] != false {
		t.Error("expected ok=false for unreachable backend")
	}
}

func TestGenerateWithMockOllama(t *testing.T) {
	// Create a mock Ollama server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []interface{}{}})
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    map[string]interface{}{"content": "Test response from mock"},
			"eval_count": 10,
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = server.URL
	client := NewHybridLLMClient(cfg)
	defer client.Close()

	if !client.IsAvailable() {
		t.Fatal("expected client to be available with mock server")
	}
	if client.ActiveBackend() != "ollama" {
		t.Errorf("expected backend 'ollama', got %q", client.ActiveBackend())
	}

	resp, err := client.Generate("test prompt", "system prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "Test response from mock" {
		t.Errorf("expected 'Test response from mock', got %q", resp.Content)
	}
	if resp.TokensUsed != 10 {
		t.Errorf("expected 10 tokens, got %d", resp.TokensUsed)
	}
	if resp.Backend != "ollama" {
		t.Errorf("expected backend 'ollama', got %q", resp.Backend)
	}
}

func TestGenerateJSONWithMock(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []interface{}{}})
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    map[string]interface{}{"content": `{"threat": "high", "score": 90}`},
			"eval_count": 5,
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = server.URL
	client := NewHybridLLMClient(cfg)
	defer client.Close()

	result, err := client.GenerateJSON("analyze this", "be concise")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["threat"] != "high" {
		t.Errorf("expected threat 'high', got %v", result["threat"])
	}
}

func TestReasonWithMock(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []interface{}{}})
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    map[string]interface{}{"content": "<think>deep thought</think>conclusion"},
			"eval_count": 20,
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := config.DefaultHybridLLMConfig()
	cfg.Ollama.BaseURL = server.URL
	client := NewHybridLLMClient(cfg)
	defer client.Close()

	resp, err := client.Reason("complex question", "think deeply")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Thinking != "deep thought" {
		t.Errorf("expected thinking 'deep thought', got %q", resp.Thinking)
	}
	if resp.Content != "conclusion" {
		t.Errorf("expected content 'conclusion', got %q", resp.Content)
	}
}
