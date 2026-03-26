package mcp

import (
	"encoding/json"
	"testing"
)

func TestListToolsCount(t *testing.T) {
	tools := ListTools()
	if len(tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(tools))
	}
}

func TestListToolsNames(t *testing.T) {
	tools := ListTools()
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"monitor", "trace", "watch", "analyze"} {
		if !names[expected] {
			t.Errorf("expected tool %q in list", expected)
		}
	}
}

func TestListToolsHaveSchemas(t *testing.T) {
	tools := ListTools()
	for _, tool := range tools {
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil schema", tool.Name)
		}
		if _, ok := tool.InputSchema["type"]; !ok {
			t.Errorf("tool %q schema missing 'type'", tool.Name)
		}
		if _, ok := tool.InputSchema["properties"]; !ok {
			t.Errorf("tool %q schema missing 'properties'", tool.Name)
		}
	}
}

func TestToolSchemasSerializable(t *testing.T) {
	tools := ListTools()
	for _, tool := range tools {
		data, err := json.Marshal(tool)
		if err != nil {
			t.Errorf("failed to marshal tool %q: %v", tool.Name, err)
		}
		if len(data) == 0 {
			t.Errorf("empty JSON for tool %q", tool.Name)
		}
	}
}

func TestTraceToolRequiresPID(t *testing.T) {
	tools := ListTools()
	for _, tool := range tools {
		if tool.Name == "trace" {
			required, ok := tool.InputSchema["required"].([]string)
			if !ok {
				t.Fatal("trace tool missing required field")
			}
			found := false
			for _, r := range required {
				if r == "pid" {
					found = true
				}
			}
			if !found {
				t.Error("trace tool should require 'pid'")
			}
		}
	}
}

func TestWatchToolRequiresPaths(t *testing.T) {
	tools := ListTools()
	for _, tool := range tools {
		if tool.Name == "watch" {
			required, ok := tool.InputSchema["required"].([]string)
			if !ok {
				t.Fatal("watch tool missing required field")
			}
			found := false
			for _, r := range required {
				if r == "paths" {
					found = true
				}
			}
			if !found {
				t.Error("watch tool should require 'paths'")
			}
		}
	}
}

func TestAnalyzeToolRequiresEvent(t *testing.T) {
	tools := ListTools()
	for _, tool := range tools {
		if tool.Name == "analyze" {
			required, ok := tool.InputSchema["required"].([]string)
			if !ok {
				t.Fatal("analyze tool missing required field")
			}
			found := false
			for _, r := range required {
				if r == "event" {
					found = true
				}
			}
			if !found {
				t.Error("analyze tool should require 'event'")
			}
		}
	}
}

func TestHandleToolCallUnknown(t *testing.T) {
	_, err := HandleToolCall("nonexistent", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown tool")
	}
}

func TestMonitorToolDescription(t *testing.T) {
	tools := ListTools()
	for _, tool := range tools {
		if tool.Name == "monitor" {
			if tool.Description == "" {
				t.Error("monitor tool has empty description")
			}
		}
	}
}

func TestToolCallRouting(t *testing.T) {
	// Test that known tool names don't return "unknown tool" error
	for _, name := range []string{"monitor", "trace", "watch", "analyze"} {
		_, err := HandleToolCall(name, map[string]interface{}{
			"pid":              float64(1),
			"paths":            []interface{}{"/tmp"},
			"event":            map[string]interface{}{"type": "test"},
			"duration_seconds": float64(0.1),
		})
		// May fail due to LLM/probes but should NOT return "unknown tool"
		if err != nil && err.Error() == "unknown tool: "+name {
			t.Errorf("tool %q should be routed, got unknown tool error", name)
		}
	}
}
