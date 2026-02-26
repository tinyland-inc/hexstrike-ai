package proxy

import (
	"encoding/json"
	"testing"
)

func TestExtractToolName(t *testing.T) {
	tests := []struct {
		name     string
		params   string
		expected string
	}{
		{"valid name", `{"name":"port_scan","arguments":{}}`, "port_scan"},
		{"empty name", `{"name":"","arguments":{}}`, "unknown"},
		{"no name field", `{"arguments":{}}`, "unknown"},
		{"invalid json", `not json`, "unknown"},
		{"null", `null`, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractToolName(json.RawMessage(tt.params))
			if got != tt.expected {
				t.Errorf("ExtractToolName(%s) = %q, want %q", tt.params, got, tt.expected)
			}
		})
	}
}
