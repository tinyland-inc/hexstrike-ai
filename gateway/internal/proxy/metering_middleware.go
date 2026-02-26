package proxy

import (
	"encoding/json"
	"time"
)

// MeterEvent captures per-tool-call metering data for Aperture and audit.
type MeterEvent struct {
	ToolName    string        `json:"tool_name"`
	Caller      string        `json:"caller"`
	BytesIn     int           `json:"bytes_in"`
	BytesOut    int           `json:"bytes_out"`
	Duration    time.Duration `json:"duration_ns"`
	Error       bool          `json:"error"`
	Timestamp   time.Time     `json:"timestamp"`
	PolicyDecision string     `json:"policy_decision"`
}

// ExtractToolName attempts to extract the tool name from a tools/call params payload.
func ExtractToolName(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "unknown"
	}
	if p.Name == "" {
		return "unknown"
	}
	return p.Name
}
