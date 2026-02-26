// Package health provides the gateway health check endpoint.
package health

import (
	"encoding/json"
	"net/http"

	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/proxy"
)

// Status is the health check response.
type Status struct {
	Status   string `json:"status"`
	Gateway  string `json:"gateway"`
	MCP      string `json:"mcp"`
	Version  string `json:"version"`
}

// Handler returns an HTTP handler for health checks.
func Handler(mcpProxy *proxy.MCPProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mcpStatus := "down"
		if mcpProxy.Alive() {
			mcpStatus = "up"
		}

		status := "ok"
		if mcpStatus != "up" {
			status = "degraded"
		}

		resp := Status{
			Status:  status,
			Gateway: "up",
			MCP:     mcpStatus,
			Version: "0.2.0",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
