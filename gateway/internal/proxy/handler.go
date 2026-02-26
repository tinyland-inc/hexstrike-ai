package proxy

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

// MCPRequest represents an incoming MCP tool call request via HTTP.
type MCPRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// MCPResponse wraps the JSON-RPC result for HTTP transport.
type MCPResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// NewMCPHandler returns an http.Handler that proxies MCP requests.
func NewMCPHandler(proxy *MCPProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}

		var req MCPRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Method == "" {
			http.Error(w, "method is required", http.StatusBadRequest)
			return
		}

		result, err := proxy.SendRequest(req.Method, req.Params)
		if err != nil {
			log.Printf("mcp error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(MCPResponse{Error: err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MCPResponse{Result: result})
	})
}
