package policy

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/proxy"
)

// Middleware returns HTTP middleware that enforces policy on MCP requests.
func Middleware(engine *Engine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read and buffer the body so we can inspect it
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "read body failed", http.StatusBadRequest)
				return
			}

			var req proxy.MCPRequest
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			// Only enforce policy on tools/call
			if req.Method == "tools/call" {
				toolName := proxy.ExtractToolName(req.Params)
				caller := callerFromRequest(r)

				decision := engine.Evaluate(caller, toolName)
				if !decision.Allowed {
					log.Printf("policy denied: caller=%s tool=%s reason=%s", caller, toolName, decision.Reason)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(proxy.MCPResponse{
						Error: "policy denied: " + decision.Reason,
					})
					return
				}

				// Pass tool name downstream for metering/audit
				r.Header.Set("X-HexStrike-Tool", toolName)
			}

			// Re-wrap body for downstream handler
			r.Body = io.NopCloser(io.NopCloser(
				&bytesReader{data: body, pos: 0},
			))

			next.ServeHTTP(w, r)
		})
	}
}

// callerFromRequest extracts caller identity from the request.
// Uses Tailscale identity header if available, falls back to remote addr.
func callerFromRequest(r *http.Request) string {
	// Tailscale whois identity (set by tsnet)
	if who := r.Header.Get("Tailscale-User-Login"); who != "" {
		return who
	}
	return r.RemoteAddr
}

// bytesReader is a simple io.Reader over a byte slice.
type bytesReader struct {
	data []byte
	pos  int
}

func (b *bytesReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
