// Package aperture integrates with Tailscale Aperture for token metering
// and circuit breaking.
package aperture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// MeteringClient posts tool-call metrics to the Aperture metering API.
type MeteringClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewMeteringClient creates an Aperture metering client.
func NewMeteringClient(baseURL string) *MeteringClient {
	return &MeteringClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// SetHTTPClient replaces the default HTTP client (e.g., with a
// tsnet-authenticated client for Tailscale-native identity).
func (c *MeteringClient) SetHTTPClient(client *http.Client) {
	if client != nil {
		c.HTTPClient = client
	}
}

// UsageEvent represents a metering event for Aperture.
type UsageEvent struct {
	Caller    string    `json:"caller"`
	ToolName  string    `json:"tool_name"`
	Tokens    int       `json:"tokens"`
	Duration  float64   `json:"duration_seconds"`
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
}

// RecordUsage posts a usage event to Aperture.
func (c *MeteringClient) RecordUsage(event UsageEvent) error {
	if c.BaseURL == "" {
		return nil // metering disabled
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	resp, err := c.HTTPClient.Post(
		c.BaseURL+"/api/v1/usage",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return fmt.Errorf("post usage: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("aperture metering: %d", resp.StatusCode)
	}

	return nil
}

// RecordAsync records usage in the background without blocking.
func (c *MeteringClient) RecordAsync(event UsageEvent) {
	go func() {
		if err := c.RecordUsage(event); err != nil {
			log.Printf("aperture metering error: %v", err)
		}
	}()
}

// MeteringMiddleware returns HTTP middleware that:
// 1. Checks circuit breaker before allowing tool calls
// 2. Records usage to Aperture after tool calls complete
func MeteringMiddleware(mc *MeteringClient, cb *CircuitBreaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract tool name from request context (set by policy middleware)
			toolName := r.Header.Get("X-HexStrike-Tool")

			// Check circuit breaker
			if toolName != "" && cb.IsTripped(toolName) {
				log.Printf("circuit breaker open: %s", toolName)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintf(w, `{"error":"rate limited: %s"}`, toolName)
				return
			}

			start := time.Now()
			// Wrap response writer to capture status
			rw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(rw, r)

			// Record usage async
			if toolName != "" {
				caller := r.Header.Get("Tailscale-User-Login")
				if caller == "" {
					caller = r.RemoteAddr
				}
				mc.RecordAsync(UsageEvent{
					Caller:    caller,
					ToolName:  toolName,
					Duration:  time.Since(start).Seconds(),
					Success:   rw.status < 400,
					Timestamp: start,
				})
			}
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
