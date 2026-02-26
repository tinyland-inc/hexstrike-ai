package aperture

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// CircuitBreaker tracks rate limit signals from Aperture.
type CircuitBreaker struct {
	mu       sync.RWMutex
	tripped  map[string]bool // tool_name -> tripped
}

// NewCircuitBreaker creates a circuit breaker.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		tripped: make(map[string]bool),
	}
}

// IsTripped checks if a tool is currently rate-limited.
func (cb *CircuitBreaker) IsTripped(toolName string) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.tripped[toolName]
}

// Trip marks a tool as rate-limited.
func (cb *CircuitBreaker) Trip(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripped[toolName] = true
	log.Printf("circuit breaker tripped: %s", toolName)
}

// Reset clears the rate-limit on a tool.
func (cb *CircuitBreaker) Reset(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.tripped, toolName)
	log.Printf("circuit breaker reset: %s", toolName)
}

// WebhookEvent is an Aperture rate-limit signal.
type WebhookEvent struct {
	Type     string `json:"type"`
	ToolName string `json:"tool_name"`
	Action   string `json:"action"` // "trip" or "reset"
}

// WebhookHandler returns an HTTP handler for Aperture webhook events.
func WebhookHandler(cb *CircuitBreaker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var event WebhookEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		switch event.Action {
		case "trip":
			cb.Trip(event.ToolName)
		case "reset":
			cb.Reset(event.ToolName)
		default:
			log.Printf("unknown aperture action: %s", event.Action)
		}

		w.WriteHeader(http.StatusOK)
	}
}
