// Package credentials provides Setec secret management integration.
// Setec uses Tailscale identity for authentication — no separate credentials needed.
package credentials

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SetecResolver fetches secrets from a Setec server using tsnet identity.
type SetecResolver struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewSetecResolver creates a Setec resolver with a default HTTP client.
func NewSetecResolver(baseURL string) *SetecResolver {
	return NewSetecResolverWithClient(baseURL, nil)
}

// NewSetecResolverWithClient creates a Setec resolver with a custom HTTP client.
// Pass a tsnet-authenticated client for production use.
func NewSetecResolverWithClient(baseURL string, client *http.Client) *SetecResolver {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	return &SetecResolver{
		BaseURL:    baseURL,
		HTTPClient: client,
	}
}

func (r *SetecResolver) Name() string { return "setec" }

func (r *SetecResolver) Resolve(key string) (string, error) {
	if r.BaseURL == "" {
		return "", fmt.Errorf("setec base URL not configured")
	}

	url := fmt.Sprintf("%s/api/v1/secret/%s", r.BaseURL, key)
	resp, err := r.HTTPClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("setec request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("setec %s: %d", key, resp.StatusCode)
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("setec decode: %w", err)
	}

	return result.Value, nil
}
