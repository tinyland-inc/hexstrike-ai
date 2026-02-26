// Package credentials implements additive credential resolution.
//
// Chain: env -> sops -> kdbx -> setec
//
// The chain mirrors RemoteJuggler's juggler_resolve_composite tool.
// In the K8s pod, Setec is accessed via the adapter sidecar which
// authenticates with tsnet identity. KDBX is accessed via the
// juggler_keys_resolve tool on the sidecar.
package credentials

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Broker resolves credentials through an additive chain.
type Broker struct {
	resolvers []Resolver
}

// Resolver is a single credential source.
type Resolver interface {
	Name() string
	Resolve(key string) (string, error)
}

// BrokerConfig configures the credential resolution chain.
type BrokerConfig struct {
	SopsFilePath string // Path to SOPS-encrypted secrets file
	KDBXEndpoint string // URL to KeePassXC bridge (adapter sidecar)
	SetecBaseURL string // URL to Setec server
}

// NewBroker creates a credential broker with the default resolution chain.
func NewBroker() *Broker {
	return NewBrokerWithConfig(BrokerConfig{})
}

// NewBrokerWithConfig creates a credential broker with explicit config.
// Resolution order: env -> sops -> kdbx -> setec
func NewBrokerWithConfig(cfg BrokerConfig) *Broker {
	resolvers := []Resolver{
		&EnvResolver{},
		&SopsResolver{FilePath: cfg.SopsFilePath},
	}

	if cfg.KDBXEndpoint != "" {
		resolvers = append(resolvers, NewKDBXResolver(cfg.KDBXEndpoint))
	}

	if cfg.SetecBaseURL != "" {
		resolvers = append(resolvers, NewSetecResolver(cfg.SetecBaseURL))
	}

	return &Broker{resolvers: resolvers}
}

// SetSetecClient replaces the Setec resolver's HTTP client (e.g., with a
// tsnet-authenticated client for Tailscale-native identity).
func (b *Broker) SetSetecClient(client *http.Client) {
	for _, r := range b.resolvers {
		if sr, ok := r.(*SetecResolver); ok {
			sr.HTTPClient = client
		}
	}
}

// Resolve tries each resolver in order until one succeeds.
func (b *Broker) Resolve(key string) (string, error) {
	for _, r := range b.resolvers {
		val, err := r.Resolve(key)
		if err == nil && val != "" {
			log.Printf("credential %q resolved via %s", key, r.Name())
			return val, nil
		}
	}
	return "", fmt.Errorf("credential %q not found in any source", key)
}

// EnvResolver reads credentials from environment variables.
type EnvResolver struct{}

func (r *EnvResolver) Name() string { return "env" }

func (r *EnvResolver) Resolve(key string) (string, error) {
	envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	val := os.Getenv(envKey)
	if val == "" {
		return "", fmt.Errorf("env %s not set", envKey)
	}
	return val, nil
}

// SopsResolver decrypts credentials from SOPS-encrypted files.
type SopsResolver struct {
	FilePath string
}

func (r *SopsResolver) Name() string { return "sops" }

func (r *SopsResolver) Resolve(key string) (string, error) {
	if r.FilePath == "" {
		return "", fmt.Errorf("sops file path not configured")
	}

	cmd := exec.Command("sops", "--decrypt", "--extract", fmt.Sprintf(`["%s"]`, key), r.FilePath)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("sops decrypt: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

// KDBXResolver resolves credentials via KeePassXC through the adapter sidecar.
// Maps to RemoteJuggler's juggler_keys_resolve tool.
type KDBXResolver struct {
	Endpoint string
}

// NewKDBXResolver creates a KDBX resolver pointing at the adapter sidecar.
func NewKDBXResolver(endpoint string) *KDBXResolver {
	return &KDBXResolver{Endpoint: endpoint}
}

func (r *KDBXResolver) Name() string { return "kdbx" }

func (r *KDBXResolver) Resolve(key string) (string, error) {
	if r.Endpoint == "" {
		return "", fmt.Errorf("kdbx endpoint not configured")
	}

	// Call adapter sidecar's juggler_keys_resolve via MCP
	// The sidecar translates this to a KeePassXC lookup
	cmd := exec.Command("curl", "-sf",
		"-H", "Content-Type: application/json",
		"-d", fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"juggler_keys_resolve","arguments":{"query":"%s"}}}`, key),
		r.Endpoint,
	)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("kdbx resolve: %w", err)
	}

	// Extract value from JSON-RPC response
	result := strings.TrimSpace(string(out))
	if result == "" || strings.Contains(result, `"error"`) {
		return "", fmt.Errorf("kdbx: key %q not found", key)
	}

	return result, nil
}
