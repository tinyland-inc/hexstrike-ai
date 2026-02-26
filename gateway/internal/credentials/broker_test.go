package credentials

import (
	"os"
	"testing"
)

func TestEnvResolver(t *testing.T) {
	r := &EnvResolver{}

	os.Setenv("TEST_API_KEY", "secret123")
	defer os.Unsetenv("TEST_API_KEY")

	val, err := r.Resolve("test.api.key")
	if err != nil {
		t.Fatalf("should resolve: %v", err)
	}
	if val != "secret123" {
		t.Fatalf("got %q, want %q", val, "secret123")
	}
}

func TestEnvResolverMissing(t *testing.T) {
	r := &EnvResolver{}

	_, err := r.Resolve("nonexistent.key")
	if err == nil {
		t.Fatal("should error on missing env var")
	}
}

func TestBrokerChain(t *testing.T) {
	os.Setenv("MY_SECRET", "from-env")
	defer os.Unsetenv("MY_SECRET")

	b := NewBroker()
	val, err := b.Resolve("my.secret")
	if err != nil {
		t.Fatalf("should resolve via env: %v", err)
	}
	if val != "from-env" {
		t.Fatalf("got %q, want %q", val, "from-env")
	}
}

func TestBrokerNotFound(t *testing.T) {
	b := NewBroker()
	_, err := b.Resolve("totally.missing.key")
	if err == nil {
		t.Fatal("should error when no resolver finds the key")
	}
}

func TestBrokerWithConfig(t *testing.T) {
	os.Setenv("CONFIGURED_KEY", "via-config")
	defer os.Unsetenv("CONFIGURED_KEY")

	b := NewBrokerWithConfig(BrokerConfig{
		SopsFilePath: "/nonexistent/sops.yaml",
		SetecBaseURL: "http://localhost:9999",
	})

	// Should still resolve from env first
	val, err := b.Resolve("configured.key")
	if err != nil {
		t.Fatalf("should resolve via env: %v", err)
	}
	if val != "via-config" {
		t.Fatalf("got %q, want %q", val, "via-config")
	}
}

func TestKDBXResolverNoEndpoint(t *testing.T) {
	r := NewKDBXResolver("")
	_, err := r.Resolve("some.key")
	if err == nil {
		t.Fatal("should error with empty endpoint")
	}
}
