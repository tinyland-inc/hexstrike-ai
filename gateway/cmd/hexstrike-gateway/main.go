// Package main is the entry point for the HexStrike gateway.
//
// The gateway wraps the F*-extracted MCP server in a Tailscale tsnet listener,
// providing identity-based authentication, policy enforcement, metering,
// credential brokering, and Prometheus metrics.
//
// In the K8s pod, it runs alongside an adapter sidecar (RemoteJuggler)
// that provides platform tools: identity management, credential resolution,
// Aperture metering, and GitHub integration.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tailscale.com/tsnet"

	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/aperture"
	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/credentials"
	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/health"
	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/metrics"
	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/policy"
	"github.com/tinyland-inc/hexstrike-ai/gateway/internal/proxy"
)

func main() {
	var (
		mcpBinary   = flag.String("mcp-binary", "hexstrike-mcp", "Path to the F*-extracted MCP server binary")
		policyPath  = flag.String("policy", "", "Path to compiled policy JSON file")
		listenAddr  = flag.String("listen", ":8080", "HTTP listen address (non-tsnet fallback)")
		tsHostname  = flag.String("ts-hostname", "hexstrike", "Tailscale hostname")
		metricsAddr = flag.String("metrics", ":9090", "Prometheus metrics listen address")
		useTsnet    = flag.Bool("tsnet", false, "Use tsnet for Tailscale-native listener")
		sopsFile    = flag.String("sops-file", "", "Path to SOPS-encrypted secrets file")
		setecURL    = flag.String("setec-url", "", "Setec server base URL")
		adapterURL  = flag.String("adapter-url", "", "Adapter sidecar MCP endpoint (for KDBX)")
		apertureURL = flag.String("aperture-url", "", "Aperture metering API base URL")
		tsStateDir  = flag.String("ts-state-dir", "", "Tailscale state directory (default: auto)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("hexstrike-gateway starting (mcp=%s, policy=%s)", *mcpBinary, *policyPath)

	// Resolve policy path from flag or environment
	polPath := *policyPath
	if polPath == "" {
		polPath = os.Getenv("HEXSTRIKE_POLICY_PATH")
	}

	// Load policy
	engine, err := policy.NewEngine(polPath)
	if err != nil {
		log.Printf("warning: policy load failed: %v (using default-allow)", err)
		engine = policy.DefaultEngine()
	}

	// Credential broker: env -> sops -> kdbx -> setec
	broker := credentials.NewBrokerWithConfig(credentials.BrokerConfig{
		SopsFilePath: *sopsFile,
		KDBXEndpoint: *adapterURL,
		SetecBaseURL: *setecURL,
	})

	// Aperture metering (async, non-blocking)
	metering := aperture.NewMeteringClient(*apertureURL)
	if *apertureURL != "" {
		log.Printf("aperture metering enabled: %s", *apertureURL)
	}

	// Start MCP subprocess manager with credential broker
	mcpProxy, err := proxy.NewMCPProxy(*mcpBinary)
	if err != nil {
		log.Fatalf("failed to start MCP proxy: %v", err)
	}
	mcpProxy.SetCredentialBroker(broker)
	defer mcpProxy.Stop()

	// Metrics
	metricsCollector := metrics.NewCollector()

	// Aperture circuit breaker (receives webhook signals)
	circuitBreaker := aperture.NewCircuitBreaker()

	// Build handler chain
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("GET /health", health.Handler(mcpProxy))

	// MCP endpoint — full middleware chain:
	//   policy -> circuit breaker -> metrics -> proxy
	mcpHandler := proxy.NewMCPHandler(mcpProxy)
	mcpHandler = metrics.Middleware(metricsCollector)(mcpHandler)
	mcpHandler = aperture.MeteringMiddleware(metering, circuitBreaker)(mcpHandler)
	mcpHandler = policy.Middleware(engine)(mcpHandler)
	mux.Handle("POST /mcp", mcpHandler)

	// Aperture webhook endpoint (receives rate-limit signals)
	mux.HandleFunc("POST /aperture/webhook", aperture.WebhookHandler(circuitBreaker))

	// Prometheus metrics endpoint
	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", metricsCollector.Handler())
		log.Printf("metrics listening on %s", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, metricsMux); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Listener: tsnet (Tailscale-native) or plain TCP
	var listener net.Listener

	var tsServer *tsnet.Server
	if *useTsnet {
		tsServer = &tsnet.Server{
			Hostname: *tsHostname,
		}
		if *tsStateDir != "" {
			tsServer.Dir = *tsStateDir
		}

		log.Printf("tsnet mode: starting as %s on tailnet...", *tsHostname)
		var err error
		listener, err = tsServer.Listen("tcp", ":80")
		if err != nil {
			log.Fatalf("tsnet listen failed: %v", err)
		}
		log.Printf("tsnet listening as %s.tailnet", *tsHostname)

		// Use tsnet-authenticated HTTP client for internal services
		tsHTTPClient := tsServer.HTTPClient()
		if *setecURL != "" {
			broker.SetSetecClient(tsHTTPClient)
			log.Printf("setec using tsnet-authenticated client")
		}
		metering.SetHTTPClient(tsHTTPClient)

		// Also start HTTPS listener for TLS-enabled clients
		go func() {
			tlsLn, err := tsServer.ListenTLS("tcp", ":443")
			if err != nil {
				log.Printf("tsnet TLS listen error: %v", err)
				return
			}
			tlsServer := &http.Server{
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}
			log.Printf("tsnet TLS listening on :443")
			if err := tlsServer.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				log.Printf("tsnet TLS server error: %v", err)
			}
		}()
	} else {
		server.Addr = *listenAddr
		var err error
		listener, err = net.Listen("tcp", *listenAddr)
		if err != nil {
			log.Fatalf("listen %s failed: %v", *listenAddr, err)
		}
		log.Printf("gateway listening on %s", *listenAddr)
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}

	if tsServer != nil {
		tsServer.Close()
	}

	mcpProxy.Stop()
	log.Println("gateway stopped")
}
