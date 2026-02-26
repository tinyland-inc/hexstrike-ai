// Package metrics provides Prometheus instrumentation for the gateway.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector holds all Prometheus metrics for the gateway.
type Collector struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	policyDecisions *prometheus.CounterVec
	toolErrors      *prometheus.CounterVec
	registry        *prometheus.Registry
}

// NewCollector creates a new metrics collector with all instruments registered.
func NewCollector() *Collector {
	reg := prometheus.NewRegistry()

	c := &Collector{
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hexstrike_requests_total",
				Help: "Total number of MCP requests",
			},
			[]string{"method", "tool_name"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "hexstrike_request_duration_seconds",
				Help:    "MCP request duration in seconds",
				Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300},
			},
			[]string{"method", "tool_name"},
		),
		policyDecisions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hexstrike_policy_decisions_total",
				Help: "Total policy decisions",
			},
			[]string{"tool_name", "decision"},
		),
		toolErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hexstrike_tool_errors_total",
				Help: "Total tool execution errors",
			},
			[]string{"tool_name"},
		),
		registry: reg,
	}

	reg.MustRegister(c.requestsTotal)
	reg.MustRegister(c.requestDuration)
	reg.MustRegister(c.policyDecisions)
	reg.MustRegister(c.toolErrors)

	return c
}

// RecordRequest records a completed MCP request.
func (c *Collector) RecordRequest(method, toolName string, duration time.Duration, isError bool) {
	c.requestsTotal.WithLabelValues(method, toolName).Inc()
	c.requestDuration.WithLabelValues(method, toolName).Observe(duration.Seconds())
	if isError {
		c.toolErrors.WithLabelValues(toolName).Inc()
	}
}

// RecordPolicyDecision records a policy evaluation result.
func (c *Collector) RecordPolicyDecision(toolName string, allowed bool) {
	decision := "allowed"
	if !allowed {
		decision = "denied"
	}
	c.policyDecisions.WithLabelValues(toolName, decision).Inc()
}

// Handler returns the Prometheus HTTP handler for scraping.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
}

// Middleware returns HTTP middleware that records request metrics.
func Middleware(c *Collector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)

			duration := time.Since(start)
			isError := rw.statusCode >= 400
			c.RecordRequest(r.Method, r.URL.Path, duration, isError)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
