// Package policy enforces grants-as-capabilities access control.
// Policies are compiled from Dhall to JSON and loaded at startup.
package policy

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// Grant represents a capability grant from a Dhall policy.
type Grant struct {
	Src                string   `json:"src"`
	Dst                string   `json:"dst"`
	App                []string `json:"app"`
	ParameterConstraints map[string]string `json:"parameter_constraints,omitempty"`
	RateLimit          int      `json:"rate_limit,omitempty"`
	AuditLevel         string   `json:"audit_level,omitempty"`
}

// CompiledPolicy is the in-memory representation of a policy file.
type CompiledPolicy struct {
	Grants  []Grant  `json:"grants"`
	Denied  []string `json:"denied,omitempty"`
	Version string   `json:"version,omitempty"`
}

// Decision is the result of a policy evaluation.
type Decision struct {
	Allowed    bool
	Reason     string
	AuditLevel string
	RateLimit  int
}

// Engine evaluates policy decisions.
type Engine struct {
	policy CompiledPolicy
}

// NewEngine loads a compiled policy from a JSON file.
func NewEngine(path string) (*Engine, error) {
	if path == "" {
		return DefaultEngine(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var pol CompiledPolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	log.Printf("policy loaded: %d grants, %d denied, version=%s",
		len(pol.Grants), len(pol.Denied), pol.Version)

	return &Engine{policy: pol}, nil
}

// DefaultEngine returns a permissive engine (allow all).
func DefaultEngine() *Engine {
	return &Engine{
		policy: CompiledPolicy{
			Grants:  nil,
			Denied:  nil,
			Version: "default-allow",
		},
	}
}

// Evaluate checks whether a caller can invoke a tool.
func (e *Engine) Evaluate(caller, toolName string) Decision {
	// Check denied list first — absolute precedence
	for _, d := range e.policy.Denied {
		if d == toolName {
			return Decision{Allowed: false, Reason: "tool is explicitly denied"}
		}
	}

	// No grants defined = allow all (default-allow mode)
	if len(e.policy.Grants) == 0 {
		return Decision{Allowed: true, Reason: "default-allow", AuditLevel: "standard"}
	}

	// Check grants — first match wins
	for _, g := range e.policy.Grants {
		if !matchCaller(g.Src, caller) {
			continue
		}
		if !matchNamespace(g.Dst, caller) {
			continue
		}
		for _, cap := range g.App {
			if cap == toolName || cap == "*" {
				return Decision{
					Allowed:    true,
					Reason:     fmt.Sprintf("granted by %s", g.Src),
					AuditLevel: g.AuditLevel,
					RateLimit:  g.RateLimit,
				}
			}
		}
	}

	return Decision{Allowed: false, Reason: "no matching grant found"}
}

// EvaluateWithParams checks policy including parameter constraints.
func (e *Engine) EvaluateWithParams(caller, toolName string, params map[string]string) Decision {
	d := e.Evaluate(caller, toolName)
	if !d.Allowed {
		return d
	}

	// Find the matching grant to check parameter constraints
	for _, g := range e.policy.Grants {
		if !matchCaller(g.Src, caller) || !matchNamespace(g.Dst, caller) {
			continue
		}
		for _, cap := range g.App {
			if cap != toolName && cap != "*" {
				continue
			}
			// Check parameter constraints (regex patterns)
			for paramName, pattern := range g.ParameterConstraints {
				if val, ok := params[paramName]; ok {
					if !matchPattern(pattern, val) {
						return Decision{
							Allowed: false,
							Reason:  fmt.Sprintf("parameter %q violates constraint %q", paramName, pattern),
						}
					}
				}
			}
			return d // constraints pass
		}
	}
	return d
}

// matchCaller checks if a grant source matches the caller identity.
func matchCaller(pattern, caller string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(caller, prefix)
	}
	return pattern == caller
}

// matchNamespace checks if a grant destination namespace applies.
// "*" matches all. "internal" matches tailnet callers. "external" matches non-tailnet.
func matchNamespace(dst, caller string) bool {
	if dst == "*" {
		return true
	}
	isTailnet := strings.Contains(caller, "@")
	if dst == "internal" {
		return isTailnet
	}
	if dst == "external" {
		return !isTailnet
	}
	return dst == caller
}

// matchPattern checks if a value matches a simple pattern.
// Supports: exact match, prefix glob (*.example.com), suffix glob (10.0.*).
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

// Reload re-reads the policy file from disk (for hot-reload).
func (e *Engine) Reload(path string) error {
	newEngine, err := NewEngine(path)
	if err != nil {
		return err
	}
	e.policy = newEngine.policy
	log.Printf("policy reloaded: %d grants", len(e.policy.Grants))
	return nil
}
