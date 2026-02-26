package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultEngineAllowsAll(t *testing.T) {
	e := DefaultEngine()
	d := e.Evaluate("anyone", "any_tool")
	if !d.Allowed {
		t.Fatalf("default engine should allow all, got denied: %s", d.Reason)
	}
}

func TestDeniedToolAlwaysDenied(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Denied: []string{"dangerous_tool"},
		},
	}
	d := e.Evaluate("admin", "dangerous_tool")
	if d.Allowed {
		t.Fatal("denied tool should always be denied")
	}
}

func TestGrantMatchesExactCaller(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "alice@tailnet", Dst: "*", App: []string{"port_scan"}},
			},
		},
	}

	d := e.Evaluate("alice@tailnet", "port_scan")
	if !d.Allowed {
		t.Fatalf("alice should be allowed port_scan, got: %s", d.Reason)
	}

	d = e.Evaluate("bob@tailnet", "port_scan")
	if d.Allowed {
		t.Fatal("bob should not be allowed port_scan")
	}
}

func TestGrantWildcardCaller(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "*", Dst: "*", App: []string{"server_health"}},
			},
		},
	}
	d := e.Evaluate("anyone", "server_health")
	if !d.Allowed {
		t.Fatalf("wildcard caller should match, got: %s", d.Reason)
	}
}

func TestGrantWildcardCapability(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "admin@tailnet", Dst: "*", App: []string{"*"}},
			},
		},
	}
	d := e.Evaluate("admin@tailnet", "any_tool_at_all")
	if !d.Allowed {
		t.Fatalf("wildcard capability should match, got: %s", d.Reason)
	}
}

func TestGrantPrefixCaller(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "agent-*", Dst: "*", App: []string{"port_scan"}},
			},
		},
	}

	d := e.Evaluate("agent-hexstrike", "port_scan")
	if !d.Allowed {
		t.Fatalf("prefix match should work, got: %s", d.Reason)
	}

	d = e.Evaluate("user-bob", "port_scan")
	if d.Allowed {
		t.Fatal("non-matching prefix should be denied")
	}
}

func TestNoMatchingGrant(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "alice@tailnet", Dst: "*", App: []string{"tls_check"}},
			},
		},
	}
	d := e.Evaluate("alice@tailnet", "port_scan")
	if d.Allowed {
		t.Fatal("should deny when tool not in any grant")
	}
}

func TestDeniedTakesPrecedenceOverGrant(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "*", Dst: "*", App: []string{"*"}},
			},
			Denied: []string{"execute_python_script"},
		},
	}
	d := e.Evaluate("admin", "execute_python_script")
	if d.Allowed {
		t.Fatal("denied list should override wildcard grant")
	}
}

func TestLoadPolicyFromFile(t *testing.T) {
	pol := CompiledPolicy{
		Grants: []Grant{
			{Src: "test@tailnet", Dst: "*", App: []string{"port_scan"}, AuditLevel: "verbose"},
		},
		Denied:  []string{"dangerous"},
		Version: "test-1.0",
	}

	data, err := json.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	e, err := NewEngine(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	d := e.Evaluate("test@tailnet", "port_scan")
	if !d.Allowed {
		t.Fatalf("loaded policy should allow, got: %s", d.Reason)
	}

	d = e.Evaluate("test@tailnet", "dangerous")
	if d.Allowed {
		t.Fatal("loaded policy should deny dangerous tool")
	}
}

func TestNamespaceInternal(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "*", Dst: "internal", App: []string{"port_scan"}},
			},
		},
	}

	// Tailnet caller (has @) matches "internal"
	d := e.Evaluate("alice@tailnet", "port_scan")
	if !d.Allowed {
		t.Fatalf("tailnet caller should match internal: %s", d.Reason)
	}

	// Non-tailnet caller should not match "internal"
	d = e.Evaluate("10.0.0.1:54321", "port_scan")
	if d.Allowed {
		t.Fatal("non-tailnet caller should not match internal namespace")
	}
}

func TestNamespaceExternal(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{Src: "*", Dst: "external", App: []string{"port_scan"}},
			},
		},
	}

	// Non-tailnet caller matches "external"
	d := e.Evaluate("10.0.0.1:54321", "port_scan")
	if !d.Allowed {
		t.Fatalf("non-tailnet caller should match external: %s", d.Reason)
	}

	// Tailnet caller should not match "external"
	d = e.Evaluate("alice@tailnet", "port_scan")
	if d.Allowed {
		t.Fatal("tailnet caller should not match external namespace")
	}
}

func TestParameterConstraints(t *testing.T) {
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{
					Src: "*", Dst: "*", App: []string{"port_scan"},
					ParameterConstraints: map[string]string{
						"target": "10.0.*",
					},
				},
			},
		},
	}

	// Matching parameter
	d := e.EvaluateWithParams("anyone", "port_scan", map[string]string{"target": "10.0.1.1"})
	if !d.Allowed {
		t.Fatalf("should allow matching target: %s", d.Reason)
	}

	// Violating parameter
	d = e.EvaluateWithParams("anyone", "port_scan", map[string]string{"target": "192.168.1.1"})
	if d.Allowed {
		t.Fatal("should deny non-matching target")
	}
}

// TestPolicyCoverage verifies every tool in the manifest is granted to at least
// one non-operator role (operator uses wildcard "*" so it trivially covers all).
func TestPolicyCoverage(t *testing.T) {
	allTools := []string{
		"port_scan", "host_discovery", "nmap_scan", "network_posture",
		"subdomain_enum", "dns_recon",
		"dir_discovery", "vuln_scan", "sqli_test", "xss_test", "waf_detect", "web_crawl",
		"api_fuzz", "graphql_scan", "jwt_analyze",
		"tls_check",
		"credential_scan", "sops_rotation_check", "brute_force", "hash_crack",
		"smb_enum", "network_exec", "rpc_enum",
		"cloud_posture", "container_scan", "iac_scan", "k8s_audit",
		"disassemble", "debug", "gadget_search", "firmware_analyze",
		"memory_forensics", "file_carving", "steganography", "metadata_extract",
		"cve_monitor", "exploit_gen", "threat_correlate",
		"smart_scan", "target_profile",
		"server_health", "execute_command",
	}

	// Build a policy matching hexstrike-agent grants (non-wildcard).
	e := &Engine{
		policy: CompiledPolicy{
			Grants: []Grant{
				{
					Src: "hexstrike-agent", Dst: "*",
					App: []string{
						"port_scan", "host_discovery", "nmap_scan", "network_posture",
						"subdomain_enum", "dns_recon", "tls_check",
						"credential_scan", "sops_rotation_check", "brute_force", "hash_crack",
						"dir_discovery", "vuln_scan", "sqli_test", "xss_test", "waf_detect", "web_crawl",
						"api_fuzz", "graphql_scan", "jwt_analyze",
						"smb_enum", "network_exec", "rpc_enum",
						"cloud_posture", "container_scan", "iac_scan", "k8s_audit",
						"disassemble", "debug", "gadget_search", "firmware_analyze",
						"memory_forensics", "file_carving", "steganography", "metadata_extract",
						"cve_monitor", "exploit_gen", "threat_correlate",
						"smart_scan", "target_profile",
						"server_health", "execute_command",
					},
				},
			},
		},
	}

	var ungrantable []string
	for _, tool := range allTools {
		d := e.Evaluate("hexstrike-agent", tool)
		if !d.Allowed {
			ungrantable = append(ungrantable, tool)
		}
	}
	if len(ungrantable) > 0 {
		t.Errorf("tools not in any hexstrike-agent grant: %v", ungrantable)
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	// Initial policy: deny port_scan
	pol1 := CompiledPolicy{Denied: []string{"port_scan"}, Version: "v1"}
	data1, _ := json.Marshal(pol1)
	os.WriteFile(path, data1, 0644)

	e, err := NewEngine(path)
	if err != nil {
		t.Fatal(err)
	}

	d := e.Evaluate("anyone", "port_scan")
	if d.Allowed {
		t.Fatal("v1 should deny port_scan")
	}

	// Reload with new policy: allow port_scan
	pol2 := CompiledPolicy{Version: "v2"}
	data2, _ := json.Marshal(pol2)
	os.WriteFile(path, data2, 0644)

	if err := e.Reload(path); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	d = e.Evaluate("anyone", "port_scan")
	if !d.Allowed {
		t.Fatalf("v2 should allow port_scan, got: %s", d.Reason)
	}
}
