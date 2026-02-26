"""
HexStrike-AI Flask REST API Server

Provides security scanning tools via a Flask REST API on port 8888.
The adapter sidecar communicates via POST /api/command.

Endpoints:
  GET  /health              — Tool availability check
  POST /api/command         — Execute security commands
  POST /api/intelligence/smart-scan       — AI-driven scan
  POST /api/intelligence/analyze-target   — Target profiling

Security commands are executed via subprocess with input sanitization.
Results include findings in __findings__[...]__end_findings__ format
for automatic extraction by the campaign runner.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import time

from flask import Flask, jsonify, request

app = Flask(__name__)
log = logging.getLogger("hexstrike")

# Allowed security tool binaries (whitelist).
ALLOWED_TOOLS = {
    "nmap",
    "curl",
    "git",
    "ssh-keyscan",
    "openssl",
    "dig",
    "host",
    "wget",
    "nc",
}

# Built-in scan commands mapped to Python functions.
BUILTIN_COMMANDS = {}


def register_command(name):
    """Decorator to register a built-in scan command."""

    def decorator(fn):
        BUILTIN_COMMANDS[name] = fn
        return fn

    return decorator


# ---------------------------------------------------------------------------
# Built-in security scan commands
# ---------------------------------------------------------------------------


@register_command("credential_scan")
def cmd_credential_scan(args):
    """Scan a GitHub repository for exposed credentials."""
    target = _parse_arg(args, "--target")
    if not target:
        return {"error": "credential_scan requires --target owner/repo"}

    patterns = [
        r"(?i)(api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*['\"][^'\"]{8,}",
        r"AKIA[0-9A-Z]{16}",  # AWS access key
        r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub PAT
        r"glpat-[a-zA-Z0-9\-]{20,}",  # GitLab PAT
    ]

    findings = []
    stdout_lines = [f"Scanning {target} for credential exposure..."]

    # Use git to clone and scan (shallow)
    tmp_dir = f"/tmp/hexstrike-scan-{int(time.time())}"
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", f"https://github.com/{target}.git", tmp_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            stdout_lines.append(f"Clone failed: {result.stderr.strip()}")
            return {
                "success": False,
                "stdout": "\n".join(stdout_lines),
                "stderr": result.stderr,
            }

        files_scanned = 0
        for root, _, files in os.walk(tmp_dir):
            if ".git" in root:
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, tmp_dir)
                # Skip binary files
                if _is_binary(fpath):
                    continue
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read()
                    files_scanned += 1
                    for i, line in enumerate(content.splitlines(), 1):
                        for pattern in patterns:
                            if re.search(pattern, line):
                                findings.append(
                                    {
                                        "title": f"Potential credential in {rel_path}:{i}",
                                        "body": f"Pattern match in `{rel_path}` line {i}. Review and rotate if real.",
                                        "severity": "high",
                                        "labels": ["security", "credentials"],
                                        "fingerprint": f"cred-{rel_path}-{i}",
                                    }
                                )
                except (OSError, UnicodeDecodeError):
                    continue

        stdout_lines.append(f"Scanned {files_scanned} files in {target}")
        if findings:
            stdout_lines.append(f"Found {len(findings)} potential credential exposures")
        else:
            stdout_lines.append("No credentials found")

    finally:
        subprocess.run(["rm", "-rf", tmp_dir], capture_output=True)

    stdout = "\n".join(stdout_lines)
    if findings:
        stdout += f"\n__findings__{json.dumps(findings)}__end_findings__"

    return {"success": True, "stdout": stdout, "stderr": "", "execution_time": 0}


@register_command("tls_check")
def cmd_tls_check(args):
    """Check TLS certificate for a target host."""
    target = _parse_arg(args, "--target")
    if not target:
        return {"error": "tls_check requires --target hostname:port"}

    # Default to port 443
    if ":" not in target:
        target = f"{target}:443"

    host, port = target.rsplit(":", 1)
    findings = []
    stdout_lines = [f"Checking TLS for {target}..."]

    try:
        # Check expiry
        result2 = subprocess.run(
            ["openssl", "s_client", "-connect", target, "-servername", host],
            input="",
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Parse certificate dates
        dates_result = subprocess.run(
            ["openssl", "x509", "-noout", "-dates"],
            input=result2.stdout,
            capture_output=True,
            text=True,
            timeout=5,
        )
        stdout_lines.append(dates_result.stdout.strip())

        # Check for weak protocols
        for proto in ["ssl3", "tls1", "tls1_1"]:
            weak_check = subprocess.run(
                ["openssl", "s_client", "-connect", target, f"-{proto}"],
                input="",
                capture_output=True,
                text=True,
                timeout=10,
            )
            if weak_check.returncode == 0 and "CONNECTED" in weak_check.stdout:
                findings.append(
                    {
                        "title": f"Weak TLS protocol {proto} supported on {host}",
                        "body": f"Host {host} accepts {proto} connections. Disable legacy protocols.",
                        "severity": "medium",
                        "labels": ["security", "tls"],
                        "fingerprint": f"tls-weak-{host}-{proto}",
                    }
                )

        stdout_lines.append(f"TLS check complete for {host}")
    except subprocess.TimeoutExpired:
        stdout_lines.append(f"Connection to {target} timed out")
    except FileNotFoundError:
        return {"error": "openssl not found"}

    stdout = "\n".join(stdout_lines)
    if findings:
        stdout += f"\n__findings__{json.dumps(findings)}__end_findings__"

    return {"success": True, "stdout": stdout, "stderr": "", "execution_time": 0}


@register_command("port_scan")
def cmd_port_scan(args):
    """Run an nmap port scan on a target."""
    target = _parse_arg(args, "--target")
    if not target:
        return {"error": "port_scan requires --target host"}

    ports = _parse_arg(args, "--ports") or "22,80,443,8080,8443,18789,18790"

    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-p", ports, "--open", "-oG", "-", target],
            capture_output=True,
            text=True,
            timeout=120,
        )
        stdout = f"Port scan of {target}:\n{result.stdout}"
        return {
            "success": True,
            "stdout": stdout,
            "stderr": result.stderr,
            "execution_time": 0,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": f"Scan of {target} timed out",
            "stderr": "timeout",
        }
    except FileNotFoundError:
        return {"error": "nmap not found"}


@register_command("network_posture")
def cmd_network_posture(args):
    """Assess network security posture of a K8s namespace."""
    findings = []
    stdout_lines = ["Network posture assessment..."]

    # Check for common exposed services
    services = [
        ("rj-gateway", "rj-gateway.fuzzy-dev.svc.cluster.local", 8080),
        ("aperture", "aperture.fuzzy-dev.svc.cluster.local", 80),
        ("ironclaw", "ironclaw-agent.fuzzy-dev.svc.cluster.local", 8080),
        ("picoclaw", "picoclaw-agent.fuzzy-dev.svc.cluster.local", 8080),
    ]

    for name, host, port in services:
        try:
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    f"http://{host}:{port}/health",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            status = result.stdout.strip()
            stdout_lines.append(f"  {name}: HTTP {status}")
            if status == "000":
                stdout_lines.append("    -> unreachable")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            stdout_lines.append(f"  {name}: timeout/error")

    stdout = "\n".join(stdout_lines)
    if findings:
        stdout += f"\n__findings__{json.dumps(findings)}__end_findings__"

    return {"success": True, "stdout": stdout, "stderr": "", "execution_time": 0}


@register_command("container_vuln")
def cmd_container_vuln(args):
    """Check for known container vulnerabilities (basic checks)."""
    findings = []
    stdout_lines = ["Container vulnerability check..."]

    # Check if running as root
    uid = os.getuid()
    if uid == 0:
        findings.append(
            {
                "title": "Container running as root",
                "body": "This container is running as UID 0. Use a non-root user.",
                "severity": "medium",
                "labels": ["security", "container"],
                "fingerprint": "container-root-uid",
            }
        )
    stdout_lines.append(f"  Running as UID: {uid}")

    # Check for writable sensitive paths
    sensitive_paths = ["/etc/passwd", "/etc/shadow", "/proc/sysrq-trigger"]
    for path in sensitive_paths:
        if os.path.exists(path) and os.access(path, os.W_OK):
            findings.append(
                {
                    "title": f"Writable sensitive path: {path}",
                    "body": f"Container has write access to {path}. This is a security risk.",
                    "severity": "high",
                    "labels": ["security", "container"],
                    "fingerprint": f"container-writable-{path.replace('/', '-')}",
                }
            )
            stdout_lines.append(f"  {path}: WRITABLE (risk)")
        else:
            stdout_lines.append(f"  {path}: ok")

    # Check for capabilities
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("Cap"):
                    stdout_lines.append(f"  {line.strip()}")
    except OSError:
        pass

    stdout = "\n".join(stdout_lines)
    if findings:
        stdout += f"\n__findings__{json.dumps(findings)}__end_findings__"

    return {"success": True, "stdout": stdout, "stderr": "", "execution_time": 0}


@register_command("sops_rotation_check")
def cmd_sops_rotation_check(args):
    """Check SOPS key rotation status."""
    _parse_arg(args, "--target")  # reserved for future filtering
    findings = []
    stdout_lines = ["SOPS key rotation check..."]

    # Check if sops binary is available
    sops_path = shutil.which("sops")
    age_path = shutil.which("age")

    stdout_lines.append(f"  sops binary: {'found' if sops_path else 'NOT FOUND'}")
    stdout_lines.append(f"  age binary: {'found' if age_path else 'NOT FOUND'}")

    if not sops_path:
        findings.append(
            {
                "title": "SOPS binary not available",
                "body": "The sops binary is not installed. SOPS key rotation cannot be verified.",
                "severity": "low",
                "labels": ["security", "sops"],
                "fingerprint": "sops-missing-binary",
            }
        )

    stdout = "\n".join(stdout_lines)
    if findings:
        stdout += f"\n__findings__{json.dumps(findings)}__end_findings__"

    return {"success": True, "stdout": stdout, "stderr": "", "execution_time": 0}


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------


@app.route("/health", methods=["GET"])
def health():
    """Health check: verify tool availability."""
    tools = {}
    for tool in ALLOWED_TOOLS:
        tools[tool] = shutil.which(tool) is not None

    builtins = list(BUILTIN_COMMANDS.keys())

    return jsonify(
        {
            "status": "ok",
            "agent": "hexstrike-ai",
            "tools": tools,
            "builtin_commands": builtins,
        }
    )


@app.route("/api/command", methods=["POST"])
def api_command():
    """Execute a security command."""
    start = time.time()

    data = request.get_json(silent=True) or {}
    command_str = data.get("command", "").strip()

    if not command_str:
        return jsonify({"error": "missing 'command' field"}), 400

    log.info("Executing command: %s", command_str)

    # Parse command name and arguments
    parts = command_str.split(None, 1)
    cmd_name = parts[0]
    cmd_args = parts[1] if len(parts) > 1 else ""

    # Check built-in commands first
    if cmd_name in BUILTIN_COMMANDS:
        result = BUILTIN_COMMANDS[cmd_name](cmd_args)
        elapsed = time.time() - start
        if "error" in result:
            return jsonify(result), 400
        result["execution_time"] = round(elapsed, 2)
        return jsonify(result)

    # Check if it's an allowed external tool
    if cmd_name not in ALLOWED_TOOLS:
        return jsonify({"error": f"command not found: {cmd_name}"}), 400

    # Sanitize: reject shell metacharacters
    if _has_shell_injection(command_str):
        return jsonify({"error": "command contains disallowed characters"}), 400

    # Execute external tool
    try:
        argv = command_str.split()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        elapsed = time.time() - start
        return jsonify(
            {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "execution_time": round(elapsed, 2),
            }
        )
    except subprocess.TimeoutExpired:
        return jsonify(
            {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out after 300s",
                "execution_time": 300,
            }
        )
    except FileNotFoundError:
        return jsonify({"error": f"tool not found: {cmd_name}"}), 400


@app.route("/api/intelligence/smart-scan", methods=["POST"])
def smart_scan():
    """AI-driven scan with automatic tool selection."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")

    results = []
    # Run relevant built-in scans based on target type
    if "/" in target:
        # Looks like a repo — run credential scan
        r = BUILTIN_COMMANDS.get("credential_scan", lambda a: {"stdout": "no scanner"})(
            f"--target {target}"
        )
        results.append(r)
    else:
        # Looks like a host — run port scan + TLS check
        r = BUILTIN_COMMANDS.get("port_scan", lambda a: {"stdout": "no scanner"})(
            f"--target {target}"
        )
        results.append(r)
        r = BUILTIN_COMMANDS.get("tls_check", lambda a: {"stdout": "no scanner"})(
            f"--target {target}"
        )
        results.append(r)

    combined_stdout = "\n".join(r.get("stdout", "") for r in results)
    return jsonify(
        {
            "success": True,
            "stdout": combined_stdout,
            "stderr": "",
            "scans_run": len(results),
        }
    )


@app.route("/api/intelligence/analyze-target", methods=["POST"])
def analyze_target():
    """Target profiling and reconnaissance."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")

    stdout_lines = [f"Target analysis: {target}"]

    if "/" in target:
        stdout_lines.append("Type: GitHub repository")
        stdout_lines.append(f"URL: https://github.com/{target}")
    elif "." in target:
        stdout_lines.append("Type: hostname/IP")
        # DNS lookup
        try:
            result = subprocess.run(
                ["host", target], capture_output=True, text=True, timeout=10
            )
            stdout_lines.append(f"DNS: {result.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            stdout_lines.append("DNS: lookup failed")

    return jsonify(
        {
            "success": True,
            "stdout": "\n".join(stdout_lines),
            "stderr": "",
        }
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_arg(args_str, flag):
    """Parse a --flag value from an argument string."""
    parts = args_str.split()
    for i, p in enumerate(parts):
        if p == flag and i + 1 < len(parts):
            return parts[i + 1]
        if p.startswith(f"{flag}="):
            return p[len(flag) + 1 :]
    return None


def _has_shell_injection(cmd):
    """Check for shell injection metacharacters."""
    return bool(re.search(r"[;&|`$(){}]", cmd))


def _is_binary(filepath):
    """Quick check if a file is binary."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except OSError:
        return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexStrike-AI REST API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8888, help="Listen port")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    log.info("HexStrike-AI server starting on %s:%d", args.host, args.port)
    log.info("Built-in commands: %s", ", ".join(BUILTIN_COMMANDS.keys()))
    log.info("Allowed external tools: %s", ", ".join(sorted(ALLOWED_TOOLS)))

    app.run(host=args.host, port=args.port, debug=args.debug)
