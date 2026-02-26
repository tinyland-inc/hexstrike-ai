# HexStrike-AI Heartbeat Checklist

HexStrike-AI is currently in dormant mode (replicas=0 by default). When activated:

## Quick Health Check
1. Verify AGENT.md, IDENTITY.md, SOUL.md exist in /workspace/
2. Check memory/MEMORY.md is accessible
3. Test Flask API health endpoint at localhost:8888/health
4. Verify security tools are available (nmap, curl, etc.)

## If checks fail
- Missing workspace files: restore from /workspace-defaults/
- Flask API down: check Python process, review logs
- Tools unavailable: verify Alpine packages installed
