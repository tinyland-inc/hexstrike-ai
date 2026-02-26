# OCI image is now built directly in flake.nix as `packages.container`.
#
# Build:  nix build .#container
# Load:   docker load < result
# Push:   skopeo copy docker-archive:result docker://ghcr.io/tinyland-inc/hexstrike-ai:edge
#
# Layer strategy (managed by dockerTools.buildLayeredImage):
#   - Security tools (nmap, nuclei, trivy, etc.) — shared base, rarely changes
#   - hexstrike-mcp (OCaml binary) — changes on MCP server updates
#   - hexstrike-gateway (Go binary) — changes on gateway updates
#   - hexstrike-policies (compiled Dhall JSON) — changes on policy updates
#
# RemoteJuggler sidecar integration:
#   The container runs alongside an adapter sidecar in K8s. The sidecar
#   provides credential resolution (juggler_resolve_composite), identity
#   management, and Aperture metering. The gateway credential broker
#   chains: env -> sops -> kdbx -> setec (via sidecar).
#
# See also:
#   - flake.nix (package definitions)
#   - tofu/stacks/hexstrike/main.tf (K8s deployment)
#   - tinyland/workspace/IDENTITY.md (pod identity)
#   - tinyland/workspace/TOOLS.md (available platform tools)
