# ADR-005: nix2container for OCI Image Builds

## Status
Accepted

## Context
We need reproducible OCI images for Kubernetes deployment. The legacy Dockerfile used `pip install` which is not reproducible and includes unnecessary build dependencies.

## Decision
Use **nix2container** (via `dockerTools.buildLayeredImage`) for OCI image construction.

## Rationale
- **Reproducibility**: Same nix flake hash always produces the same image.
- **Layer strategy**: 4 layers (base, MCP+Futhark, gateway, policies) enable efficient caching and small updates.
- **No Docker daemon**: Images are built by Nix, no Docker required in CI.
- **Minimal attack surface**: Only runtime dependencies included, no compilers or build tools.

## Consequences
- Image builds require Nix in CI (handled by DeterminateSystems/nix-installer-action).
- Debugging requires `nix-shell` or similar (no `docker exec` with package managers).
- Layer boundaries are explicit and intentional, not Dockerfile-cache-dependent.
