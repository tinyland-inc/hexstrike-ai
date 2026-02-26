{
  description = "HexStrike-AI — auditable, provable cybersecurity MCP platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];

      imports = [
        inputs.treefmt-nix.flakeModule
      ];

      perSystem = { config, pkgs, lib, system, ... }:
      let
        # ── OCaml package set ────────────────────────────────
        # OCaml has a known test failure on aarch64-darwin
        # (tests/unwind/driver.ml fails for both 5.2 and 5.3).
        # Skip OCaml's test suite on darwin; it compiles fine.
        ocamlPkgs = if pkgs.stdenv.hostPlatform.isDarwin then
          pkgs.ocamlPackages.overrideScope (self: super: {
            ocaml = super.ocaml.overrideAttrs (old: { doCheck = false; });
          })
        else
          pkgs.ocamlPackages;

        # ── Futhark compiled kernels ──────────────────────────
        # Each kernel is compiled to a separate shared library to avoid
        # symbol collisions (all export futhark_context_new etc.)
        # Source is in futhark/out/ (gitignored, built by CI futhark-build job).
        # For local dev, the OCaml FFI bridge falls back to pure-OCaml stubs.
        # Build locally: just futhark-build && just futhark-kernels
        sharedLibExt = if pkgs.stdenv.hostPlatform.isDarwin then "dylib" else "so";

        # ── OCaml package dependencies ─────────────────────────
        ocamlDeps = with ocamlPkgs; [
          findlib yojson cmdliner sha uuidm logs fmt ctypes ctypes-foreign
        ];
        ocamlTestDeps = with ocamlPkgs; [ alcotest ];

        # ── Security tool runtime ──────────────────────────────
        # Every binary declared in dhall/tools/*.dhall requiredBinaries
        # plus execute_command.ml whitelist.
        #
        # Some packages are broken on aarch64-darwin in nixpkgs-unstable:
        #   - samba 4.22: test_ldb_comparison_fold build failure
        #   - thc-hydra: depends on samba/libssh which fails
        #   - checkov/prowler: pycep-parser needs uv_build
        # These are available in the container (Linux) or via pip overlay.
        securityTools = with pkgs; [
          # Network/Recon
          nmap
          subfinder
          dig

          # Crypto
          openssl

          # Web security
          curl
          nuclei
          sqlmap
          dalfox
          wafw00f
          katana

          # Cloud/Container
          trivy
          kube-bench

          # CredentialAudit
          john
        ] ++ lib.optionals (!pkgs.stdenv.hostPlatform.isDarwin) [
          # These build on Linux but fail on macOS:
          thc-hydra   # needs libssh/samba
          samba       # smbclient, rpcclient
          binutils    # objdump, readelf, strings (GNU ar conflicts with macOS ld)
        ] ++ (with pkgs; [
          # BinaryAnalysis
          binwalk

          # Forensics
          exiftool
          foremost

          # Intelligence
          exploitdb  # searchsploit

          # API Testing
          ffuf

          # Credentials/Utils
          sops
          wget
          netcat-gnu
          git
          openssh
          gnugrep
          coreutils
          bash
        ]);

      in {

        treefmt = {
          projectRootFile = "flake.nix";
          programs.ocamlformat.enable = true;
          programs.nixpkgs-fmt.enable = true;
        };

        # ── Packages ──────────────────────────────────────────

        packages = {
          # OCaml MCP server binary
          hexstrike-mcp = ocamlPkgs.buildDunePackage {
            pname = "hexstrike-mcp";
            version = "0.2.0";
            src = ./ocaml;
            duneVersion = "3";
            buildInputs = ocamlDeps;
            checkInputs = ocamlTestDeps;
            doCheck = true;
            meta.description = "HexStrike MCP server — verified cybersecurity tool dispatch";
          };

          # Go gateway binary
          hexstrike-gateway = pkgs.buildGoModule {
            pname = "hexstrike-gateway";
            version = "0.2.0";
            src = ./gateway;
            vendorHash = "sha256-Vz+WNq66jZkmzFrIpIf1ZqcG4JjTonqDI3bEllUZUm4=";
            subPackages = [ "cmd/hexstrike-gateway" ];
            meta.description = "HexStrike gateway — tsnet + policy + metering";
          };

          # Compiled Dhall policies (JSON)
          hexstrike-policies = pkgs.runCommand "hexstrike-policies" {
            nativeBuildInputs = [ pkgs.dhall-json ];
            src = ./dhall;
          } ''
            mkdir -p $out
            dhall-to-json --file $src/render.dhall --output $out/tool-manifest.json
            dhall-to-json --file $src/policies/compose.dhall --output $out/policy.json
          '';

          # Full-fat OCI container image
          container = pkgs.dockerTools.buildLayeredImage {
            name = "ghcr.io/tinyland-inc/hexstrike-ai";
            tag = "edge";

            contents = [
              config.packages.hexstrike-mcp
              config.packages.hexstrike-gateway
              config.packages.hexstrike-policies
              pkgs.cacert
            ] ++ securityTools;

            config = {
              Entrypoint = [ "hexstrike-gateway" ];
              Cmd = [
                "-mcp-binary" "hexstrike-mcp"
                "-policy" "/compiled/policy.json"
                "-listen" ":8080"
                "-metrics" ":9090"
              ];
              Env = [
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                "HEXSTRIKE_RESULTS_DIR=/results"
                "HEXSTRIKE_POLICY_PATH=/compiled/policy.json"
              ];
              WorkingDir = "/workspace";
              Volumes = {
                "/workspace" = {};
                "/results" = {};
              };
              ExposedPorts = {
                "8080/tcp" = {};
                "9090/tcp" = {};
              };
            };

            # Symlink compiled policies into /compiled for gateway Cmd default
            extraCommands = ''
              mkdir -p compiled
              ln -s ${config.packages.hexstrike-policies}/policy.json compiled/policy.json
              ln -s ${config.packages.hexstrike-policies}/tool-manifest.json compiled/tool-manifest.json
              mkdir -p workspace results
            '';
          };

          default = config.packages.hexstrike-gateway;
        };

        # ── Dev Shells ────────────────────────────────────────

        # F* has its own OCaml 5.3 dep tree that may not be cached.
        # Split into two shells: default (fast, cached) and fstar (includes F*).
        devShells.default = pkgs.mkShell {
          name = "hexstrike-dev";

          inputsFrom = [
            config.packages.hexstrike-mcp
          ];

          packages = with pkgs; [
            # Dhall
            dhall
            dhall-json
            dhall-lsp-server

            # Futhark
            futhark

            # Go (for gateway)
            go

            # Build tools
            just
            gnumake

            # Utilities
            jq
          ] ++ securityTools;

          shellHook = ''
            # Futhark kernels: set path if locally built
            if [ -d "futhark/lib" ]; then
              export FUTHARK_KERNEL_PATH="$PWD/futhark/lib"
            '' + (if pkgs.stdenv.hostPlatform.isDarwin then ''
              export DYLD_LIBRARY_PATH="$PWD/futhark/lib''${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
            '' else ''
              export LD_LIBRARY_PATH="$PWD/futhark/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '') + ''
            fi
            echo "hexstrike-dev shell ready"
            echo "  dhall     : $(dhall version 2>/dev/null || echo 'not found')"
            echo "  futhark   : $(futhark --version 2>/dev/null || echo 'not found')"
            echo "  ocaml     : $(ocaml --version 2>/dev/null || echo 'not found')"
            echo "  dune      : $(dune --version 2>/dev/null || echo 'not found')"
            echo "  go        : $(go version 2>/dev/null || echo 'not found')"
            echo "  just      : $(just --version 2>/dev/null || echo 'not found')"
          '';
        };

        # Full shell with F* + Z3 (may require building from source)
        devShells.fstar = pkgs.mkShell {
          name = "hexstrike-fstar";

          inputsFrom = [ config.devShells.default ];

          packages = with pkgs; [
            fstar
            z3
          ];

          shellHook = ''
            echo "hexstrike-fstar shell ready"
            echo "  fstar     : $(fstar.exe --version 2>/dev/null | head -1 || echo 'not found')"
            echo "  z3        : $(z3 --version 2>/dev/null || echo 'not found')"
          '';
        };
      };
    };
}
