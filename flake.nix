# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
{
  description = "Abysslink — paranoid-by-default phone-to-laptop remote setup over Tailscale";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = if self ? rev then self.shortRev else "dev";
      in {
        packages = {
          abysslink = pkgs.buildGoModule {
            pname = "abysslink";
            inherit version;
            src = ./.;
            # Set to null initially; update after first successful build
            # by running: nix build --print-out-paths 2>&1 | grep vendorHash
            vendorHash = null;
            subPackages = [ "cmd/abysslink" ];
            ldflags = [
              "-s"
              "-w"
              "-X github.com/abysslink/abysslink/internal/cli.version=${version}"
            ];
            meta = with pkgs.lib; {
              description = "Paranoid-by-default phone-to-laptop remote setup over Tailscale";
              homepage = "https://github.com/abysslink/abysslink";
              license = licenses.asl20;
              maintainers = [ ];
              platforms = platforms.unix;
              mainProgram = "abysslink";
            };
          };
          default = self.packages.${system}.abysslink;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            golangci-lint
            goreleaser
            syft
            cosign
            shellcheck
            mkdocs
          ];
          shellHook = ''
            echo "abysslink dev shell ready"
            echo "  make build   — compile binaries"
            echo "  make test    — run tests"
            echo "  make lint    — run linters"
          '';
        };

        checks = {
          build = self.packages.${system}.abysslink;
        };
      }
    );
}
