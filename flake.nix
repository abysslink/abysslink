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
        # go.mod requires go >= 1.26.4; nixpkgs-unstable currently ships
        # 1.26.3, so build the exact toolchain from the upstream source
        # tarball. Drop this override once nixpkgs catches up.
        go_1_26_4 = pkgs.go.overrideAttrs (old: {
          version = "1.26.4";
          src = pkgs.fetchurl {
            url = "https://go.dev/dl/go1.26.4.src.tar.gz";
            hash = "sha256-T2aKMvv8ETLmqIH7lowvHa2mMUkqM5IRc1+7JVpCYC0=";
          };
        });
        buildGoModule = pkgs.buildGoModule.override { go = go_1_26_4; };
      in {
        packages = {
          abysslink = buildGoModule {
            pname = "abysslink";
            inherit version;
            src = ./.;
            vendorHash = "sha256-g9CB7I4+bjErPg5pEvNJjlxcxoszguXU9+q/WPEPtTw=";
            subPackages = [ "cmd/abysslink" "cmd/abysslinkd" ];
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
