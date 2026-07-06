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
            vendorHash = "sha256-ZT094nVSjFBQHTV3GBwgEVxVx3GJ5cYLWf+yDttIc8Q=";
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
        }
        # LNCH-02 quickstart fire-drill in a REAL fresh NixOS VM. NixOS VM tests
        # are Linux+KVM only, so guard the attribute off on darwin (where
        # `testers.runNixOSTest` is unavailable). Runs in CI; covers the Linux
        # half of the fire-drill. The macOS half stays operator-manual.
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          quickstart-vm = pkgs.testers.runNixOSTest {
            name = "abysslink-quickstart-firedrill";
            nodes.machine = { ... }: {
              # tailscale is required: doctor's core module checks shell out to
              # the `tailscale` binary; without it doctor errors before emitting
              # any findings and the `grep -q severity` assertion below fails
              # (the Monday-cron red-gate this fixes).
              environment.systemPackages = [
                self.packages.${system}.abysslink
                pkgs.tailscale
              ];
            };
            testScript = ''
              machine.start()
              machine.wait_for_unit("multi-user.target")

              # Rock-solid invariants on a pristine VM:
              machine.succeed("abysslink version")
              machine.succeed("abysslink up --help | grep -- --apply")
              machine.succeed("abysslink enroll --help | grep -- phone")
              machine.succeed("abysslink daemon --help | grep -- enable")
              # doctor is read-only + fail-closed: on this pristine VM it exits
              # 2 BY DESIGN (unencrypted disk gate, no keychain backend), and
              # the test driver's pipefail would otherwise fail the assertion
              # even though grep matched — the Monday-cron red-gate this fixes.
              # `|| true` absorbs doctor's documented exit (and any SIGPIPE);
              # grep (without -q, so it drains stdin) still fails the check if
              # no findings JSON is emitted. Do NOT weaken doctor instead: the
              # fail-closed exit contract is an immutable security default.
              machine.succeed("(abysslink --json doctor || true) | grep severity >/dev/null")

              # Full timed fire-drill harness — INFORMATIONAL (does not gate the
              # check): `up --dry-run` may need a config on a bare box, so its
              # output is logged, not asserted. The operator's --apply drill (with
              # a Tailscale ephemeral auth key + LUKS-encrypted VM) is the gate.
              print(machine.execute(
                "ABYSSLINK_BIN=$(command -v abysslink) bash ${./scripts/quickstart-firedrill.sh}"
              )[1])
            '';
          };
        };
      }
    );
}
