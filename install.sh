#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# Abysslink installer — downloads the latest release, verifies the cosign
# signature on the checksum file, checks the binary's SHA-256 against the
# verified checksum, then installs to INSTALL_DIR (default: ~/.local/bin).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | bash
#   INSTALL_DIR=/usr/local/bin bash install.sh
#   bash install.sh v1.2.3   # install a specific version
set -euo pipefail

REPO="abysslink/abysslink"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_IDENTITY_REGEXP="https://github.com/abysslink/abysslink/.github/workflows/release.yml@refs/tags/.*"

# ── helpers ──────────────────────────────────────────────────────────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1 — install it and retry"; }

# ── OS / arch detection ───────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Darwin) echo darwin ;;
    Linux)  echo linux  ;;
    *) die "Unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── main ─────────────────────────────────────────────────────────────────────

main() {
  need curl
  need tar
  need sha256sum || need shasum  # macOS uses shasum

  # Resolve version.
  local version="${1:-}"
  if [[ -z "$version" ]]; then
    info "Fetching latest release tag..."
    version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [[ -n "$version" ]] || die "Could not determine latest release version"
  fi
  info "Installing abysslink ${version}"

  local os arch
  os=$(detect_os)
  arch=$(detect_arch)

  local base_url="https://github.com/${REPO}/releases/download/${version}"
  local tarball="abysslink_${version#v}_${os}_${arch}.tar.gz"
  local checksums="abysslink_${version#v}_checksums.txt"
  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  # ── download artifacts ────────────────────────────────────────────────────

  info "Downloading ${tarball}..."
  curl -fsSL "${base_url}/${tarball}" -o "${tmpdir}/${tarball}"

  info "Downloading checksum manifest and cosign signature..."
  curl -fsSL "${base_url}/${checksums}"         -o "${tmpdir}/${checksums}"
  curl -fsSL "${base_url}/${checksums}.sig"     -o "${tmpdir}/${checksums}.sig"
  curl -fsSL "${base_url}/${checksums}.pem"     -o "${tmpdir}/${checksums}.pem"

  # ── verify cosign signature on the checksum manifest ─────────────────────

  if command -v cosign >/dev/null 2>&1; then
    info "Verifying cosign signature on checksum manifest..."
    cosign verify-blob \
      --certificate         "${tmpdir}/${checksums}.pem" \
      --signature           "${tmpdir}/${checksums}.sig" \
      --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
      --certificate-oidc-issuer     "${COSIGN_OIDC_ISSUER}" \
      "${tmpdir}/${checksums}" \
      || die "cosign signature verification FAILED — refusing to install"
    info "Signature OK"
  else
    echo ""
    echo "  WARNING: cosign is not installed; skipping signature verification."
    echo "  Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/)"
    echo "  and re-run this installer to verify the release signature before installing."
    echo ""
    read -r -p "  Continue WITHOUT signature verification? [y/N] " yn
    [[ "${yn,,}" == "y" ]] || die "Aborted — install cosign and retry for a verified install"
  fi

  # ── verify tarball SHA-256 against signed checksum manifest ──────────────

  info "Verifying ${tarball} SHA-256..."
  (
    cd "$tmpdir"
    if command -v sha256sum >/dev/null 2>&1; then
      grep "${tarball}" "${checksums}" | sha256sum --check --status \
        || die "SHA-256 mismatch for ${tarball} — download may be corrupted"
    else
      # macOS shasum
      grep "${tarball}" "${checksums}" | shasum -a 256 --check --status \
        || die "SHA-256 mismatch for ${tarball} — download may be corrupted"
    fi
  )
  info "Checksum OK"

  # ── extract and install ───────────────────────────────────────────────────

  info "Extracting..."
  tar -xzf "${tmpdir}/${tarball}" -C "${tmpdir}"

  mkdir -p "${INSTALL_DIR}"
  install -m 0755 "${tmpdir}/abysslink"   "${INSTALL_DIR}/abysslink"
  install -m 0755 "${tmpdir}/abysslinkd"  "${INSTALL_DIR}/abysslinkd" 2>/dev/null || true

  echo ""
  echo "  Installed abysslink ${version} → ${INSTALL_DIR}/abysslink"

  # ── PATH hint ────────────────────────────────────────────────────────────

  if ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
    echo ""
    echo "  Add ${INSTALL_DIR} to your PATH:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo "  (add to ~/.zshrc or ~/.bashrc to make it permanent)"
  fi

  echo ""
  echo "  Run: abysslink init && abysslink up"
}

main "$@"
