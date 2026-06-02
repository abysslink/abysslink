#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# Abysslink installer — downloads, verifies, and installs the abysslink binary.
# Usage: curl -fsSL https://abysslink.dev/install.sh | sh
#        ABYSSLINK_VERSION=v0.1.0 sh install.sh
#
# Requirements: curl or wget, sha256sum or shasum, tar.
# Optional:     cosign (for signature verification).
set -e

REPO="abysslink/abysslink"
BINARY="abysslink"
VERSION="${ABYSSLINK_VERSION:-latest}"

# --------------------------------------------------------------------------- #
# Utility helpers                                                              #
# --------------------------------------------------------------------------- #

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '==> %s\n' "$*"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# --------------------------------------------------------------------------- #
# Detect OS and architecture                                                   #
# --------------------------------------------------------------------------- #

detect_os() {
    _uname="$(uname -s)"
    case "${_uname}" in
        Darwin)  printf 'darwin' ;;
        Linux)   printf 'linux'  ;;
        *)       die "unsupported OS: ${_uname}" ;;
    esac
}

detect_arch() {
    _uname="$(uname -m)"
    case "${_uname}" in
        x86_64|amd64)   printf 'amd64' ;;
        arm64|aarch64)  printf 'arm64' ;;
        *)              die "unsupported architecture: ${_uname}" ;;
    esac
}

# --------------------------------------------------------------------------- #
# Resolve latest version from GitHub API                                       #
# --------------------------------------------------------------------------- #

resolve_version() {
    _ver="$1"
    if [ "${_ver}" = "latest" ]; then
        _api="https://api.github.com/repos/${REPO}/releases/latest"
        if have_cmd curl; then
            _ver="$(curl -fsSL "${_api}" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        elif have_cmd wget; then
            _ver="$(wget -qO- "${_api}" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        else
            die "curl or wget is required to resolve the latest version"
        fi
        [ -n "${_ver}" ] || die "failed to resolve latest version from GitHub API"
    fi
    printf '%s' "${_ver}"
}

# --------------------------------------------------------------------------- #
# Download a URL to a local file                                               #
# --------------------------------------------------------------------------- #

download() {
    _url="$1"
    _dest="$2"
    if have_cmd curl; then
        curl -fsSL -o "${_dest}" "${_url}" || die "download failed: ${_url}"
    elif have_cmd wget; then
        wget -qO "${_dest}" "${_url}" || die "download failed: ${_url}"
    else
        die "curl or wget is required"
    fi
}

# --------------------------------------------------------------------------- #
# Verify SHA-256 checksum                                                      #
# --------------------------------------------------------------------------- #

verify_checksum() {
    _file="$1"
    _sums="$2"
    _basename="$(basename "${_file}")"
    # Exact filename match via awk (not a grep regex): the basename is compared
    # literally as field 2, accepting GNU sha256sum's optional binary-mode '*'
    # marker. Avoids regex-metacharacter mismatches (e.g. the '.' in '.tar.gz').
    _expected="$(awk -v f="${_basename}" '$2 == f || $2 == "*"f {print $1}' "${_sums}")"
    [ -n "${_expected}" ] || die "checksum entry not found for ${_basename}"

    if have_cmd sha256sum; then
        _actual="$(sha256sum "${_file}" | awk '{print $1}')"
    elif have_cmd shasum; then
        _actual="$(shasum -a 256 "${_file}" | awk '{print $1}')"
    else
        die "sha256sum or shasum is required for checksum verification"
    fi

    if [ "${_actual}" != "${_expected}" ]; then
        die "checksum mismatch for ${_basename}: expected ${_expected}, got ${_actual}"
    fi
    info "checksum OK: ${_basename}"
}

# --------------------------------------------------------------------------- #
# Verify cosign v3 bundle signature (fails CLOSED on bad signature)           #
# --------------------------------------------------------------------------- #

verify_cosign_bundle() {
    _artifact="$1"
    _bundle="$2"
    if have_cmd cosign; then
        info "verifying cosign v3 bundle signature ..."
        cosign verify-blob \
            --bundle "${_bundle}" \
            --offline \
            --certificate-identity-regexp "^https://github\.com/${REPO}/\.github/workflows/release\.yml@refs/tags/.*$" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${_artifact}" || die "cosign bundle verification FAILED — refusing to install (Pitfall 14: fail closed)"
        info "cosign bundle OK"
    else
        printf '\n  WARNING: cosign not found — skipping signature verification.\n'
        printf '  Install cosign for supply-chain assurance:\n'
        printf '    https://docs.sigstore.dev/cosign/system_config/installation/\n\n'
    fi
}

# --------------------------------------------------------------------------- #
# Determine install directory                                                  #
# --------------------------------------------------------------------------- #

install_dir() {
    if [ "$(id -u)" -eq 0 ]; then
        printf '/usr/local/bin'
    else
        printf '%s/.local/bin' "${HOME}"
    fi
}

# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #

main() {
    need_cmd uname
    need_cmd tar

    _os="$(detect_os)"
    _arch="$(detect_arch)"
    _version="$(resolve_version "${VERSION}")"

    # Strip leading 'v' from version for filename template if present.
    _ver_bare="${_version#v}"

    _tarball="${BINARY}_${_ver_bare}_${_os}_${_arch}.tar.gz"
    _sums_file="${BINARY}_${_ver_bare}_checksums.txt"
    _base_url="https://github.com/${REPO}/releases/download/${_version}"

    _tmpdir="$(mktemp -d)"
    # Ensure temp directory is cleaned up on exit.
    # shellcheck disable=SC2064
    trap "rm -rf '${_tmpdir}'" EXIT INT TERM

    info "installing abysslink ${_version} (${_os}/${_arch})"

    info "downloading ${_tarball} …"
    download "${_base_url}/${_tarball}" "${_tmpdir}/${_tarball}"

    info "downloading checksums …"
    download "${_base_url}/${_sums_file}" "${_tmpdir}/${_sums_file}"

    verify_checksum "${_tmpdir}/${_tarball}" "${_tmpdir}/${_sums_file}"

    # Download the cosign v3 bundle unconditionally (it is always published) and
    # verify it. Fails CLOSED when cosign is present and verification fails; warns
    # (but continues — checksum already verified) when cosign is absent.
    _bundle_file="${_sums_file}.bundle"
    info "downloading cosign bundle ..."
    download "${_base_url}/${_bundle_file}" "${_tmpdir}/${_bundle_file}"
    verify_cosign_bundle \
        "${_tmpdir}/${_sums_file}" \
        "${_tmpdir}/${_bundle_file}"

    info "extracting ${_tarball} …"
    tar -xzf "${_tmpdir}/${_tarball}" -C "${_tmpdir}"

    _dest_dir="$(install_dir)"
    mkdir -p "${_dest_dir}"

    info "installing ${BINARY} to ${_dest_dir}/ …"
    install -m 755 "${_tmpdir}/${BINARY}" "${_dest_dir}/${BINARY}"

    # Verify the installed binary runs (fail closed: a binary that cannot
    # execute — wrong arch, corrupt extraction, missing loader — must not be
    # reported as a successful install).
    if ! "${_dest_dir}/${BINARY}" version >/dev/null 2>&1; then
        die "installed binary failed to run — installation is broken"
    fi

    info "abysslink ${_version} installed to ${_dest_dir}/${BINARY}"

    # Advise PATH update if ~/.local/bin might not be on PATH.
    case ":${PATH}:" in
        *":${_dest_dir}:"*) ;;
        *)
            printf '\n  Add %s to your PATH:\n' "${_dest_dir}"
            # shellcheck disable=SC2016
            printf '    export PATH="%s:$PATH"\n\n' "${_dest_dir}"
            ;;
    esac
}

main "$@"
