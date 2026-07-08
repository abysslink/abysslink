#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# Abysslink installer — downloads, verifies, and installs the abysslink CLI
# and the abysslinkd daemon.
#
# NOTE: scripts/install.sh is the canonical source of this script. The
# repository-root install.sh is a byte-identical copy kept only so the
#   curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | sh
# one-liner works. Edit scripts/install.sh first, then copy it over the
# root install.sh.
#
# Usage: curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | sh
#        ABYSSLINK_VERSION=v0.1.0 sh install.sh
#
# Environment:
#   ABYSSLINK_VERSION=vX.Y.Z      pin a release (default: latest)
#   ABYSSLINK_REQUIRE_COSIGN=1    fail closed when cosign is not installed
#
# Requirements: curl or wget, sha256sum or shasum, tar.
# Optional:     cosign (for signature verification).
set -e

REPO="abysslink/abysslink"
BINARY="abysslink"
DAEMON="abysslinkd"
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

# Best-effort download: returns non-zero (does NOT die) when the URL is absent.
# Used for optional assets like the cosign bundle, which older releases predate.
try_download() {
    _url="$1"
    _dest="$2"
    if have_cmd curl; then
        curl -fsSL -o "${_dest}" "${_url}" 2>/dev/null
    elif have_cmd wget; then
        wget -qO "${_dest}" "${_url}" 2>/dev/null
    else
        die "curl or wget is required"
    fi
}

# When a pinned release's tarball 404s, tell the user WHY if we can: the tag
# may not exist, or the release may still be an unpublished draft (draft
# assets are not publicly downloadable). Purely advisory — the caller still
# dies with the download error.
release_status_hint() {
    _tag="$1"
    _tagapi="https://api.github.com/repos/${REPO}/releases/tags/${_tag}"
    have_cmd curl || return 0
    _code="$(curl -s -o /dev/null -w '%{http_code}' "${_tagapi}" 2>/dev/null)" || return 0
    if [ "${_code}" = "404" ]; then
        printf 'note: release %s was not found on GitHub — it may not exist, or it may\n' "${_tag}" >&2
        printf '      still be an unpublished draft (draft assets are not downloadable).\n' >&2
        printf '      Published releases: https://github.com/%s/releases\n' "${REPO}" >&2
    fi
}

# Releases from v4.0.1 on are cut through the gated release workflow, which
# guarantees the cosign bundle is uploaded BEFORE the release is published —
# so for those versions a missing bundle means a spoofed or tampered download
# location, and the installer fails closed. Older releases (e.g. v1.0.0)
# predate bundle signing and keep the warn-and-continue path.
bundle_required() {
    _v="$1"                 # bare version, e.g. 4.0.1 or 4.0.1-rc.1
    _core="${_v%%-*}"       # strip any prerelease suffix
    _maj="${_core%%.*}"
    _rest="${_core#*.}"
    _min="${_rest%%.*}"
    _pat="${_rest#*.}"
    # Unparseable version strings fail closed (bundle required).
    case "${_maj}" in '' | *[!0-9]*) return 0 ;; esac
    case "${_min}" in '' | *[!0-9]*) return 0 ;; esac
    case "${_pat}" in '' | *[!0-9]*) return 0 ;; esac
    [ "${_maj}" -gt 4 ] && return 0
    [ "${_maj}" -lt 4 ] && return 1
    [ "${_min}" -gt 0 ] && return 0
    [ "${_pat}" -ge 1 ] && return 0
    return 1
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
        # No --offline: it is deprecated in cosign v3 and cannot deliver
        # air-gapped verification for the new bundle format (cosign fetches the
        # Sigstore TUF trusted root over the network either way). The installer
        # is already online, so this is fine, and it stays fail-closed — a bad
        # signature or an unreachable trust root both make cosign exit non-zero.
        cosign verify-blob \
            --bundle "${_bundle}" \
            --certificate-identity-regexp "^https://github\.com/${REPO}/\.github/workflows/release\.yml@refs/tags/.*$" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${_artifact}" || die "cosign bundle verification FAILED — refusing to install (Pitfall 14: fail closed)"
        info "cosign bundle OK"
    else
        if [ "${ABYSSLINK_REQUIRE_COSIGN:-0}" = "1" ]; then
            die "cosign required (ABYSSLINK_REQUIRE_COSIGN=1) but not found — refusing to install (Pitfall 14: fail closed)"
        fi
        printf '\n  WARNING: cosign not found — skipping signature verification.\n'
        printf '  Install cosign for supply-chain assurance:\n'
        printf '    https://docs.sigstore.dev/cosign/system_config/installation/\n'
        printf '  Set ABYSSLINK_REQUIRE_COSIGN=1 to fail closed when cosign is absent.\n\n'
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
    if ! try_download "${_base_url}/${_tarball}" "${_tmpdir}/${_tarball}"; then
        release_status_hint "${_version}"
        die "download failed: ${_base_url}/${_tarball}"
    fi

    info "downloading checksums …"
    download "${_base_url}/${_sums_file}" "${_tmpdir}/${_sums_file}"

    verify_checksum "${_tmpdir}/${_tarball}" "${_tmpdir}/${_sums_file}"

    # The cosign v3 bundle is published for every release cut through the
    # gated release workflow (v4.0.1+), where publish is blocked until the
    # bundle is uploaded — for those versions a missing bundle is FATAL (fail
    # closed). Pre-bundle releases (e.g. v1.0.0) don't carry it, so for them
    # fetch best-effort: when present, verify (fail CLOSED if cosign is
    # installed and verification fails); when absent, warn and continue on the
    # already-verified SHA-256 checksum — UNLESS ABYSSLINK_REQUIRE_COSIGN=1,
    # which makes a missing bundle fatal for any version.
    _bundle_file="${_sums_file}.bundle"
    info "downloading cosign bundle ..."
    if try_download "${_base_url}/${_bundle_file}" "${_tmpdir}/${_bundle_file}"; then
        verify_cosign_bundle \
            "${_tmpdir}/${_sums_file}" \
            "${_tmpdir}/${_bundle_file}"
    else
        if bundle_required "${_ver_bare}"; then
            die "cosign bundle missing for ${_version} — releases from v4.0.1 on always ship one, so this download location cannot be trusted (fail closed)"
        fi
        if [ "${ABYSSLINK_REQUIRE_COSIGN:-0}" = "1" ]; then
            die "cosign bundle not published for ${_version} (ABYSSLINK_REQUIRE_COSIGN=1) — refusing to install (fail closed)"
        fi
        printf '\n  WARNING: no cosign bundle for %s — this release predates bundle signing.\n' "${_version}"
        printf '  The SHA-256 checksum was verified. Signature verification skipped.\n'
        printf '  Pin a newer release (ABYSSLINK_VERSION=vX.Y.Z) or set ABYSSLINK_REQUIRE_COSIGN=1 to fail closed.\n\n'
    fi

    info "extracting ${_tarball} …"
    tar -xzf "${_tmpdir}/${_tarball}" -C "${_tmpdir}"

    _dest_dir="$(install_dir)"
    mkdir -p "${_dest_dir}"

    info "installing ${BINARY} to ${_dest_dir}/ …"
    install -m 755 "${_tmpdir}/${BINARY}" "${_dest_dir}/${BINARY}"

    # Install the abysslinkd daemon alongside the CLI — `abysslink daemon
    # start` expects it next to the CLI or on PATH. Older releases shipped
    # only the CLI in the tarball, so its absence is not an error.
    if [ -f "${_tmpdir}/${DAEMON}" ]; then
        info "installing ${DAEMON} to ${_dest_dir}/ …"
        install -m 755 "${_tmpdir}/${DAEMON}" "${_dest_dir}/${DAEMON}"
    else
        info "${DAEMON} not found in this release archive — skipping (daemon features need a newer release)"
    fi

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
