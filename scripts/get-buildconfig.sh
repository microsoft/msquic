#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Helper script that detects platform, architecture, TLS library, and computes
# the artifacts directory path.  Intended to be *sourced* by other scripts:
#
#   source "$(dirname "$0")/get-buildconfig.sh"
#
# After sourcing the following variables are exported:
#   QUIC_PLATFORM  – windows | linux | macos
#   QUIC_ARCH      – x64 | arm64 | arm | x86
#   QUIC_TLS       – schannel | quictls | openssl
#   QUIC_CONFIG    – Debug | Release  (pass-through, default Debug)
#   QUIC_ARTIFACTS_DIR – full path to the artifact output directory

set -euo pipefail

# ── Inputs (may be set by caller before sourcing) ───────────────────────────
QUIC_CONFIG="${QUIC_CONFIG:-Debug}"
QUIC_ARCH="${QUIC_ARCH:-}"
QUIC_PLATFORM="${QUIC_PLATFORM:-}"
QUIC_TLS="${QUIC_TLS:-}"
QUIC_EXTRA_ARTIFACT_DIR="${QUIC_EXTRA_ARTIFACT_DIR:-}"

# ── Root of the repository ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Detect platform ────────────────────────────────────────────────────────
if [ -z "$QUIC_PLATFORM" ]; then
    case "$(uname -s)" in
        Linux*)   QUIC_PLATFORM="linux"  ;;
        Darwin*)  QUIC_PLATFORM="macos"  ;;
        CYGWIN*|MINGW*|MSYS*) QUIC_PLATFORM="windows" ;;
        *)        echo "ERROR: unsupported OS $(uname -s)" >&2; exit 1 ;;
    esac
fi

# ── Detect architecture ────────────────────────────────────────────────────
if [ -z "$QUIC_ARCH" ]; then
    case "$(uname -m)" in
        x86_64|amd64)  QUIC_ARCH="x64"   ;;
        aarch64|arm64) QUIC_ARCH="arm64"  ;;
        armv7l|armhf)  QUIC_ARCH="arm"    ;;
        i?86)          QUIC_ARCH="x86"    ;;
        *)
            # macOS Rosetta: uname reports x86_64, but we might be on arm64
            if [ "$QUIC_PLATFORM" = "macos" ] && [ "$(uname -m)" = "x86_64" ]; then
                if sysctl -in sysctl.proc_translated 2>/dev/null | grep -q 1; then
                    QUIC_ARCH="arm64"
                else
                    QUIC_ARCH="x64"
                fi
            else
                echo "ERROR: unknown architecture $(uname -m)" >&2; exit 1
            fi
            ;;
    esac
fi

# ── Detect TLS library ─────────────────────────────────────────────────────
if [ -z "$QUIC_TLS" ]; then
    if [ "$QUIC_PLATFORM" = "windows" ]; then
        QUIC_TLS="schannel"
    else
        # Default to quictls; upgrade to openssl if system OpenSSL >= 3.5
        QUIC_TLS="quictls"
        if command -v openssl >/dev/null 2>&1; then
            _ssl_ver="$(openssl version 2>/dev/null || true)"
            if echo "$_ssl_ver" | grep -qE '^OpenSSL 3\.[5-9]'; then
                QUIC_TLS="openssl"
            fi
        fi
    fi
fi

# ── Compute artifacts directory ─────────────────────────────────────────────
QUIC_ARTIFACTS_DIR="${ROOT_DIR}/artifacts/bin/${QUIC_PLATFORM}"
if [ -n "$QUIC_EXTRA_ARTIFACT_DIR" ]; then
    QUIC_ARTIFACTS_DIR="${QUIC_ARTIFACTS_DIR}/${QUIC_ARCH}_${QUIC_CONFIG}_${QUIC_TLS}_${QUIC_EXTRA_ARTIFACT_DIR}"
else
    QUIC_ARTIFACTS_DIR="${QUIC_ARTIFACTS_DIR}/${QUIC_ARCH}_${QUIC_CONFIG}_${QUIC_TLS}"
fi

export QUIC_PLATFORM QUIC_ARCH QUIC_TLS QUIC_CONFIG QUIC_ARTIFACTS_DIR ROOT_DIR
