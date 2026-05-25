#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# openssl-prefix-rename.sh
#
# Generate a symbol-prefix map from one or more static archives and apply it
# via `objcopy --redefine-syms` to produce renamed copies.
#
# Used by `cmake/PrefixOpenSSLArchives.cmake` to namespace-prefix the bundled
# OpenSSL static archives (and any consuming archive's undefined references)
# when `QUIC_OPENSSL_SYMBOL_PREFIX` is set. This lets the resulting binary
# coexist with another copy of OpenSSL loaded into the same process (e.g. a
# system `libcrypto.so.3` pulled in by a transitive dependency) without
# global-symbol collisions.
#
# Modes:
#   gen-syms   PREFIX OUT_SYMS_FILE INPUT_AR [INPUT_AR ...]
#     Extract all defined external globals (nm types T/D/R/B/W/V/C) from the
#     input archives, sort+unique, and emit `<sym> <PREFIX><sym>` lines.
#
#   apply      SYMS_FILE INPUT_AR OUTPUT_AR
#     Copy INPUT_AR to OUTPUT_AR (skipped if same path) and run
#     `objcopy --redefine-syms=SYMS_FILE` on the copy. The rename touches both
#     definitions and undefined references inside the archive's member objects.
#
# Environment overrides (honored for cross-compilation):
#   NM        path to the binutils `nm` matching the target architecture
#             (defaults to `nm`; host BFD multi-target usually works but
#             `${CMAKE_NM}` is the safe choice)
#   OBJCOPY   path to the binutils `objcopy` matching the target architecture
#             (defaults to `objcopy`)

set -euo pipefail

NM=${NM:-nm}
OBJCOPY=${OBJCOPY:-objcopy}

# Surface unusable tools as a clear configuration error instead of a generic
# "no such file or directory" from the underlying exec.
command -v "$NM" >/dev/null 2>&1 || { echo "$0: NM='$NM' not found" >&2; exit 1; }
command -v "$OBJCOPY" >/dev/null 2>&1 || { echo "$0: OBJCOPY='$OBJCOPY' not found" >&2; exit 1; }

usage() {
    cat >&2 <<EOF
usage:
  $0 gen-syms PREFIX OUT_SYMS_FILE INPUT_AR [INPUT_AR ...]
  $0 apply    SYMS_FILE INPUT_AR OUTPUT_AR

env (optional, for cross-compile):
  NM       (default: nm)
  OBJCOPY  (default: objcopy)
EOF
    exit 2
}

cmd=${1:-}
shift || usage

case "$cmd" in
gen-syms)
    [[ $# -ge 3 ]] || usage
    prefix=$1
    out_syms=$2
    shift 2
    # Defined-extern symbol-type filter:
    #   T/D/R/B = text / data / read-only / bss globals
    #   W/V/C   = weak (func / object) and common
    #   I       = STT_GNU_IFUNC (e.g. AES-NI/SHA-NI dispatch resolvers OpenSSL
    #             3.x emits on x86_64); these are externally-visible defined
    #             symbols, so they must end up in the rename map or MsQuic's
    #             undefs to them won't get prefixed and unprefixed OpenSSL
    #             symbols will still leak through the consumer archive.
    # Do NOT pipe nm's stderr to /dev/null: an unreadable archive, a wrong
    # cross-compile nm, or a corrupt input file should surface its real error
    # message in the custom-command log.
    "$NM" --defined-only --extern-only "$@" \
        | awk 'NF==3 && $2 ~ /^[TDRBWVCI]$/ {print $3}' \
        | LC_ALL=C sort -u \
        | awk -v p="$prefix" '{print $1 " " p $1}' \
        > "$out_syms"
    # A 0-line syms file would make `objcopy --redefine-syms` a no-op, leaving
    # the build green with unprefixed symbols. Fail loudly instead.
    [[ -s "$out_syms" ]] || {
        echo "$0: gen-syms produced an empty syms file from: $*" >&2
        echo "$0: (check that nm '$NM' supports the input archives and emits defined-extern globals)" >&2
        exit 1
    }
    ;;

apply)
    [[ $# -eq 3 ]] || usage
    syms=$1
    in_ar=$2
    out_ar=$3
    if [[ "$(readlink -f -- "$in_ar")" != "$(readlink -f -- "$out_ar")" ]]; then
        # Tmp-file + atomic rename so an interrupted run does not leave a
        # fresh-mtime, partially-renamed (or un-renamed) archive at out_ar
        # that the next build would mistake for up-to-date.
        tmp="${out_ar}.tmp.$$"
        trap 'rm -f -- "$tmp"' EXIT
        cp -- "$in_ar" "$tmp"
        "$OBJCOPY" --redefine-syms="$syms" "$tmp"
        mv -- "$tmp" "$out_ar"
        trap - EXIT
    else
        # In-place rename on the same path. No atomic-rename protection is
        # possible here (callers that need crash-safety should pass a distinct
        # out_ar). Used by the POST_BUILD step on libmsquic_platform.a.
        "$OBJCOPY" --redefine-syms="$syms" "$out_ar"
    fi
    ;;

*)
    usage
    ;;
esac
