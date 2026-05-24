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
    "$NM" --defined-only --extern-only "$@" 2>/dev/null \
        | awk 'NF==3 && $2 ~ /^[TDRBWVC]$/ {print $3}' \
        | LC_ALL=C sort -u \
        | awk -v p="$prefix" '{print $1 " " p $1}' \
        > "$out_syms"
    ;;

apply)
    [[ $# -eq 3 ]] || usage
    syms=$1
    in_ar=$2
    out_ar=$3
    if [[ "$(readlink -f -- "$in_ar")" != "$(readlink -f -- "$out_ar")" ]]; then
        cp -- "$in_ar" "$out_ar"
    fi
    "$OBJCOPY" --redefine-syms="$syms" "$out_ar"
    ;;

*)
    usage
    ;;
esac
