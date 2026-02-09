#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Build script for MsQuic – bash replacement for build.ps1.
#
# Usage:
#   ./scripts/build.sh [options]
#
# Examples:
#   ./scripts/build.sh                          # Debug build, platform defaults
#   ./scripts/build.sh --config Release         # Release build
#   ./scripts/build.sh --tls openssl            # Force OpenSSL
#   ./scripts/build.sh --clean --parallel       # Clean + parallel build
#   ./scripts/build.sh --config Release --arch arm64 --sysroot /path/to/sysroot

set -euo pipefail

##############################################################################
# Defaults
##############################################################################
CONFIG="Debug"
ARCH=""
PLATFORM=""
TLS=""
STATIC=0
DISABLE_LOGS=0
LOGGING_TYPE=""
SANITIZE_ADDRESS=0
SANITIZE_THREAD=0
CODE_CHECK=0
DISABLE_TOOLS=0
DISABLE_TEST=0
DISABLE_PERF=0
CLEAN=0
PARALLEL=""
DYNAMIC_CRT=0
STATIC_CRT=0
PGO=0
USE_XDP=0
USE_IOURING=0
GENERATOR=""
SKIP_PDB_ALT_PATH=0
SKIP_SOURCE_LINK=0
CLANG=0
UPDATE_CLOG=0
CONFIGURE_ONLY=0
CI=0
OFFICIAL_RELEASE=0
FORCE_OFFICIAL_RELEASE=0
ENABLE_TELEMETRY_ASSERTS=1
USE_SYSTEM_OPENSSL_CRYPTO=0
ENABLE_HIGH_RES_TIMERS=0
EXTRA_ARTIFACT_DIR=""
LIBRARY_NAME="msquic"
SYSROOT="/"
ONEBRANCH=0
TOOLCHAIN_FILE=""
CODE_COVERAGE=0

##############################################################################
# Parse arguments
##############################################################################
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)               CONFIG="$2"; shift 2 ;;
        --arch)                 ARCH="$2"; shift 2 ;;
        --platform)             PLATFORM="$2"; shift 2 ;;
        --tls)                  TLS="$2"; shift 2 ;;
        --static)               STATIC=1; shift ;;
        --disable-logs)         DISABLE_LOGS=1; shift ;;
        --logging-type)         LOGGING_TYPE="$2"; shift 2 ;;
        --sanitize-address)     SANITIZE_ADDRESS=1; shift ;;
        --sanitize-thread)      SANITIZE_THREAD=1; shift ;;
        --code-check)           CODE_CHECK=1; shift ;;
        --disable-tools)        DISABLE_TOOLS=1; shift ;;
        --disable-test)         DISABLE_TEST=1; shift ;;
        --disable-perf)         DISABLE_PERF=1; shift ;;
        --clean)                CLEAN=1; shift ;;
        --parallel)
            if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                PARALLEL="$2"; shift 2
            else
                PARALLEL="0"; shift
            fi ;;

        --dynamic-crt)          DYNAMIC_CRT=1; shift ;;
        --static-crt)           STATIC_CRT=1; shift ;;
        --pgo)                  PGO=1; shift ;;
        --use-xdp)              USE_XDP=1; shift ;;
        --use-iouring)          USE_IOURING=1; shift ;;
        --generator)            GENERATOR="$2"; shift 2 ;;
        --skip-pdb-alt-path)    SKIP_PDB_ALT_PATH=1; shift ;;
        --skip-source-link)     SKIP_SOURCE_LINK=1; shift ;;
        --clang)                CLANG=1; shift ;;
        --update-clog)          UPDATE_CLOG=1; shift ;;
        --configure-only)       CONFIGURE_ONLY=1; shift ;;
        --ci)                   CI=1; shift ;;
        --official-release)     OFFICIAL_RELEASE=1; shift ;;
        --force-official-release) FORCE_OFFICIAL_RELEASE=1; shift ;;
        --no-telemetry-asserts) ENABLE_TELEMETRY_ASSERTS=0; shift ;;
        --use-system-openssl-crypto) USE_SYSTEM_OPENSSL_CRYPTO=1; shift ;;
        --enable-high-res-timers) ENABLE_HIGH_RES_TIMERS=1; shift ;;
        --extra-artifact-dir)   EXTRA_ARTIFACT_DIR="$2"; shift 2 ;;
        --library-name)         LIBRARY_NAME="$2"; shift 2 ;;
        --sysroot)              SYSROOT="$2"; shift 2 ;;
        --onebranch)            ONEBRANCH=1; shift ;;
        --toolchain-file)       TOOLCHAIN_FILE="$2"; shift 2 ;;
        --code-coverage)        CODE_COVERAGE=1; shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^[^#]/p' "$0" | head -n -1
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

##############################################################################
# Source build-config helper
##############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

QUIC_CONFIG="$CONFIG"
QUIC_ARCH="$ARCH"
QUIC_PLATFORM="$PLATFORM"
QUIC_TLS="$TLS"
QUIC_EXTRA_ARTIFACT_DIR="$EXTRA_ARTIFACT_DIR"
export QUIC_CONFIG QUIC_ARCH QUIC_PLATFORM QUIC_TLS QUIC_EXTRA_ARTIFACT_DIR

# shellcheck source=get-buildconfig.sh
source "${SCRIPT_DIR}/get-buildconfig.sh"

# Re-capture resolved values
PLATFORM="$QUIC_PLATFORM"
TLS="$QUIC_TLS"
ARCH="$QUIC_ARCH"
ARTIFACTS_DIR="$QUIC_ARTIFACTS_DIR"

##############################################################################
# Validation
##############################################################################
if [ "$PLATFORM" = "uwp" ] && [ "$PLATFORM" != "windows" ]; then
    echo "ERROR: Cannot build UWP on non-Windows platforms" >&2; exit 1
fi
if [ "$PLATFORM" = "gamecore_console" ] && [ "$PLATFORM" != "windows" ]; then
    echo "ERROR: Cannot build GameCore on non-Windows platforms" >&2; exit 1
fi
if [ "$ARCH" = "arm64ec" ] && [ "$PLATFORM" != "windows" ]; then
    echo "ERROR: arm64ec is only supported on Windows" >&2; exit 1
fi
if [ "$PLATFORM" = "linux" ] && [ "$ARCH" != "x64" ] && [ "$USE_XDP" -eq 1 ]; then
    echo "ERROR: Linux XDP is only supported on x64" >&2; exit 1
fi
if [ "$PLATFORM" = "ios" ] && [ "$STATIC" -eq 0 ]; then
    STATIC=1; echo "iOS can only be built as static"
fi

##############################################################################
# Generator defaults
##############################################################################
if [ -z "$GENERATOR" ]; then
    if [ "$PLATFORM" = "windows" ]; then
        GENERATOR="Visual Studio 17 2022"
    else
        GENERATOR="Unix Makefiles"
    fi
fi

##############################################################################
# Official release check
##############################################################################
if [ "$OFFICIAL_RELEASE" -eq 1 ]; then
    OFFICIAL_RELEASE=0
    if git describe --exact-match --tags "$(git log -n1 --pretty='%h')" 2>/dev/null | grep -qv "fatal:"; then
        echo "Configuring OfficialRelease for tag build"
        OFFICIAL_RELEASE=1
    fi
fi
if [ "$FORCE_OFFICIAL_RELEASE" -eq 1 ]; then
    OFFICIAL_RELEASE=1
fi

##############################################################################
# Directories
##############################################################################
BUILD_DIR="${ROOT_DIR}/build/${PLATFORM}/${ARCH}_${TLS}"

if [ "$CLEAN" -eq 1 ]; then
    # Remove build outputs but preserve test certificates (*.pfx)
    find "$ARTIFACTS_DIR" -mindepth 1 ! -name '*.pfx' -delete 2>/dev/null || true
    rm -rf "$BUILD_DIR"
fi
mkdir -p "${ROOT_DIR}/artifacts" "$BUILD_DIR"

##############################################################################
# Compiler selection
##############################################################################
if [ "$CLANG" -eq 1 ]; then
    if [ "$PLATFORM" = "windows" ]; then
        echo "ERROR: Clang is not supported on Windows currently" >&2; exit 1
    fi
    export CC=clang CXX=clang++
fi

# Workaround for perl quictls build warnings.
export TERM="${TERM:-ansi}"

##############################################################################
# Helpers
##############################################################################
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

cmake_execute() {
    log "cmake $*"
    cmake "$@"
    log "cmake exited successfully"
}

##############################################################################
# CMake Generate
##############################################################################
cmake_generate() {
    local args=()

    # Generator
    if [ "$PLATFORM" = "windows" ]; then
        if echo "$GENERATOR" | grep -q "Visual Studio"; then
            args+=(-G "$GENERATOR")
            case "$ARCH" in
                x86)      args+=(-A Win32)   ;;
                x64)      args+=(-A x64)     ;;
                arm)      args+=(-A arm)     ;;
                arm64)    args+=(-A arm64)   ;;
                arm64ec)  args+=(-A arm64ec) ;;
            esac
        else
            echo "Non-VS generators must be run from a Visual Studio Developer prompt matching the target architecture"
            args+=(-G "$GENERATOR")
        fi
    else
        args+=(-G "$GENERATOR")
    fi

    # iOS
    if [ "$PLATFORM" = "ios" ]; then
        local ios_tc="${ROOT_DIR}/cmake/toolchains/ios.cmake"
        args+=(-DCMAKE_TOOLCHAIN_FILE="$ios_tc" -DDEPLOYMENT_TARGET=13.0 -DENABLE_ARC=0 -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0)
        case "$ARCH" in
            x64)   args+=(-DPLATFORM=SIMULATOR64) ;;
            arm64) args+=(-DPLATFORM=OS64) ;;
        esac
    fi

    # macOS
    if [ "$PLATFORM" = "macos" ]; then
        case "$ARCH" in
            x64)   args+=(-DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_OSX_DEPLOYMENT_TARGET=13) ;;
            arm64) args+=(-DCMAKE_OSX_ARCHITECTURES=arm64  -DCMAKE_OSX_DEPLOYMENT_TARGET=13) ;;
        esac
    fi

    # Linux cross-compilation
    if [ "$PLATFORM" = "linux" ]; then
        local host_arch
        host_arch="$(uname -m)"
        case "$host_arch" in
            x86_64|amd64)  host_arch="x64"   ;;
            aarch64|arm64) host_arch="arm64"  ;;
            armv7l|armhf)  host_arch="arm"    ;;
        esac

        if [ "$host_arch" != "$ARCH" ]; then
            if [ "$ONEBRANCH" -eq 1 ]; then
                args+=(-DONEBRANCH=1)
                if [ -z "$TOOLCHAIN_FILE" ]; then
                    case "$ARCH" in
                        arm)   TOOLCHAIN_FILE="cmake/toolchains/arm-linux.cmake" ;;
                        arm64) TOOLCHAIN_FILE="cmake/toolchains/aarch64-linux.cmake" ;;
                    esac
                fi
            fi
            args+=(-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER -DCMAKE_CROSSCOMPILING=1 "-DCMAKE_SYSROOT=$SYSROOT")
            case "$ARCH" in
                arm64) args+=(-DCMAKE_CXX_COMPILER_TARGET=aarch64-linux-gnu -DCMAKE_C_COMPILER_TARGET=aarch64-linux-gnu -DCMAKE_TARGET_ARCHITECTURE=arm64) ;;
                arm)   args+=(-DCMAKE_CXX_COMPILER_TARGET=arm-linux-gnueabihf -DCMAKE_C_COMPILER_TARGET=arm-linux-gnueabihf -DCMAKE_TARGET_ARCHITECTURE=arm) ;;
            esac
            case "$ARCH" in
                arm)   export PKG_CONFIG_PATH="$SYSROOT/usr/lib/arm-linux-gnueabihf/pkgconfig" ;;
                arm64) export PKG_CONFIG_PATH="$SYSROOT/usr/lib/aarch64-linux-gnu/pkgconfig" ;;
            esac
        fi
    fi

    # Toolchain file
    if [ -n "$TOOLCHAIN_FILE" ]; then
        args+=("-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE")
    fi

    # Shared / static
    if [ "$STATIC" -eq 1 ]; then
        args+=(-DQUIC_BUILD_SHARED=off)
    fi

    # Core CMake vars
    args+=("-DQUIC_TLS_LIB=$TLS")
    args+=("-DQUIC_OUTPUT_DIR=$ARTIFACTS_DIR")

    # Logging
    if [ "$DISABLE_LOGS" -eq 0 ]; then
        args+=(-DQUIC_ENABLE_LOGGING=on)
    fi
    if [ -n "$LOGGING_TYPE" ]; then
        args+=(-DQUIC_ENABLE_LOGGING=on "-DQUIC_LOGGING_TYPE=$LOGGING_TYPE")
    fi

    # Sanitizers
    if [ "$SANITIZE_ADDRESS" -eq 1 ]; then
        args+=(-DQUIC_ENABLE_ALL_SANITIZERS=on)
    fi
    if [ "$SANITIZE_THREAD" -eq 1 ]; then
        args+=(-DQUIC_ENABLE_TSAN=on)
    fi

    # Code checks
    if [ "$CODE_CHECK" -eq 1 ]; then
        args+=(-DQUIC_CODE_CHECK=on)
    fi

    # Build targets
    if [ "$PLATFORM" != "uwp" ] && [ "$PLATFORM" != "gamecore_console" ]; then
        [ "$DISABLE_TOOLS" -eq 0 ] && args+=(-DQUIC_BUILD_TOOLS=on)
        [ "$DISABLE_TEST"  -eq 0 ] && args+=(-DQUIC_BUILD_TEST=on)
        [ "$DISABLE_PERF"  -eq 0 ] && args+=(-DQUIC_BUILD_PERF=on)
    fi

    # Build type (non-Windows multi-config generators)
    if [ "$PLATFORM" != "windows" ]; then
        local build_type="$CONFIG"
        [ "$CONFIG" = "Release" ] && build_type="RelWithDebInfo"
        args+=("-DCMAKE_BUILD_TYPE=$build_type")
    fi

    # Windows CRT linking
    if [ "$PLATFORM" = "windows" ]; then
        if [ "$DYNAMIC_CRT" -eq 1 ]; then
            args+=(-DQUIC_STATIC_LINK_CRT=off -DQUIC_STATIC_LINK_PARTIAL_CRT=off)
        fi
        if [ "$STATIC_CRT" -eq 1 ]; then
            args+=(-DQUIC_STATIC_LINK_CRT=on -DQUIC_STATIC_LINK_PARTIAL_CRT=off)
        fi
    fi

    # PGO
    [ "$PGO"         -eq 1 ] && args+=(-DQUIC_PGO=on)
    [ "$USE_XDP"     -eq 1 ] && args+=(-DQUIC_LINUX_XDP_ENABLED=on)
    [ "$USE_IOURING" -eq 1 ] && args+=(-DQUIC_LINUX_IOURING_ENABLED=on)

    # UWP / GameCore
    if [ "$PLATFORM" = "uwp" ]; then
        args+=(-DCMAKE_SYSTEM_NAME=WindowsStore -DCMAKE_SYSTEM_VERSION=10.0 -DQUIC_UWP_BUILD=on)
    fi
    if [ "$PLATFORM" = "gamecore_console" ]; then
        args+=(-DCMAKE_SYSTEM_VERSION=10.0 -DQUIC_GAMECORE_BUILD=on)
    fi

    # PDB / SourceLink
    [ "$SKIP_PDB_ALT_PATH" -eq 1 ] && args+=(-DQUIC_PDBALTPATH=OFF)
    [ "$SKIP_SOURCE_LINK"  -eq 1 ] && args+=(-DQUIC_SOURCE_LINK=OFF)

    # CI
    if [ "$CI" -eq 1 ]; then
        args+=(-DQUIC_CI=ON)
        if [ "$PLATFORM" = "android" ] || [ -n "$TOOLCHAIN_FILE" ]; then
            args+=(-DQUIC_SKIP_CI_CHECKS=ON)
        fi
        args+=("-DQUIC_VER_BUILD_ID=${BUILD_BUILDID:-0}")
        args+=(-DQUIC_VER_SUFFIX=-official)
    fi

    [ "$OFFICIAL_RELEASE"        -eq 1 ] && args+=(-DQUIC_OFFICIAL_RELEASE=ON)
    [ "$ENABLE_TELEMETRY_ASSERTS" -eq 1 ] && args+=(-DQUIC_TELEMETRY_ASSERTS=on)
    [ "$USE_SYSTEM_OPENSSL_CRYPTO" -eq 1 ] && args+=(-DQUIC_USE_SYSTEM_LIBCRYPTO=on)
    [ "$ENABLE_HIGH_RES_TIMERS"  -eq 1 ] && args+=(-DQUIC_HIGH_RES_TIMERS=on)

    # Code coverage (Linux only, uses gcov)
    if [ "$CODE_COVERAGE" -eq 1 ]; then
        if [ "$PLATFORM" = "linux" ]; then
            args+=("-DCMAKE_C_FLAGS=--coverage" "-DCMAKE_CXX_FLAGS=--coverage")
        else
            echo "WARNING: --code-coverage is only supported on Linux. Ignoring flag." >&2
        fi
    fi

    # Android
    if [ "$PLATFORM" = "android" ]; then
        local ndk="${ANDROID_NDK_LATEST_HOME:-$ANDROID_NDK_HOME}"
        export PATH="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
        export ANDROID_NDK_HOME="$ndk" ANDROID_NDK_ROOT="$ndk"
        case "$ARCH" in
            x86)   args+=(-DANDROID_ABI=x86)          ;;
            x64)   args+=(-DANDROID_ABI=x86_64)       ;;
            arm)   args+=(-DANDROID_ABI=armeabi-v7a)   ;;
            arm64) args+=(-DANDROID_ABI=arm64-v8a)     ;;
        esac
        args+=(-DANDROID_PLATFORM=android-29)
        args+=("-DANDROID_NDK=$ndk")
        args+=("-DCMAKE_TOOLCHAIN_FILE=$ndk/build/cmake/android.toolchain.cmake")
    fi

    args+=("-DQUIC_LIBRARY_NAME=$LIBRARY_NAME")
    args+=("${ROOT_DIR}")

    (cd "$BUILD_DIR" && cmake_execute "${args[@]}")
}

##############################################################################
# CMake Build
##############################################################################
cmake_build() {
    local args=(--build .)

    # Parallel
    if [ -n "$PARALLEL" ]; then
        if [ "$PARALLEL" -gt 0 ] 2>/dev/null; then
            args+=(--parallel "$PARALLEL")
        else
            args+=(--parallel)
        fi
    fi

    # Config for multi-config generators (Windows / VS)
    if [ "$PLATFORM" = "windows" ]; then
        args+=(--config "$CONFIG")
    elif [ "$GENERATOR" = "Unix Makefiles" ] || [ -z "$GENERATOR" ]; then
        args+=(-- VERBOSE=1)
    fi

    (cd "$BUILD_DIR" && cmake_execute "${args[@]}")

    # Post-build: copy .lib on Windows
    if [ "$PLATFORM" = "windows" ]; then
        local lib_file="${BUILD_DIR}/obj/${CONFIG}/${LIBRARY_NAME}.lib"
        [ -f "$lib_file" ] && cp "$lib_file" "$ARTIFACTS_DIR/"
    fi

    # Post-build: tar on OneBranch Linux
    if [ "$PLATFORM" = "linux" ] && [ "$ONEBRANCH" -eq 1 ]; then
        local parent; parent="$(dirname "$ARTIFACTS_DIR")"
        local leaf; leaf="$(basename "$ARTIFACTS_DIR")"
        tar -cvf "${ARTIFACTS_DIR}.tar" -C "$parent" "./$leaf"
    fi

    # Post-build: dsymutil on macOS
    if [ "$PLATFORM" = "macos" ]; then
        for artifact in "$ARTIFACTS_DIR"/*; do
            [ -f "$artifact" ] && dsymutil "$artifact" 2>/dev/null || true
        done
    fi
}

##############################################################################
# Main
##############################################################################
if [ "$UPDATE_CLOG" -eq 1 ]; then
    export CLOG_DEVELOPMENT_MODE=1
fi

log "Generating files..."
cmake_generate

if [ "$CONFIGURE_ONLY" -eq 0 ]; then
    log "Building..."
    cmake_build
fi

log "Done."

if [ "$UPDATE_CLOG" -eq 1 ]; then
    export CLOG_DEVELOPMENT_MODE=0
fi
