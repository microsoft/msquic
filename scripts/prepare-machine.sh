#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Installs build and test dependencies for MsQuic on Linux/macOS.
# Bash replacement for prepare-machine.ps1.
#
# Usage:
#   sudo ./scripts/prepare-machine.sh [options]
#
# Examples:
#   sudo ./scripts/prepare-machine.sh                    # Default: --for-build --for-test
#   sudo ./scripts/prepare-machine.sh --for-build        # Build deps only
#   sudo ./scripts/prepare-machine.sh --for-test         # Test deps only
#   sudo ./scripts/prepare-machine.sh --use-xdp          # Include XDP deps

set -euo pipefail

##############################################################################
# Defaults
##############################################################################
FOR_BUILD=0
FOR_TEST=0
TLS=""
USE_XDP=0
INSTALL_ARM64_TOOLCHAIN=0
INSTALL_CODE_COVERAGE=0
DISABLE_TEST=0

##############################################################################
# Parse arguments
##############################################################################
while [[ $# -gt 0 ]]; do
    case "$1" in
        --for-build)              FOR_BUILD=1; shift ;;
        --for-test)               FOR_TEST=1; shift ;;
        --tls)                    TLS="$2"; shift 2 ;;
        --use-xdp)                USE_XDP=1; shift ;;
        --install-arm64-toolchain) INSTALL_ARM64_TOOLCHAIN=1; shift ;;
        --install-code-coverage)  INSTALL_CODE_COVERAGE=1; shift ;;
        --disable-test)           DISABLE_TEST=1; shift ;;
        -h|--help)
            echo "Usage: sudo $0 [options]"
            echo "  --for-build               Install build dependencies"
            echo "  --for-test                Install test dependencies"
            echo "  --tls <quictls|openssl>   TLS library to use"
            echo "  --use-xdp                 Install XDP dependencies"
            echo "  --install-arm64-toolchain Install arm64 cross-compilation tools"
            echo "  --install-code-coverage   Install gcovr for code coverage"
            echo "  --disable-test            Skip googletest submodule init"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

##############################################################################
# If no flags given, default to build + test
##############################################################################
if [ "$FOR_BUILD" -eq 0 ] && [ "$FOR_TEST" -eq 0 ]; then
    echo "No arguments passed, defaulting to --for-build and --for-test"
    FOR_BUILD=1
    FOR_TEST=1
fi

##############################################################################
# Detect environment
##############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACTS_DIR="$ROOT_DIR/artifacts"
mkdir -p "$ARTIFACTS_DIR"

OS="$(uname -s)"
IS_LINUX=0; IS_MACOS=0
case "$OS" in
    Linux*)  IS_LINUX=1 ;;
    Darwin*) IS_MACOS=1 ;;
    *) echo "WARNING: Unsupported OS $OS. Some steps may fail." >&2 ;;
esac

# Detect TLS default
if [ -z "$TLS" ]; then
    TLS="quictls"
    if command -v openssl >/dev/null 2>&1; then
        if openssl version 2>/dev/null | grep -qE '^OpenSSL 3\.[5-9]'; then
            TLS="openssl"
        fi
    fi
fi

IS_UBUNTU_2404=0
DISTRO="unknown"
if [ "$IS_LINUX" -eq 1 ] && [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release 2>/dev/null || true
    case "${ID:-}" in
        ubuntu|debian|linuxmint|pop) DISTRO="debian" ;;
        arch|manjaro|endeavouros)    DISTRO="arch" ;;
        fedora|rhel|centos|rocky)    DISTRO="fedora" ;;
        *)                           DISTRO="unknown" ;;
    esac
    grep -q "24.04" /etc/os-release 2>/dev/null && IS_UBUNTU_2404=1
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

##############################################################################
# Package manager helpers
##############################################################################
apt_install() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y "$@"
    else
        echo "WARNING: apt-get not available. Please install manually: $*" >&2
    fi
}

pacman_install() {
    if command -v pacman >/dev/null 2>&1; then
        pacman -S --needed --noconfirm "$@"
    else
        echo "WARNING: pacman not available. Please install manually: $*" >&2
    fi
}

dnf_install() {
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y "$@"
    else
        echo "WARNING: dnf not available. Please install manually: $*" >&2
    fi
}

brew_install() {
    if command -v brew >/dev/null 2>&1; then
        brew install "$@" 2>/dev/null || true
    else
        echo "WARNING: brew not available. Please install manually: $*" >&2
    fi
}

##############################################################################
# Submodule initialization
##############################################################################
init_submodules() {
    log "Initializing clog submodule"
    git -C "$ROOT_DIR" submodule init submodules/clog

    if [ "$TLS" = "quictls" ]; then
        log "Initializing quictls submodule"
        git -C "$ROOT_DIR" submodule init submodules/quictls
    fi

    if [ "$TLS" = "openssl" ]; then
        log "Initializing openssl submodule"
        git -C "$ROOT_DIR" submodule init submodules/openssl
    fi

    if [ "$DISABLE_TEST" -eq 0 ]; then
        log "Initializing googletest submodule"
        git -C "$ROOT_DIR" submodule init submodules/googletest
    fi

    log "Updating submodules"
    git -C "$ROOT_DIR" submodule update --jobs=8
}

##############################################################################
# Linux build dependencies
##############################################################################
install_linux_build_deps() {
    log "Installing Linux build dependencies ($DISTRO)"

    if [ "$DISTRO" = "arch" ]; then
        install_arch_build_deps
    elif [ "$DISTRO" = "fedora" ]; then
        install_fedora_build_deps
    else
        install_debian_build_deps
    fi

    if [ "$INSTALL_ARM64_TOOLCHAIN" -eq 1 ]; then
        log "Installing arm64 cross-compilation toolchain"
        if [ "$DISTRO" = "arch" ]; then
            pacman_install aarch64-linux-gnu-gcc aarch64-linux-gnu-binutils
        elif [ "$DISTRO" = "fedora" ]; then
            dnf_install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
        else
            apt_install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu g++-aarch64-linux-gnu
        fi
    fi

    if [ "$USE_XDP" -eq 1 ]; then
        log "Installing XDP dependencies"
        if [ "$DISTRO" = "arch" ]; then
            pacman_install xdp-tools libbpf libpcap libelf clang pkgconf zlib
        elif [ "$DISTRO" = "fedora" ]; then
            dnf_install xdp-tools-devel libbpf-devel libpcap-devel elfutils-libelf-devel clang pkgconf zlib-devel
            dnf_install libnl3-devel || true
        else
            apt_install --no-install-recommends libc6-dev-i386 || true
            if [ "$IS_UBUNTU_2404" -eq 0 ]; then
                apt-add-repository "deb http://mirrors.kernel.org/ubuntu noble main" -y 2>/dev/null || true
                apt-get update -y
            fi
            apt_install libxdp-dev libbpf-dev
            apt_install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev zlib1g-dev zlib1g pkg-config m4 clang libpcap-dev libelf-dev
        fi
    fi
}

install_debian_build_deps() {
    apt-get update -y
    apt_install cmake build-essential liblttng-ust-dev libssl-dev libnuma-dev liburing-dev

    # babeltrace2 (fallback to babeltrace)
    apt_install babeltrace2 || apt_install babeltrace || true

    # Code check tools
    apt_install cppcheck clang-tidy || true

    # Packaging tools
    apt_install ruby ruby-dev rpm || true
    gem install public_suffix -v 4.0.7 2>/dev/null || true
    gem install fpm 2>/dev/null || true
}

install_arch_build_deps() {
    pacman -Sy --noconfirm
    pacman_install cmake base-devel openssl numactl liburing

    # LTTng (may not be in official repos, skip if unavailable)
    pacman_install lttng-ust 2>/dev/null || log "WARNING: lttng-ust not available on Arch, tracing will be disabled"

    # babeltrace2
    pacman_install babeltrace2 2>/dev/null || true

    # Code check tools
    pacman_install cppcheck clang || true

    # Packaging tools
    pacman_install ruby rpm-tools 2>/dev/null || true
    gem install public_suffix -v 4.0.7 2>/dev/null || true
    gem install fpm 2>/dev/null || true
}

install_fedora_build_deps() {
    dnf install -y 'dnf-command(config-manager)' || true
    dnf_install cmake gcc gcc-c++ make openssl-devel numactl-devel liburing-devel

    # LTTng
    dnf_install lttng-ust-devel || log "WARNING: lttng-ust-devel not available, tracing will be disabled"

    # babeltrace2
    dnf_install babeltrace2 2>/dev/null || true

    # Code check tools
    dnf_install cppcheck clang-tools-extra || true

    # Packaging tools
    dnf_install ruby ruby-devel rpm-build || true
    gem install public_suffix -v 4.0.7 2>/dev/null || true
    gem install fpm 2>/dev/null || true
}
install_linux_test_deps() {
    log "Installing Linux test dependencies ($DISTRO)"

    if [ "$DISTRO" = "arch" ]; then
        install_arch_test_deps
    elif [ "$DISTRO" = "fedora" ]; then
        install_fedora_test_deps
    else
        install_debian_test_deps
    fi

    if [ "$USE_XDP" -eq 1 ]; then
        if [ "$DISTRO" = "arch" ]; then
            pacman_install xdp-tools libbpf libnl iproute2 iptables || true
        elif [ "$DISTRO" = "fedora" ]; then
            dnf_install xdp-tools libbpf libnl3 iproute iptables || true
        else
            if [ "$IS_UBUNTU_2404" -eq 0 ]; then
                apt-add-repository "deb http://mirrors.kernel.org/ubuntu noble main" -y 2>/dev/null || true
                apt-get update -y
            fi
            apt_install libxdp1 libbpf1 || true
            apt_install libnl-3-200 libnl-route-3-200 libnl-genl-3-200 || true
            apt_install iproute2 iptables || true
        fi

        # Install DuoNic
        local duonic_script="$SCRIPT_DIR/duonic.sh"
        if [ -f "$duonic_script" ]; then
            log "Installing DuoNic"
            bash "$duonic_script" install
        fi
    fi

    # Enable core dumps
    log "Configuring core dumps"
    {
        echo 'root soft core unlimited'
        echo 'root hard core unlimited'
        echo '* soft core unlimited'
        echo '* hard core unlimited'
        echo 'root soft nofile 1048576'
        echo 'root hard nofile 1048576'
        echo '* soft nofile 1048576'
        echo '* hard nofile 1048576'
    } >> /etc/security/limits.conf 2>/dev/null || true

    # Set core dump pattern
    log "Setting core dump pattern"
    echo -n '%e.%p.%t.core' > /proc/sys/kernel/core_pattern 2>/dev/null || true
}

install_debian_test_deps() {
    apt-get update -y
    apt_install lttng-tools liblttng-ust-dev gdb liburing2 || true
}

install_arch_test_deps() {
    pacman -Sy --noconfirm
    pacman_install gdb liburing || true
    pacman_install lttng-tools lttng-ust 2>/dev/null || log "WARNING: lttng not available on Arch, tracing disabled"
}

install_fedora_test_deps() {
    dnf_install gdb liburing || true
    dnf_install lttng-tools lttng-ust 2>/dev/null || log "WARNING: lttng not available on Fedora, tracing disabled"
}

##############################################################################
# macOS dependencies
##############################################################################
install_macos_build_deps() {
    log "Installing macOS build dependencies"
    brew_install cmake openssl
}

install_macos_test_deps() {
    log "Configuring macOS test environment"
    sysctl -w kern.corefile=%N.%P.core 2>/dev/null || true
}

##############################################################################
# Test certificates
##############################################################################
install_test_certificates() {
    # Source build config to get artifacts dir
    QUIC_TLS="$TLS"
    export QUIC_TLS
    # shellcheck source=get-buildconfig.sh
    source "$SCRIPT_DIR/get-buildconfig.sh"

    local pfx_file="$QUIC_ARTIFACTS_DIR/selfsignedservercert.pfx"
    mkdir -p "$QUIC_ARTIFACTS_DIR"

    if [ ! -f "$pfx_file" ]; then
        log "Generating test certificates"
        bash "$SCRIPT_DIR/install-test-certificates.sh" "$pfx_file"
    else
        log "Test certificates already exist at $pfx_file"
    fi
}

##############################################################################
# Code coverage tools
##############################################################################
install_code_coverage() {
    if command -v gcovr >/dev/null 2>&1; then
        log "gcovr is already installed"
        return
    fi
    log "Installing gcovr"
    if [ "$DISTRO" = "arch" ]; then
        pacman_install python-pip python-gcovr 2>/dev/null || pip install gcovr || true
    elif [ "$DISTRO" = "fedora" ]; then
        dnf_install python3-gcovr 2>/dev/null || pip3 install gcovr || true
    elif command -v pip3 >/dev/null 2>&1; then
        pip3 install gcovr
    elif command -v pip >/dev/null 2>&1; then
        pip install gcovr
    else
        log "Installing pip first"
        if [ "$IS_LINUX" -eq 1 ]; then
            apt_install python3-pip
        elif [ "$IS_MACOS" -eq 1 ]; then
            brew_install python3
        fi
        pip3 install gcovr || pip install gcovr || true
    fi
}

##############################################################################
# Main
##############################################################################

if [ "$FOR_BUILD" -eq 1 ]; then
    if [ "$IS_LINUX" -eq 1 ]; then
        install_linux_build_deps
    elif [ "$IS_MACOS" -eq 1 ]; then
        install_macos_build_deps
    fi
    init_submodules
fi

if [ "$FOR_TEST" -eq 1 ]; then
    if [ "$IS_LINUX" -eq 1 ]; then
        install_linux_test_deps
    elif [ "$IS_MACOS" -eq 1 ]; then
        install_macos_test_deps
    fi
    install_test_certificates
fi

if [ "$INSTALL_CODE_COVERAGE" -eq 1 ]; then
    install_code_coverage
fi

log "Done."
