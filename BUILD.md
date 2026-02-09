# Building MsQuic (Bash / Make)

This guide covers building, testing, and collecting code coverage for MsQuic
using the bash-based build system. **No PowerShell required.**

For the legacy PowerShell-based instructions, see [docs/BUILD.md](docs/BUILD.md).

## Prerequisites

- **CMake** ≥ 3.16 (≥ 3.20 on Windows)
- **C/C++ compiler** — GCC or Clang on Linux/macOS, MSVC on Windows
- **Git** — with submodules initialized

Clone the repo and initialize submodules:

```sh
git clone --recurse-submodules https://github.com/microsoft/msquic.git
cd msquic
```

For existing clones:

```sh
git submodule update --init --recursive
```

### Linux (Ubuntu/Debian)

```sh
sudo apt-get install -y cmake build-essential liblttng-ust-dev libssl-dev
```

### macOS

```sh
brew install cmake openssl
```

### Windows (MSYS2)

Install [MSYS2](https://www.msys2.org/), then from an MSYS2 terminal:

```sh
pacman -S cmake gcc make
```

For Visual Studio builds, run from a **Developer Command Prompt** or ensure
`cl.exe` is on your `PATH`.

---

## Quick Start

```sh
# Debug build (auto-detects platform, architecture, TLS library)
make

# Release build with 8 parallel jobs
make CONFIG=Release PARALLEL=8

# Run tests
make test
```

---

## Building

### Using Make

| Command | Description |
|---|---|
| `make` | Debug build with defaults |
| `make CONFIG=Release` | Release build |
| `make PARALLEL=4` | Build with 4 parallel jobs |
| `make TLS=openssl` | Force OpenSSL TLS backend |
| `make ARCH=arm64` | Cross-compile for arm64 |
| `make configure` | CMake configure only (no build) |
| `make clean` | Remove build and artifact directories |

Variables can be combined: `make CONFIG=Release TLS=openssl PARALLEL=8`

### Using build.sh Directly

For full control over all options, call `build.sh` directly:

```sh
# Basic debug build
./scripts/build.sh

# Release build with OpenSSL
./scripts/build.sh --config Release --tls openssl

# Parallel build
./scripts/build.sh --parallel 8

# Configure only (no compilation)
./scripts/build.sh --configure-only

# Clean build
./scripts/build.sh --clean

# Static library instead of shared
./scripts/build.sh --static

# With address sanitizer
./scripts/build.sh --sanitize-address

# With thread sanitizer
./scripts/build.sh --sanitize-thread

# Use Clang instead of GCC
./scripts/build.sh --clang

# Cross-compile for arm64
./scripts/build.sh --arch arm64 --sysroot /path/to/sysroot
```

Run `./scripts/build.sh --help` for the full list of options.

### Build Output

Artifacts are placed in:

```
artifacts/bin/<platform>/<arch>_<config>_<tls>/
```

For example, a default Linux debug build produces:

```
artifacts/bin/linux/x64_Debug_openssl/
├── libmsquic.so -> libmsquic.so.2
├── libmsquic.so.2 -> libmsquic.so.2.6.0
├── libmsquic.so.2.6.0
├── msquictest
├── msquiccoretest
├── msquicplatformtest
├── secnetperf
└── ...
```

---

## Testing

### Using Make

```sh
# Build and run all tests
make test

# With specific config
make test CONFIG=Release
```

### Using test.sh Directly

```sh
# Run all tests
./scripts/test.sh

# Filter tests by name
./scripts/test.sh --filter 'ParameterValidation*'

# List available test cases
./scripts/test.sh --list-test-cases

# Run tests in batch mode (single process)
./scripts/test.sh --isolation-mode Batch

# Run under gdb
./scripts/test.sh --debugger

# Break on failure
./scripts/test.sh --break-on-failure

# Multiple iterations (useful for catching flaky tests)
./scripts/test.sh --num-iterations 5
```

Run `./scripts/test.sh --help` for the full list of options.

---

## Code Coverage

Code coverage uses `gcov` (compile-time instrumentation) and `gcovr` (report
generation). This is supported on **Linux only**.

### 1. Install gcovr

```sh
pip install gcovr
```

### 2. Build with Coverage

```sh
./scripts/build.sh --code-coverage
```

This passes `--coverage` to the C/C++ compiler flags, which instruments the
binary to write `.gcda` profiling data at runtime.

### 3. Run Tests

```sh
./scripts/test.sh --code-coverage
```

After tests complete, `gcovr` automatically runs and produces a Cobertura XML
report at:

```
artifacts/coverage/msquiccoverage.xml
```

### Clang Builds

If you built with Clang, pass `--clang` so that `gcovr` uses `llvm-cov gcov`
instead of `gcov`:

```sh
./scripts/build.sh --code-coverage --clang
./scripts/test.sh --code-coverage --clang
```

### Coverage for Specific Tests

You can combine `--code-coverage` with `--filter` to get coverage for a subset
of tests:

```sh
./scripts/test.sh --code-coverage --filter 'HandshakeTest*'
```

---

## TLS Libraries

MsQuic supports multiple TLS backends:

| Value | Description | Default on |
|---|---|---|
| `schannel` | Windows built-in TLS | Windows |
| `quictls` | QuicTLS (OpenSSL fork with QUIC support) | Linux (OpenSSL < 3.5) |
| `openssl` | System OpenSSL ≥ 3.5 | Linux (OpenSSL ≥ 3.5) |

The build system auto-detects the best TLS library for your platform. Override
with `--tls`:

```sh
./scripts/build.sh --tls quictls
```

---

## Common Build Options Reference

| Flag | Description |
|---|---|
| `--config <Debug\|Release>` | Build configuration (default: Debug) |
| `--arch <x64\|arm64\|arm\|x86>` | Target architecture (default: host) |
| `--tls <schannel\|quictls\|openssl>` | TLS library (default: auto) |
| `--parallel [N]` | Parallel build (N jobs, or all cores) |
| `--clean` | Remove previous build before building |
| `--static` | Build static library |
| `--clang` | Use Clang compiler |
| `--sanitize-address` | Enable AddressSanitizer |
| `--sanitize-thread` | Enable ThreadSanitizer |
| `--code-coverage` | Enable gcov instrumentation (Linux) |
| `--disable-test` | Skip building tests |
| `--disable-tools` | Skip building tools |
| `--disable-perf` | Skip building perf tools |
| `--disable-logs` | Disable logging/tracing |
| `--configure-only` | Run CMake configure without building |
