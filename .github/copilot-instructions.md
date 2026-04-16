# Copilot Instructions for MsQuic

## Project Overview

MsQuic is Microsoft's cross-platform C implementation of the IETF QUIC protocol. It also has C++ API wrappers and Rust/C# interop layers. The codebase targets Windows (user & kernel mode), Linux, macOS, and FreeBSD. The primary language is C (C17), with C++ (C17) for tests/tools, Rust bindings, and C# interop. Build system: CMake + PowerShell scripts.

## Repository Layout

| Path | Description |
|---|---|
| `src/core/` | Platform-independent QUIC protocol logic (connections, streams, loss detection, congestion control) |
| `src/platform/` | Platform abstraction layer: sockets/datapath, TLS (schannel/openssl), crypto, OS primitives |
| `src/inc/` | Public and internal headers. `msquic.h` is the public C API. `msquic.hpp` is the C++ wrapper. |
| `src/bin/` | Packages static libs into platform-specific shared/static binaries |
| `src/test/lib/` | Test implementations (GoogleTest-based): `ApiTest.cpp`, `HandshakeTest.cpp`, etc. |
| `src/test/bin/` | Test runner executable (`quic_gtest.cpp`) |
| `src/tools/` | Utilities: `sample/`, `spin/`, `attack/`, `interop/`, perf tools (`secnetperf`) |
| `src/perf/` | Performance test library and tools |
| `src/generated/` | Auto-generated CLOG tracing files. **Do not edit manually** — regenerate with `scripts/update-sidecar.ps1` |
| `src/rs/` | Rust bindings (`lib.rs`, `types.rs`, `config.rs`, etc.) |
| `src/cs/` | C# interop layer |
| `src/manifest/` | Windows ETW manifest and CLOG config (`clog.sidecar`, `msquic.clog_config`) |
| `scripts/` | PowerShell build/test/CI scripts (cross-platform via pwsh) |
| `docs/` | Documentation: `BUILD.md`, `TEST.md`, `API.md`, `Architecture.md`, etc. |
| `submodules/` | Git submodules: `googletest`, `quictls`, `openssl`, `clog`, `xdp-for-windows` |
| `cmake/` | CMake helper modules and toolchain files |
| `.github/workflows/` | CI workflows: `build.yml`, `test.yml`, `cargo.yml`, `check-clog.yml`, `check-dotnet.yml` |

Key files: `CMakeLists.txt` (root build), `version.json` (version info), `.clang-format` (C/C++ style), `src/.editorconfig` (editor settings), `Cargo.toml` (Rust crate config), `rust-toolchain.toml` (Rust 1.93.1).

## Building (Windows)

Always use PowerShell 7+ (`pwsh`). All scripts are in `scripts/`.

**Prerequisites**: Visual Studio 2022 with C++ workload, CMake ≥ 3.20, Windows SDK 10.0.26100.0+, .NET SDK (see `global.json`). Submodules must be initialized: `git submodule update --init`.

**First-time setup**:
```powershell
./scripts/prepare-machine.ps1 -ForBuild
```

**Build with schannel** (default on Windows, no extra dependencies):
```powershell
./scripts/build.ps1
```

**Build with openssl/quictls** (requires Perl + NASM installed):
```powershell
./scripts/build.ps1 -Tls openssl
```

Key build flags: `-Config Debug|Release` (default: Debug), `-Arch x86|x64|arm64` (default: x64), `-Tls schannel|openssl|quictls`, `-Clean` (clean rebuild), `-DisableTest`, `-DisableTools`, `-DisablePerf`, `-Static`.

**Build output**: `artifacts/bin/<platform>/<arch>_<config>_<tls>/` for binaries; `build/<platform>/<arch>_<tls>/` for CMake intermediates.

**Important**: Building with `-Tls openssl` on Windows requires Strawberry Perl and NASM. If you get `'perl' is not recognized`, install Perl or use `-Tls schannel` instead.

## Building (Linux)

```bash
pwsh ./scripts/prepare-machine.ps1 -ForBuild
pwsh ./scripts/build.ps1 -Tls openssl
```

## Testing

Build first, then:
```powershell
./scripts/prepare-machine.ps1 -ForTest
./scripts/test.ps1 -Tls schannel         # Windows
./scripts/test.ps1 -Tls openssl          # Linux or Windows+OpenSSL
./scripts/test.ps1 -Filter 'SomeTest.*'  # Run subset via GoogleTest filter
```

Tests are GoogleTest-based. Three test binaries: `msquicplatformtest`, `msquiccoretest`, `msquictest`. Tests should be run in a VM or dedicated machine — some tests require admin/root, test signing, or network configuration.

## Rust

```bash
cargo build                  # Builds C library from source + Rust bindings
cargo test                   # Runs Rust tests
cargo fmt --all -- --check   # Format check (CI enforced)
cargo clippy --all-targets -- -D warnings  # Lint (CI enforced)
```

Rust toolchain version is pinned in `rust-toolchain.toml` (1.93.1).

## CLOG Tracing (Critical for Trace Changes)

If you add or modify trace/log calls (macros like `QuicTraceLogInfo`, `QuicTraceEvent`, etc.), you **must** regenerate the CLOG sidecar:
```powershell
./scripts/update-sidecar.ps1
```
This updates files under `src/generated/`. Commit the regenerated files with your change. The `check-clog.yml` CI workflow validates this — it will fail if generated files are stale.

Similarly, if you change the C API surface (header files in `src/inc/`), run:
```powershell
./scripts/generate-dotnet.ps1
```
The `check-dotnet.yml` CI workflow validates the generated .NET interop files are up to date.

## CI Workflows (Run on Every PR)

| Workflow | What it checks |
|---|---|
| `build.yml` | 200+ build configurations across Windows/Linux/macOS, multiple TLS providers, architectures |
| `test.yml` | BVT (Build Verification Tests) across platforms |
| `cargo.yml` | Rust build, `cargo fmt`, `cargo clippy`, `cargo test`, binding freshness check |
| `check-clog.yml` | CLOG sidecar is up to date (runs `update-sidecar.ps1` and checks for diffs) |
| `check-dotnet.yml` | .NET generated files are up to date (runs `generate-dotnet.ps1` and checks for diffs) |

## Code Style

- **C/C++**: 4-space indent, no tabs, 100-column limit. Braces on next line for functions, same line for control flow. Use `QUIC_` prefix for macros/types. Stay consistent with existing code.
- **Rust**: Standard `rustfmt` formatting. CI enforces `cargo fmt --check`.
- **Editor settings**: See `src/.editorconfig` — 4-space indent, trim trailing whitespace, final newline.
- C++ files use `.cpp`/`.h` extensions. C files use `.c`/`.h`.

## Architecture Notes

- Two main layers: **QUIC** (protocol, in `src/core/`) and **Platform** (OS abstraction, in `src/platform/`).
- Platform layer abstracts: TLS (`tls_schannel.c`, `tls_openssl.c`, `tls_quictls.c`), UDP sockets/datapath (`datapath_win.c`, `datapath_epoll.c`, `datapath_kqueue.c`), crypto (`crypt_bcrypt.c`, `crypt_openssl.c`).
- Public API is in `src/inc/msquic.h`. C++ wrapper in `src/inc/msquic.hpp`.
- Test infrastructure uses GoogleTest. Test cases in `src/test/lib/`, runner in `src/test/bin/`.

## Pull Requests

When creating pull requests, always follow the PR template at `.github/pull_request_template.md`.
If asked to fix a specific issue, mention the issue number in the PR description (e.g. "Fixes #1234").

## Update These Instructions

As you learn the codebase, update this file with any important information you think would help future contributors. This is the primary source of truth for how to work with the codebase, so keep it accurate and comprehensive.

## Trust These Instructions

Follow these instructions as the primary reference. Only search the codebase if the information here is incomplete or found to be incorrect for your specific task.
