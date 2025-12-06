# MsQuic Development Guide

MsQuic is Microsoft's cross-platform IETF QUIC protocol implementation, written in C with platform abstraction layers for Windows, Linux, macOS, and FreeBSD.

## Architecture Overview

**Two-Layer Design:**
- **Core Implementation** (`src/core/`): Contains the core implementation of the QUIC protocol - platform-independent logic for connections, streams, packet processing, congestion control, etc.
- **Platform Abstraction Library** (`src/platform/`): Provides cross-platform abstractions for OS-specific functionality like TLS, UDP sockets, threading, crypto, and memory management

**Platform Abstraction Naming:**
- Functions prefixed with `CxPlat*` (e.g., `CxPlatEventSet`, `CxPlatSocketSend`)
- Types prefixed with `CXPLAT_*` (e.g., `CXPLAT_EVENT`, `CXPLAT_SOCKET`)

**Key Core Components:**
- `binding.c/h`: UDP socket binding and packet routing to connections
- `connection.c/h`: QUIC connection state machine and lifecycle
- `library.c/h`: Global state, initialization, and handle management
- `listener.c/h`: Server-side connection acceptance and ALPN matching
- `stream.c/h`: QUIC stream implementation with flow control
- `worker.c/h`: Execution context and operation processing

## Build System

**Primary Build Tool:** PowerShell scripts (cross-platform)
```powershell
.\scripts\build.ps1                    # Default build (Debug config, platform TLS)
.\scripts\build.ps1 -Config Release    # Release build
.\scripts\build.ps1 -Tls openssl       # Force OpenSSL instead of platform default
.\scripts\test.ps1                     # Run all tests
.\scripts\test.ps1 -LogProfile Full.Light  # With logging
```

**Default TLS Libraries:**
- Windows: Schannel (built-in)
- POSIX without OpenSSL 3.5+: QuicTLS (fork of OpenSSL)
- POSIX with OpenSSL 3.5+: OpenSSL

**CMake Variables:**
- `QUIC_TLS_LIB`: Choose TLS provider (schannel/openssl)
- `QUIC_BUILD_TEST`: Enable test projects
- `QUIC_ENABLE_LOGGING`: Enable ETW/LTTng tracing

## Coding Patterns

**Handle Types:** All API objects inherit from `QUIC_HANDLE` with typed handles:
```c
typedef struct QUIC_REGISTRATION {
    QUIC_HANDLE Handle;  // Must be first member
    // ... implementation fields
} QUIC_REGISTRATION;
```

**Reference Counting:** Objects use `QuicFooAddRef/Release` patterns with specific ref types:
```c
QuicConnAddRef(Connection, QUIC_CONN_REF_HANDLE_OWNER);
QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);
```

**Platform Abstraction:** Use `CxPlat` prefixed APIs for all OS operations:
```c
CxPlatDispatchLockAcquire(&Lock);
CxPlatEventSet(&Event);
CxPlatSocketSend(Socket, Route, SendData);
```

**Event-Driven Operations:** Core uses operation queuing pattern:
```c
QUIC_OPERATION* Oper = QuicOperationAlloc(Worker, QUIC_OPER_TYPE_...);
QuicWorkerQueueOperation(Worker, Oper);
```

## Testing Framework

**Test Structure:**
- `src/test/lib/`: Reusable test helper classes (`TestConnection`, `TestStream`, `TestListener`)
- `src/test/bin/`: Functional tests using helper classes
- Tests use C++ wrappers around C API for convenience

**Key Test Patterns:**
```cpp
TestConnection Client(Registration);
TEST_QUIC_SUCCEEDED(Client.Start(ClientConfiguration, ...));
TEST_TRUE(Client.WaitForConnectionComplete());
```

**Memory Management:** Tests often use RAII patterns with auto-cleanup callbacks:
```cpp
auto Stream = TestStream::FromConnectionHandle(Connection, AutoCleanupCallback, Flags);
```

## Diagnostic Tools

**Logging System:**
- Windows: ETW tracing via `netsh trace start provider=Microsoft-Quic-MsQuic`
  - Tests run without Administrator privileges, but logging collection requires Administrator
- Linux: LTTng tracing, or compile with `-DQUIC_LOGGING_TYPE=stdout`
- All events defined in `src/manifest/MsQuicEtw.man`

**Performance:** Use `src/tools/secnetperf.exe` for throughput/latency testing

## Multi-Language Support

- **C++ API:** Header-only wrappers in `src/inc/msquic.hpp` (RAII patterns)
- **Rust:** Cargo-based bindings in `src/rs/` 
- **C#:** .NET bindings in `src/cs/`

## Critical Conventions

- All public APIs are async with callback-based completion
- Memory pools used extensively (`QUIC_POOL_*` tags for debugging)
- Strict IRQL annotations for Windows kernel mode support
- Platform-specific includes via `#ifdef _KERNEL_MODE / _WIN32 / __linux__`
- Connection and stream IDs are 62-bit values (`QUIC_UINT62`)
- Error codes follow `QUIC_STATUS_*` enumeration

## Key Integration Points

- **TLS Integration:** `src/platform/tls_*.c` implements TLS 1.3 integration
- **Datapath:** `src/platform/datapath_*.c` handles UDP socket operations
- **Crypto:** Platform-specific crypto in `src/platform/crypt_*.c`
- **XDP Support:** Raw datapath bypasses kernel stack via `datapath_raw_xdp_*.c`