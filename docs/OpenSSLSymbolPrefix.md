# OpenSSL Symbol Prefix (`QUIC_OPENSSL_SYMBOL_PREFIX`)

> **Status: Experimental / opt-in.** Linux only. Default off.

## Motivation

When a process links MsQuic statically and also pulls in another copy of
OpenSSL via an unrelated dependency (e.g. a system `libcrypto.so.3` brought in
by a logging library, a database driver, or any C++ library that itself uses
OpenSSL), the two OpenSSL copies share the same global C symbols
(`SSL_CTX_new`, `EVP_*`, `BN_*`, `ERR_*`, the per-module init constructors,
etc.). The dynamic linker resolves every reference to the **first definition
loaded**, so all callers — including MsQuic — silently end up sharing one
OpenSSL's state machine while their headers and ABI assumptions came from the
other. Typical symptoms:

- Crashes in `OPENSSL_init_crypto` / `RAND_load_file` when one OpenSSL's
  per-module init runs against the other's global registries.
- Spurious SSL handshake failures when callbacks installed against one
  `SSL_CTX` see the other's vtable layout.
- ABI mismatches when one OpenSSL is `3.0.x` (system `libcrypto.so.3` on
  Ubuntu 22.04 / RHEL 9) and MsQuic's bundled OpenSSL is `3.5.x` (required for
  `SSL_set_quic_tls_cbs`).

Building MsQuic as a `SHARED` library with `--exclude-libs=ALL` hides the
bundled OpenSSL from the global symbol table, but does not help consumers that
want a single statically-linked binary, and does not address process-level
duplicate-singleton issues if the consumer itself produces a `.so`.

## What this option does

When `QUIC_OPENSSL_SYMBOL_PREFIX=<prefix>` is passed at CMake configure time,
the build:

1. Builds the bundled OpenSSL submodule normally to produce `libssl.a` and
   `libcrypto.a`.
2. Extracts every globally-defined external symbol from those two archives
   using `nm --defined-only --extern-only` and writes a redefine-syms file
   mapping each `<sym>` to `<prefix><sym>`.
3. Produces prefixed copies of the archives via
   `objcopy --redefine-syms=<file> libssl.a libssl_prefixed.a` (and the same
   for `libcrypto.a`). The rename touches both definitions and undefined
   references inside each member object.
4. Applies the same `--redefine-syms` step as a POST_BUILD action on
   `libmsquic_platform.a` so that MsQuic's own undefined references to
   OpenSSL (from `tls_openssl.c`, `tls_quictls.c`, `crypt_openssl.c`,
   `selfsign_openssl.c`) get rewritten to match the prefixed names.
5. Routes the existing `OpenSSL` interface target at the prefixed archives, so
   the rest of the build is unchanged.

The result is a `libmsquic.so` (or final exe / static archive when
`BUILD_SHARED_LIBS=OFF`) whose only externally-visible OpenSSL symbols are the
prefixed ones. The dynamic linker has no reason to resolve them against any
other OpenSSL copy present in the same process.

## Usage

```bash
cmake -B build -DQUIC_TLS_LIB=quictls -DQUIC_OPENSSL_SYMBOL_PREFIX=mymsquic_ ...
cmake --build build
```

Pick a prefix that is unique to your binary (`<orgname>_<binname>_`) so that
two independently-renamed MsQuics in the same process still do not collide
with each other.

## Constraints

| Constraint | Why |
| --- | --- |
| Linux only (`CX_PLATFORM=linux`) | The implementation uses GNU binutils `objcopy --redefine-syms`. macOS support would need `llvm-objcopy` >= 13 (untested); PE/COFF lacks a flat-namespace symbol table and would need an entirely different approach. |
| Bundled OpenSSL only | An external/system OpenSSL is owned by the caller and cannot be renamed. The option is rejected with `FATAL_ERROR` if combined with `QUIC_USE_EXTERNAL_OPENSSL`, `QUIC_OPENSSL_INCLUDE_DIR`, `QUIC_OPENSSL_LIB_DIR`, `QUIC_OPENSSL_ROOT_DIR`, or `QUIC_USE_SYSTEM_LIBCRYPTO`. |
| Cross-compile aware | `${CMAKE_NM}` and `${CMAKE_OBJCOPY}` are honored so cross-compiled builds (e.g. `aarch64-linux-gnu-objcopy`) work correctly. |

## Performance

The rename step adds a few seconds to the first build (the syms file is ~95k
lines; `objcopy --redefine-syms` over each archive runs in 1-2s). Subsequent
incremental builds re-apply the POST_BUILD step on `libmsquic_platform.a`
whenever it changes, which is negligible.

## Verification

After the build, the prefixed archive should contain only renamed symbols:

```bash
nm -gC --defined-only build/openssl-prefixed/mymsquic_/libssl.a \
  | awk 'NF==3 && $2 ~ /^[TDRBWVC]$/ {print $3}' | grep -vc '^mymsquic_'
# Expected: 0
```

The shared/static library's external OpenSSL references should all be
prefixed:

```bash
nm -uC build/lib/libmsquic.so | grep -E 'SSL_|EVP_|BN_|ERR_' | grep -v mymsquic_
# Expected: no output
```

## Future direction

The cleanest long-term solution is for OpenSSL itself to expose a
configure-time `--symbol-prefix=` option that compiles every public symbol
with the prefix baked in. Until that lands upstream, this CMake helper
provides an equivalent at link time without requiring an OpenSSL fork.
