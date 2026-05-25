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

Replace `<your_prefix>` with a value unique to your binary, e.g.
`acme_myapp_msquic_` (so that two independently-renamed MsQuics in the same
process still do not collide with each other). The prefix must match
`^[A-Za-z_][A-Za-z0-9_]*$` — the CMake guard rejects anything else, because
the value is interpolated into `objcopy --redefine-syms` map lines and into
the build-tree path.

```bash
cmake -B build \
    -DQUIC_TLS_LIB=quictls \
    -DQUIC_BUILD_SHARED=OFF \
    -DQUIC_OPENSSL_SYMBOL_PREFIX=<your_prefix> ...
cmake --build build
```

`-DQUIC_BUILD_SHARED=OFF` is required: this option drives MsQuic's
`BUILD_SHARED_LIBS`, and the prefixed OpenSSL is currently only supported with
`BUILD_SHARED_LIBS=OFF` (see Constraints below). Omitting it on a default
configure (where `QUIC_BUILD_SHARED=ON`) trips the `FATAL_ERROR` guard.

### Changing the prefix value

The POST_BUILD rename step on `libmsquic_platform.a` is keyed on the platform
archive's mtime, not on the prefix value. If you reconfigure with a different
`QUIC_OPENSSL_SYMBOL_PREFIX` over the same build tree, the platform archive
is untouched, the POST_BUILD step does not refire, and the resulting binary
will still carry the previous prefix on the platform side while the
`openssl-prefixed/<new_prefix>/` directory holds the new prefix on the OpenSSL
side — link will fail or, worse, silently produce a mixed-prefix binary.

Workaround until the rename is restructured as a proper `add_custom_command`
in the dependency graph: when you change the prefix, force a clean rebuild of
the affected targets:

```bash
cmake --build build --target clean
cmake --build build
```

or blow the build tree away (`rm -rf build && cmake -B build ...`).

## Constraints

| Constraint | Why |
| --- | --- |
| Linux only (`CX_PLATFORM=linux`) | The implementation uses GNU binutils `objcopy --redefine-syms`. macOS support would need `llvm-objcopy` >= 13 (untested); PE/COFF lacks a flat-namespace symbol table and would need an entirely different approach. |
| Bundled OpenSSL only | An external/system OpenSSL is owned by the caller and cannot be renamed. The option is rejected with `FATAL_ERROR` if combined with `QUIC_USE_EXTERNAL_OPENSSL`, `QUIC_OPENSSL_INCLUDE_DIR`, `QUIC_OPENSSL_LIB_DIR`, `QUIC_OPENSSL_ROOT_DIR`, or `QUIC_USE_SYSTEM_LIBCRYPTO`. |
| Cross-compile aware | `${CMAKE_NM}` and `${CMAKE_OBJCOPY}` are honored so cross-compiled builds (e.g. `aarch64-linux-gnu-objcopy`) work correctly. |
| Prefix charset | Must match `^[A-Za-z_][A-Za-z0-9_]*$`. The CMake guard rejects anything else. The value is interpolated into `objcopy --redefine-syms` map lines and into the build-tree path. |
| `BUILD_SHARED_LIBS=OFF` only | The prefixed OpenSSL is exposed as an `INTERFACE IMPORTED GLOBAL` target referencing build-tree archive paths under `${CMAKE_BINARY_DIR}/openssl-prefixed/`; it is not installable via `install(TARGETS ... EXPORT msquic)`. Building MsQuic as a shared lib with prefixing enabled is rejected with `FATAL_ERROR` until the install path is restructured. |
| Prefix changes require clean rebuild | The POST_BUILD rename on `libmsquic_platform.a` is keyed on the archive mtime, not the prefix value. See "Changing the prefix value" above. |

## Performance

The rename step adds a few seconds to the first build (the syms file is ~95k
lines; `objcopy --redefine-syms` over each archive runs in 1-2s). Subsequent
incremental builds re-apply the POST_BUILD step on `libmsquic_platform.a`
whenever it changes, which is negligible.

## Verification

Replace `<your_prefix>` and `<arch>_<tls>` (e.g. `x64_quictls`) with the
values used at configure time. After the build, the prefixed archive should
contain only renamed symbols:

```bash
nm -g --defined-only build/openssl-prefixed/<your_prefix>/libssl.a \
  | awk 'NF>=3 && $(NF-1) ~ /^[TDRBWVCI]$/ {print $NF}' \
  | grep -v '^<your_prefix>' | wc -l
# Expected: 0
```

`libmsquic_platform.a`'s undefined OpenSSL references should all be
prefixed (this option requires `QUIC_BUILD_SHARED=OFF`, so the final output is
the static archive — there is no `libmsquic.so` to check):

```bash
nm -u build/linux/<arch>_<tls>/obj/Release/libmsquic_platform.a \
  | awk '$1=="U"{print $2}' \
  | grep -E '^(SSL_|EVP_|BN_|ERR_|X509_|OPENSSL_|RAND_|RSA_|EC_|BIO_|ASN1_|PEM_|CRYPTO_)'
# Expected: no output (every OpenSSL undef is now <your_prefix>-prefixed)
```

Notes on the `nm` invocations above:

- We use plain `-g` (no `-C`) to match the script's symbol filter, which
  operates on mangled names.
- The `awk` filter mirrors the script's rule (`NF>=3` and a symbol-type set
  that includes `I` / GNU IFUNC, used by OpenSSL 3.x dispatch resolvers on
  x86_64). If you tighten it, you may falsely conclude the rename is
  incomplete.
- The pipeline uses `grep -v ... | wc -l` rather than `grep -vc` because
  `grep -vc` exits non-zero when its count is 0, which under `set -e` would
  abort a verification script for the success case.

## Future direction

The cleanest long-term solution is for OpenSSL itself to expose a
configure-time `--symbol-prefix=` option that compiles every public symbol
with the prefix baked in. Until that lands upstream, this CMake helper
provides an equivalent at link time without requiring an OpenSSL fork.
