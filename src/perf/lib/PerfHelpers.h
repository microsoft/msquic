/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Perf Helpers

--*/

#pragma once

#ifdef QUIC_CLOG
#include "PerfHelpers.h.clog.h"
#endif

#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1 // For self-signed cert API
#endif

#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // For disabling encryption

#include <quic_platform.h>
#include <quic_trace.h>
#include <msquic.hpp>
#include <msquichelper.h>

#ifndef _KERNEL_MODE
#include <stdlib.h>
#include <stdio.h>
#include <new> // Needed for placement new
#else
#include <new.h>
#endif

struct PerfSelfSignedConfiguration {
#ifdef _KERNEL_MODE
    QUIC_CERTIFICATE_HASH SelfSignedSecurityHash;
#else
    QUIC_SEC_CONFIG_PARAMS* SelfSignedParams;
#endif
};

#define QUIC_TEST_SESSION_CLOSED    1

extern
QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT* StopEvent,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    );

extern
QUIC_STATUS
QuicMainStop(
    _In_ int Timeout
    );

extern volatile int BufferCurrent;
constexpr int BufferLength = 40 * 1024 * 1024;
extern char Buffer[BufferLength];

inline
int
#ifndef _WIN32
 __attribute__((__format__(__printf__, 1, 2)))
#endif
WriteOutput(
    _In_z_ const char* format
    ...
    )
{
#ifndef _KERNEL_MODE
    va_list args;
    va_start(args, format);
    int rval = vprintf(format, args);
    va_end(args);
    return rval;
#else
    char Buf[256];
    char* BufEnd;
    va_list args;
    va_start(args, format);
    NTSTATUS Status = RtlStringCbVPrintfExA(Buf, sizeof(Buf), &BufEnd, nullptr, 0, format, args);
    va_end(args);

    if (Status == STATUS_INVALID_PARAMETER) {
        // Write error
        Status = RtlStringCbPrintfExA(Buf, sizeof(Buf), &BufEnd, nullptr, 0, "Invalid Format: %s\n", format);
        if (Status != STATUS_SUCCESS) {
            return 0;
        }
    }

    int Length = (int)(BufEnd - Buf);
    int End = InterlockedAdd((volatile LONG*)&BufferCurrent, Length);
    if (End > BufferLength) {
        return 0;
    }
    int Start = End - Length;
    QuicCopyMemory(Buffer + Start, Buf, Length);


    return Length;
#endif
}

struct PerfSecurityConfig {
    QUIC_STATUS Initialize(int argc, char** argv, const MsQuicRegistration& Registration, PerfSelfSignedConfiguration* Config) {
        uint16_t useSelfSigned = 0;
        if (TryGetValue(argc, argv, "selfsign", &useSelfSigned)) {
#ifdef _KERNEL_MODE
            CreateSecConfigHelper Helper;
            SecurityConfig =
                Helper.Create(
                    MsQuic,
                    Registration,
                    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
                    &Config->SelfSignedSecurityHash,
                    nullptr);
#else
            SecurityConfig =
                GetSecConfigForSelfSigned(
                    MsQuic,
                    Registration,
                    Config->SelfSignedParams);
#endif
            if (!SecurityConfig) {
                WriteOutput("Failed to create security config for self signed certificate\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else {
            const char* certThumbprint;
            if (!TryGetValue(argc, argv, "thumbprint", &certThumbprint)) {
                WriteOutput("Must specify -thumbprint: for server mode.\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            const char* certStoreName;
            if (!TryGetValue(argc, argv, "cert_store", &certStoreName)) {
                SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, certThumbprint);
                if (SecurityConfig == nullptr) {
                    WriteOutput("Failed to create security configuration for thumbprint:'%s'.\n", certThumbprint);
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
            } else {
                uint32_t machineCert = 0;
                TryGetValue(argc, argv, "machine_cert", &machineCert);
                QUIC_CERTIFICATE_HASH_STORE_FLAGS flags =
                    machineCert ? QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE : QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;

                SecurityConfig = GetSecConfigForThumbprintAndStore(MsQuic, Registration, flags, certThumbprint, certStoreName);
                if (SecurityConfig == nullptr) {
                    WriteOutput(
                        "Failed to create security configuration for thumbprint:'%s' and store: '%s'.\n",
                        certThumbprint,
                        certStoreName);
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    ~PerfSecurityConfig() {
        if (SecurityConfig) {
            MsQuic->SecConfigDelete(SecurityConfig);
        }
    }

    operator QUIC_SEC_CONFIG*() const { return SecurityConfig; }

    QUIC_SEC_CONFIG* SecurityConfig {nullptr};
};

struct CountHelper {
    long RefCount;

    QUIC_EVENT* Done;

    CountHelper() :
        RefCount{1}, Done{} {}

    CountHelper(QUIC_EVENT* Done) :
        RefCount{1}, Done{Done} { }

    bool
    Wait(
        uint32_t Milliseconds
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return true;
        } else {
            return !QuicEventWaitWithTimeout(*Done, Milliseconds);
        }
    }

    void
    WaitForever(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return;
        } else {
            QuicEventWaitForever(*Done);
        }
    }

    void
    AddItem(
        ) {
        InterlockedIncrement(&RefCount);
    }

    void
    CompleteItem(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            QuicEventSet(*Done);
        }
    }
};

//
// Implementation of std::forward, to allow use in kernel mode.
// Based on reference implementation in MSVC's STL
//

template <class _Ty>
struct QuicRemoveReference {
    using type                 = _Ty;
    using _Const_thru_ref_type = const _Ty;
};

template <class _Ty>
using QuicRemoveReferenceT = typename QuicRemoveReference<_Ty>::type;

template <class _Ty>
constexpr _Ty&& QuicForward(
    QuicRemoveReferenceT<_Ty>& _Arg) noexcept { // forward an lvalue as either an lvalue or an rvalue
    return static_cast<_Ty&&>(_Arg);
}

class QuicPoolBufferAllocator {
    QUIC_POOL Pool;
    bool Initialized {false};
public:
    QuicPoolBufferAllocator() {
        QuicZeroMemory(&Pool, sizeof(Pool));
    }

    ~QuicPoolBufferAllocator() {
        if (Initialized) {
            QuicPoolUninitialize(&Pool);
            Initialized = false;
        }
    }

    void Initialize(uint32_t Size, bool Paged = false) {
        QUIC_DBG_ASSERT(Initialized == false);
        QuicPoolInitialize(Paged, Size, QUIC_POOL_PERF, &Pool);
        Initialized = true;
    }

    uint8_t* Alloc() {
        return static_cast<uint8_t*>(QuicPoolAlloc(&Pool));
    }

    void Free(uint8_t* Buf) {
        if (Buf == nullptr) {
            return;
        }
        QuicPoolFree(&Pool, Buf);
    }
};

template<typename T, bool Paged = false>
class QuicPoolAllocator {
    QUIC_POOL Pool;
public:
    QuicPoolAllocator() noexcept {
        QuicPoolInitialize(Paged, sizeof(T), QUIC_POOL_PERF, &Pool);
    }

    ~QuicPoolAllocator() noexcept {
        QuicPoolUninitialize(&Pool);
    }

    template <class... Args>
    T* Alloc(Args&&... args) noexcept {
        void* Raw = QuicPoolAlloc(&Pool);
        if (Raw == nullptr) {
            return nullptr;
        }
        return new (Raw) T (QuicForward<Args>(args)...);
    }

    void Free(T* Obj) noexcept {
        if (Obj == nullptr) {
            return;
        }
        Obj->~T();
        QuicPoolFree(&Pool, Obj);
    }
};
