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
#define QUIC_API_ENABLE_PREVIEW_FEATURES  1 // For CIBIR extension

#include "quic_platform.h"
#include "quic_trace.h"
#include "msquic.hpp"
#include "msquichelper.h"
#include "quic_hashtable.h"
#include "PerfBase.h"
#include "Tcp.h"

#ifndef _KERNEL_MODE
#include <stdlib.h>
#include <stdio.h>
#include <new> // Needed for placement new
#else
#include <new.h>
#endif

#define QUIC_TEST_SESSION_CLOSED    1

extern
QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ CXPLAT_EVENT* StopEvent,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig
    );

extern
QUIC_STATUS
QuicMainStop(
    );

extern
void
QuicMainFree(
    );

extern
QUIC_STATUS
QuicMainGetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Metadata
    );

extern
QUIC_STATUS
QuicMainGetExtraData(
    _Out_writes_bytes_(*Length) uint8_t* Data,
    _Inout_ uint32_t* Length
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
    CxPlatCopyMemory(Buffer + Start, Buf, Length);


    return Length;
#endif
}

/*struct PerfSecurityConfig {
    QUIC_STATUS Initialize(int argc, char** argv, const MsQuicRegistration& Registration, PerfSelfSignedConfiguration* Config) {
        uint16_t useSelfSigned = 0;
        if (TryGetValue(argc, argv, "selfsign", &useSelfSigned)) {
#ifdef _KERNEL_MODE
            CreateSecConfigHelper Helper;
            SecurityConfig =
                Helper.Create(
                    MsQuic,
                    Registration,
                    CXPLAT_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
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

    operator CXPLAT_SEC_CONFIG*() const { return SecurityConfig; }

    CXPLAT_SEC_CONFIG* SecurityConfig {nullptr};
};*/

struct CountHelper {
    long RefCount;

    CXPLAT_EVENT* Done;

    CountHelper() :
        RefCount{1}, Done{} {}

    CountHelper(CXPLAT_EVENT* Done) :
        RefCount{1}, Done{Done} { }

    bool
    Wait(
        uint32_t Milliseconds
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return true;
        } else {
            return !CxPlatEventWaitWithTimeout(*Done, Milliseconds);
        }
    }

    void
    WaitForever(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return;
        } else {
            CxPlatEventWaitForever(*Done);
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
            CxPlatEventSet(*Done);
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
    CXPLAT_POOL Pool;
    bool Initialized {false};
public:
    QuicPoolBufferAllocator() {
        CxPlatZeroMemory(&Pool, sizeof(Pool));
    }

    ~QuicPoolBufferAllocator() {
        if (Initialized) {
            CxPlatPoolUninitialize(&Pool);
            Initialized = false;
        }
    }

    void Initialize(uint32_t Size, bool Paged = false) {
        CXPLAT_DBG_ASSERT(Initialized == false);
        CxPlatPoolInitialize(Paged, Size, QUIC_POOL_PERF, &Pool);
        Initialized = true;
    }

    uint8_t* Alloc() {
        return static_cast<uint8_t*>(CxPlatPoolAlloc(&Pool));
    }

    void Free(uint8_t* Buf) {
        if (Buf == nullptr) {
            return;
        }
        CxPlatPoolFree(&Pool, Buf);
    }
};

template<typename T, bool Paged = false>
class QuicPoolAllocator {
    CXPLAT_POOL Pool;
public:
    QuicPoolAllocator() noexcept {
        CxPlatPoolInitialize(Paged, sizeof(T), QUIC_POOL_PERF, &Pool);
    }

    ~QuicPoolAllocator() noexcept {
        CxPlatPoolUninitialize(&Pool);
    }

    template <class... Args>
    T* Alloc(Args&&... args) noexcept {
        void* Raw = CxPlatPoolAlloc(&Pool);
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
        CxPlatPoolFree(&Pool, Obj);
    }
};

inline
void
QuicPrintConnectionStatistics(
    _In_ const QUIC_API_TABLE* ApiTable,
    _In_ HQUIC Connection
    )
{
    QUIC_STATISTICS_V2 Statistics;
    uint32_t StatsSize = sizeof(Statistics);
    if (QUIC_SUCCEEDED(
        ApiTable->GetParam(
            Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Statistics))) {
        WriteOutput(
            "[conn][%p] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu\n",
            Connection,
            (unsigned long long)Statistics.SendTotalPackets,
            (unsigned long long)Statistics.SendSuspectedLostPackets,
            (unsigned long long)Statistics.SendSpuriousLostPackets,
            (unsigned long long)Statistics.RecvTotalPackets,
            (unsigned long long)Statistics.RecvReorderedPackets,
            (unsigned long long)Statistics.RecvDroppedPackets,
            (unsigned long long)Statistics.RecvDuplicatePackets,
            (unsigned long long)Statistics.RecvDecryptionFailures);
    }
}
