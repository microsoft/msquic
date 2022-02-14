/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#pragma warning(disable:28922) // Redundant Pointer Test
#pragma warning(disable:26451) // Arithmetic overflow: Using operator '+' on a 4 byte value and then casting the result to a 8 byte value.

#include "quic_platform.h"
#include "quic_datapath.h"
#include "quic_pcp.h"
#include "quic_storage.h"
#include "quic_tls.h"
#include "quic_versions.h"
#include "quic_trace.h"

#include "msquic.h"
#include "msquicp.h"

// Must be included after msquic.h for QUIC_CERTIFICATE_FLAGS
#include "quic_cert.h"

#ifdef QUIC_FUZZER
#include "msquic_fuzz.h"

#define QUIC_DISABLED_BY_FUZZER_START if (!MsQuicFuzzerContext.RedirectDataPath) {
#define QUIC_DISABLED_BY_FUZZER_END }

#else

#define QUIC_DISABLED_BY_FUZZER_START
#define QUIC_DISABLED_BY_FUZZER_END

#endif

#ifdef _KERNEL_MODE

#define CXPLAT_BASE_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct CX_PLATFORM {

    //
    // Random number algorithm loaded for DISPATCH_LEVEL usage.
    //
    BCRYPT_ALG_HANDLE RngAlgorithm;

#ifdef DEBUG
    //
    // 1/Denominator of allocations to fail.
    // Negative is Nth allocation to fail.
    //
    int32_t AllocFailDenominator;

    //
    // Count of allocations.
    //
    long AllocCounter;
#endif

} CX_PLATFORM;

#elif _WIN32

#pragma warning(push)
#pragma warning(disable:6385) // Invalid data: accessing [buffer-name], the readable size is size1 bytes but size2 bytes may be read
#pragma warning(disable:6101) // Returning uninitialized memory
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma warning(pop)

#include <mswsock.h>

#if DEBUG
#include <crtdbg.h>
#endif

#define CXPLAT_BASE_REG_PATH "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct CX_PLATFORM {

    //
    // Heap used for all allocations.
    //
    HANDLE Heap;

#ifdef DEBUG
    //
    // 1/Denominator of allocations to fail.
    // Negative is Nth allocation to fail.
    //
    int32_t AllocFailDenominator;

    //
    // Count of allocations.
    //
    long AllocCounter;
#endif

} CX_PLATFORM;

#elif defined(CX_PLATFORM_LINUX) || defined(CX_PLATFORM_DARWIN)

typedef struct CX_PLATFORM {

    void* Reserved; // Nothing right now.

#ifdef DEBUG
    //
    // 1/Denominator of allocations to fail.
    // Negative is Nth allocation to fail.
    //
    int32_t AllocFailDenominator;

    //
    // Count of allocations.
    //
    long AllocCounter;
#endif

} CX_PLATFORM;

#else

#error "Unsupported Platform"

#endif

#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union

//
// Global Platform variables/state.
//
extern CX_PLATFORM CxPlatform;

//
// PCP Receive Callback
//
CXPLAT_DATAPATH_RECEIVE_CALLBACK CxPlatPcpRecvCallback;

#if _WIN32 // Some Windows Helpers

//
// Converts IPv6 or IPV4 address to a (possibly mapped) IPv6.
//
inline
void
CxPlatConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    if (InAddr->si_family == QUIC_ADDRESS_FAMILY_INET) {
        SCOPE_ID unspecified_scope = {0};
        IN6ADDR_SETV4MAPPED(
            &OutAddr->Ipv6,
            &InAddr->Ipv4.sin_addr,
            unspecified_scope,
            InAddr->Ipv4.sin_port);
    } else {
        *OutAddr = *InAddr;
    }
}

//
// Converts (possibly mapped) IPv6 address to a IPv6 or IPV4 address. Does
// support InAdrr == OutAddr.
//
#pragma warning(push)
#pragma warning(disable: 6101) // Intentially don't overwrite output if unable to convert
inline
void
CxPlatConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    CXPLAT_DBG_ASSERT(InAddr->si_family == QUIC_ADDRESS_FAMILY_INET6);
    if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
        OutAddr->si_family = QUIC_ADDRESS_FAMILY_INET;
        OutAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
        OutAddr->Ipv4.sin_addr =
            *(IN_ADDR UNALIGNED *)
            IN6_GET_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr);
    } else if (OutAddr != InAddr) {
        *OutAddr = *InAddr;
    }
}
#pragma warning(pop)

#endif

//
// Crypt Initialization
//

QUIC_STATUS
CxPlatCryptInitialize(
    void
    );

void
CxPlatCryptUninitialize(
    void
    );

//
// Platform Worker APIs
//

BOOLEAN
CxPlatWorkersInit(
    void
    );

void
CxPlatWorkersUninit(
    void
    );

void
CxPlatDataPathWake(
    _In_ void* Context
    );

void
CxPlatDataPathRunEC(
    _In_ void** Context,
    _In_ CXPLAT_THREAD_ID CurThreadId,
    _In_ uint32_t WaitTime
    );

void
CxPlatWorkerRegisterDataPath(
    _In_ uint16_t IdealProcessor,
    _In_ void* Context
    );
