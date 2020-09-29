/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#pragma warning(disable:28922) // Redundant Pointer Test
#pragma warning(disable:26451) // Arithmetic overflow: Using operator '+' on a 4 byte value and then casting the result to a 8 byte value.

#include "quic_platform.h"
#include "quic_datapath.h"
#include "quic_cert.h"
#include "quic_storage.h"
#include "quic_tls.h"
#include "quic_versions.h"
#include "quic_trace.h"

#include <msquic.h>
#include <msquicp.h>

#define QUIC_CREDENTIAL_TYPE_NULL ((QUIC_CREDENTIAL_TYPE)0xF0000000)    // Stub-only special case type

#ifdef QUIC_FUZZER
#include "msquic_fuzz.h"

#define QUIC_DISABLED_BY_FUZZER_START if (!MsQuicFuzzerContext.RedirectDataPath) {
#define QUIC_DISABLED_BY_FUZZER_END }

#else

#define QUIC_DISABLED_BY_FUZZER_START
#define QUIC_DISABLED_BY_FUZZER_END

#endif

#ifdef _KERNEL_MODE

#define QUIC_BASE_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct QUIC_PLATFORM {

    PDRIVER_OBJECT DriverObject;

    //
    // Random number algorithm loaded for DISPATCH_LEVEL usage.
    //
    BCRYPT_ALG_HANDLE RngAlgorithm;

} QUIC_PLATFORM;

#elif _WIN32

#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>
#if DEBUG
#include <crtdbg.h>
#endif

#define QUIC_BASE_REG_PATH "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct QUIC_PLATFORM {

    //
    // Heap used for all allocations.
    //
    HANDLE Heap;

} QUIC_PLATFORM;

#elif QUIC_PLATFORM_LINUX

typedef struct QUIC_PLATFORM {

    void* Reserved; // Nothing right now.

} QUIC_PLATFORM;

#else

#error "Unsupported Platform"

#endif

#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union

//
// Global Platform variables/state.
//
extern QUIC_PLATFORM QuicPlatform;

#if _WIN32 // Some Windows Helpers

//
// Converts IPv6 or IPV4 address to a (possibly mapped) IPv6.
//
inline
void
QuicConvertToMappedV6(
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
QuicConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    QUIC_DBG_ASSERT(InAddr->si_family == QUIC_ADDRESS_FAMILY_INET6);
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
// TLS Initialization
//

QUIC_STATUS
QuicTlsLibraryInitialize(
    void
    );

void
QuicTlsLibraryUninitialize(
    void
    );
