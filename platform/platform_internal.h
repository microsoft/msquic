/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#pragma warning(disable:28922)  // Redundant Pointer Test

#include "quic_platform.h"
#include "quic_datapath.h"
#include "quic_cert.h"
#include "quic_storage.h"
#include "quic_tls.h"
#include "quic_versions.h"
#include "quic_trace.h"

#include <msquic.h>
#include <msquicp.h>

#ifdef _KERNEL_MODE

#define QUIC_BASE_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct _QUIC_PLATFORM {

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

#define QUIC_BASE_REG_PATH "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct _QUIC_PLATFORM {

    //
    // Heap used for all allocations.
    //
    HANDLE Heap;

} QUIC_PLATFORM;

#elif QUIC_PLATFORM_LINUX

typedef struct _QUIC_PLATFORM {

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
    _In_ const SOCKADDR_INET * InAddr,
    _Out_ SOCKADDR_INET * OutAddr
    )
{
    if (InAddr->si_family == AF_INET) {
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
inline
void
QuicConvertFromMappedV6(
    _In_ const SOCKADDR_INET * InAddr,
    _Inout_ SOCKADDR_INET * OutAddr
    )
{
    QUIC_DBG_ASSERT(InAddr->si_family == AF_INET6);
    if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
        OutAddr->si_family = AF_INET;
        OutAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
        OutAddr->Ipv4.sin_addr =
            *(IN_ADDR UNALIGNED *)
            IN6_GET_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr);
    } else if (OutAddr != InAddr) {
        *OutAddr = *InAddr;
    }
}

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
