/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw_unix.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket.c.clog.h"
#endif

#define SOCKET int
#define SocketError() errno
#define HRESULT_FROM_WIN32 (QUIC_STATUS)

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

//
// Socket Pool Logic
//

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        return FALSE;
    }
    CxPlatRwLockInitialize(&Pool->Lock);
    return TRUE;
}

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    CxPlatRwLockUninitialize(&Pool->Lock);
    CxPlatHashtableUninitialize(&Pool->Sockets);
}

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    UNREFERENCED_PARAMETER(Pool);
    UNREFERENCED_PARAMETER(Socket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatResolveRoute(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(PathId);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Callback);
    return QUIC_STATUS_NOT_SUPPORTED;
}


QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    UNREFERENCED_PARAMETER(Pool);
    UNREFERENCED_PARAMETER(Socket);

    return QUIC_STATUS_NOT_SUPPORTED;
}