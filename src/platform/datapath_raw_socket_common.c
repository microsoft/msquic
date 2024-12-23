/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket_common.c.clog.h"
#endif


#if defined(CX_PLATFORM_LINUX) || defined(CX_PLATFORM_DARWIN)
#define CxPlatSocketError() errno
#define CxPlatCloseSocket(s) close(s)
#define CxPlatQuicErrorFromSocketError(e) (QUIC_STATUS)e
#define CxPlatAddressLengthType uint32_t
#elif defined(_WIN32)
#define CxPlatSocketError() WSAGetLastError()
#define CxPlatCloseSocket(s) closesocket(s)
#define CxPlatQuicErrorFromSocketError(e) HRESULT_FROM_WIN32(e)
#define CxPlatAddressLengthType int
#else
#error unsupported platform
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

#ifdef _KERNEL_MODE

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);
    CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;

    //
    // Get (and reserve) a transport layer port from the OS networking stack by
    // binding an auxiliary (dual stack) socket.
    //

    CxPlatRwLockAcquireExclusive(&Pool->Lock);

    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET_RAW* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET_RAW, Entry);
        if (CxPlatSocketCompare(Temp, &Socket->LocalAddress, &Socket->RemoteAddress)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatHashtableInsert(&Pool->Sockets, &Socket->Entry, Socket->LocalAddress.Ipv4.sin_port, &Context);
    }

    CxPlatRwLockReleaseExclusive(&Pool->Lock);

    return Status;
}

#else

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);

    if (Socket->AuxSocket != INVALID_SOCKET &&
        CxPlatCloseSocket(Socket->AuxSocket) == SOCKET_ERROR) {
        int Error = CxPlatSocketError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "closesocket");
    }

    CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    int Option;
    QUIC_ADDR MappedAddress = {0};
    SOCKET TempUdpSocket = INVALID_SOCKET;
    CxPlatAddressLengthType AssignedLocalAddressLength;

    //
    // Get (and reserve) a transport layer port from the OS networking stack by
    // binding an auxiliary (dual stack) socket.
    //

    if (Socket->UseTcp) {
        Socket->AuxSocket =
            socket(
                AF_INET6,
                SOCK_STREAM,
                IPPROTO_TCP);
        if (Socket->AuxSocket == INVALID_SOCKET) {
            int WsaError = CxPlatSocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "socket");
            Status = CxPlatQuicErrorFromSocketError(WsaError);
            goto Error;
        }

        Option = FALSE;
        Result =
            setsockopt(
                Socket->AuxSocket,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = CxPlatSocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_V6ONLY");
            Status = CxPlatQuicErrorFromSocketError(WsaError);
            goto Error;
        }

        if (Socket->CibirIdLength) {
            Option = TRUE;
            Result =
                setsockopt(
                    Socket->AuxSocket,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set SO_REUSEADDR");
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
        }

        CxPlatConvertToMappedV6(&Socket->LocalAddress, &MappedAddress);
#if QUIC_ADDRESS_FAMILY_INET6 != AF_INET6
        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }
#endif
    }

    CxPlatRwLockAcquireExclusive(&Pool->Lock);

    if (Socket->UseTcp) {
        QUIC_ADDR_STR LocalAddressString = {0};
        QuicAddrToString(&MappedAddress, &LocalAddressString);
        QuicTraceLogVerbose(
            DatapathTcpAuxBinding,
            "[data][%p] Binding TCP socket to %s",
            Socket,
            LocalAddressString.Address);
        Result =
            bind(
                Socket->AuxSocket,
                (struct sockaddr*)&MappedAddress,
                sizeof(MappedAddress));
        if (Result == SOCKET_ERROR) {
            int WsaError = CxPlatSocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "bind");
            CxPlatRwLockReleaseExclusive(&Pool->Lock);
            Status = CxPlatQuicErrorFromSocketError(WsaError);
            goto Error;
        }

        if (Socket->Connected) {
            CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
            CxPlatConvertToMappedV6(&Socket->RemoteAddress, &MappedAddress);

#if QUIC_ADDRESS_FAMILY_INET6 != AF_INET6
            if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
                MappedAddress.Ipv6.sin6_family = AF_INET6;
            }
#endif
            //
            // Create a temporary UDP socket bound to a wildcard port
            // and connect this socket to the remote address.
            // By doing this, the OS will select a local address for us.
            //
            uint16_t LocalPortChosen = 0;
            QUIC_ADDR TempLocalAddress = {0};
            AssignedLocalAddressLength = sizeof(TempLocalAddress);
            Result =
                getsockname(
                    Socket->AuxSocket,
                    (struct sockaddr*)&TempLocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
            LocalPortChosen = TempLocalAddress.Ipv4.sin_port;
            TempUdpSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (TempUdpSocket == INVALID_SOCKET) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "temp udp socket");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            Option = FALSE;
            Result =
                setsockopt(
                    TempUdpSocket,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set IPV6_V6ONLY (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            CxPlatZeroMemory(&TempLocalAddress, sizeof(TempLocalAddress));
            CxPlatConvertToMappedV6(&Socket->LocalAddress, &TempLocalAddress);
            TempLocalAddress.Ipv4.sin_port = 0;
            Result =
                bind(
                    TempUdpSocket,
                    (struct sockaddr*)&TempLocalAddress,
                    sizeof(TempLocalAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "bind (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            Result =
                connect(
                    TempUdpSocket,
                    (struct sockaddr*)&MappedAddress,
                    sizeof(MappedAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "connect failed (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    TempUdpSocket,
                    (struct sockaddr*)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
            CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
            Socket->LocalAddress.Ipv4.sin_port = LocalPortChosen;
            CXPLAT_FRE_ASSERT(Socket->LocalAddress.Ipv4.sin_port != 0);
        } else {
            AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    Socket->AuxSocket,
                    (struct sockaddr*)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
            CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
        }
    }

    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET_RAW* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET_RAW, Entry);
        if (CxPlatSocketCompare(Temp, &Socket->LocalAddress, &Socket->RemoteAddress)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatHashtableInsert(&Pool->Sockets, &Socket->Entry, Socket->LocalAddress.Ipv4.sin_port, &Context);
    }

    CxPlatRwLockReleaseExclusive(&Pool->Lock);

Error:

    if (QUIC_FAILED(Status) && Socket->AuxSocket != INVALID_SOCKET) {
        CxPlatCloseSocket(Socket->AuxSocket);
    }

    if (TempUdpSocket != INVALID_SOCKET) {
        CxPlatCloseSocket(TempUdpSocket);
    }

    return Status;
}

#endif // _KERNEL_MODE