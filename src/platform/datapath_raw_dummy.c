/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "datapath_raw.h"
#include "platform_internal.h"

uint32_t
CxPlatGetRawSocketSize(void) {
    return sizeof(CXPLAT_SOCKET_RAW);
}

CXPLAT_SOCKET*
CxPlatRawToSocket(_In_ CXPLAT_SOCKET_RAW* Socket) {
    return (CXPLAT_SOCKET*)((unsigned char*)Socket + sizeof(CXPLAT_SOCKET_RAW) - sizeof(CXPLAT_SOCKET));
}

CXPLAT_SOCKET_RAW*
CxPlatSocketToRaw(_In_ CXPLAT_SOCKET* Socket) {
    return (CXPLAT_SOCKET_RAW*)((unsigned char*)Socket - sizeof(CXPLAT_SOCKET_RAW) + sizeof(CXPLAT_SOCKET));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketCreateUdp(
    _In_ CXPLAT_DATAPATH_RAW* DataPath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Inout_ CXPLAT_SOCKET_RAW* NewSocket
    )
{
    UNREFERENCED_PARAMETER(DataPath);
    UNREFERENCED_PARAMETER(Config);
    UNREFERENCED_PARAMETER(NewSocket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawSocketDelete(
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    UNREFERENCED_PARAMETER(Socket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _In_opt_ const CXPLAT_DATAPATH* ParentDataPath,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Out_ CXPLAT_DATAPATH_RAW** DataPath
    )
{
    UNREFERENCED_PARAMETER(ClientRecvContextLength);
    UNREFERENCED_PARAMETER(Config);
    UNREFERENCED_PARAMETER(ParentDataPath);
    UNREFERENCED_PARAMETER(WorkerPool);
    UNREFERENCED_PARAMETER(DataPath);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Config);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
RawDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RawDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketUpdateQeo(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Offloads);
    UNREFERENCED_PARAMETER(OffloadCount);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
RawSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    UNREFERENCED_PARAMETER(Socket);
    return 1500;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawRecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    UNREFERENCED_PARAMETER(RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
RawSendDataAlloc(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Config);
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
RawSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(MaxBufferLength);
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(Buffer);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RawSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
RawSocketSend(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(SendData);
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
RawResolveRouteComplete(
    _In_ void* Context,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(PathId);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawResolveRoute(
    _In_ CXPLAT_SOCKET_RAW* Sock,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    )
{
    UNREFERENCED_PARAMETER(Sock);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(PathId);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Callback);
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
RawDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    UNREFERENCED_PARAMETER(DstRoute);
    UNREFERENCED_PARAMETER(SrcRoute);
}
