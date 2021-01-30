/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains function pointers and dispatch table for various
    datapath and platform functionalities.

Environment:

    Linux

--*/

#pragma once

#ifdef CX_PLATFORM_DISPATCH_TABLE

#include "quic_platform.h"
#include "quic_datapath.h"

//
// Function pointers for PAL, DAL and TAL implementation.
//

typedef
void*
(*CXPLAT_ALLOC)(
    _In_ size_t ByteCount
    );

typedef
void
(*CXPLAT_FREE)(
    _Inout_ void* Mem
    );

typedef
void
(*CXPLAT_LOG)(
    _In_ const char* Fmt,
    _In_ va_list args
    );

typedef
CXPLAT_RECV_DATA*
(*CXPLAT_DATAPATH_RECVCONTEXT_TO_RECVBUFFER)(
    _In_ const CXPLAT_RECV_PACKET* const RecvPacket
    );

typedef
CXPLAT_RECV_PACKET*
(*CXPLAT_DATAPATH_RECVBUFFER_TO_RECVCONTEXT)(
    _In_ const CXPLAT_RECV_DATA* const RecvDatagram
    );

typedef
QUIC_STATUS
(*CXPLAT_DATAPATH_INITIALIZE)(
    _In_ uint32_t ClientRecvContextLength,
    _In_ const CXPLAT_DATAPATH_CALLBACKS* Callback,
    _Out_ CXPLAT_DATAPATH** NewDatapath
    );

typedef
void
(*CXPLAT_DATAPATH_UNINITIALIZE)(
    _In_ CXPLAT_DATAPATH* Datapath
    );

typedef
BOOLEAN
(*CXPLAT_DATAPATH_IS_PADDING_PREFERRED)(
    _In_ CXPLAT_DATAPATH* Datapath
    );

typedef
QUIC_STATUS
(*CXPLAT_DATAPATH_RESOLVE_ADDRESS)(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    );

typedef
QUIC_STATUS
(*CXPLAT_SOCKET_CREATE)(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_TYPE Type,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    );

typedef
void
(*CXPLAT_SOCKET_DELETE)(
    _In_ CXPLAT_SOCKET* Socket
    );

typedef
uint16_t
(*CXPLAT_DATPATH_SOCKET_GET_LOCAL_MTU)(
    _In_ CXPLAT_SOCKET* Socket
    );

typedef
void
(*CXPLAT_SOCKET_GET_LOCAL_ADDRESS)(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

typedef
void
(*CXPLAT_SOCKET_GET_REMOTE_ADDRESS)(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

typedef
void
(*CXPLAT_RECV_DATA_RETURN)(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    );

typedef
CXPLAT_SEND_DATA*
(*CXPLAT_SEND_DATA_ALLOC)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    );

typedef
void
(*CXPLAT_SEND_DATA_FREE)(
    _In_ CXPLAT_SEND_DATA* SendData
    );

typedef
QUIC_BUFFER*
(*CXPLAT_SEND_DATA_ALLOC_BUFFER)(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    );

typedef
void
(*CXPLAT_SEND_DATA_FREE_BUFFER)(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    );

typedef
BOOLEAN
(*CXPLAT_SEND_DATA_IS_FULL)(
    _In_ CXPLAT_SEND_DATA* SendData
    );

typedef
QUIC_STATUS
(*CXPLAT_SOCKET_SEND)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    );

typedef
QUIC_STATUS
(*CXPLAT_SOCKET_SET_PARAM)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    );

typedef
QUIC_STATUS
(*CXPLAT_SOCKET_GET_PARAM)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    );

typedef
QUIC_STATUS
(*CXPLAT_RANDOM)(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

typedef struct CX_PLATFORM_DISPATCH {
    CXPLAT_ALLOC Alloc;
    CXPLAT_FREE Free;

    CXPLAT_LOG Log;

    CXPLAT_RANDOM Random;

    CXPLAT_DATAPATH_INITIALIZE DatapathInitialize;
    CXPLAT_DATAPATH_UNINITIALIZE DatapathUninitialize;
    CXPLAT_DATAPATH_RECVCONTEXT_TO_RECVBUFFER DatapathRecvContextToRecvPacket;
    CXPLAT_DATAPATH_RECVBUFFER_TO_RECVCONTEXT DatapathRecvPacketToRecvContext;
    CXPLAT_DATAPATH_IS_PADDING_PREFERRED DatapathIsPaddingPreferred;
    CXPLAT_DATAPATH_RESOLVE_ADDRESS DatapathResolveAddress;
    CXPLAT_SOCKET_CREATE SocketCreate;
    CXPLAT_SOCKET_DELETE SocketDelete;
    CXPLAT_DATPATH_SOCKET_GET_LOCAL_MTU SocketGetLocalMtu;
    CXPLAT_SOCKET_GET_LOCAL_ADDRESS SocketGetLocalAddress;
    CXPLAT_SOCKET_GET_REMOTE_ADDRESS SocketGetRemoteAddress;
    CXPLAT_RECV_DATA_RETURN RecvDataReturn;
    CXPLAT_SEND_DATA_ALLOC SendDataAlloc;
    CXPLAT_SEND_DATA_FREE SendDataFree;
    CXPLAT_SEND_DATA_IS_FULL SendDataIsFull;
    CXPLAT_SEND_DATA_ALLOC_BUFFER SendDataAllocBuffer;
    CXPLAT_SEND_DATA_FREE_BUFFER SendDataFreeBuffer;
    CXPLAT_SOCKET_SEND SocketSend;
    CXPLAT_SOCKET_SET_PARAM SocketSetParam;
    CXPLAT_SOCKET_GET_PARAM SocketGetParam;

} CX_PLATFORM_DISPATCH;

extern CX_PLATFORM_DISPATCH* PlatDispatch;

#endif // CX_PLATFORM_DISPATCH_TABLE
