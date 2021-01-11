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

#ifdef QUIC_PLATFORM_DISPATCH_TABLE

#include "quic_platform.h"
#include "quic_datapath.h"

//
// Function pointers for PAL, DAL and TAL implementation.
//

typedef
void*
(*QUIC_ALLOC)(
    _In_ size_t ByteCount
    );

typedef
void
(*QUIC_FREE)(
    _Inout_ void* Mem
    );

typedef
void
(*QUIC_POOL_INITIALIZE)(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _Inout_ QUIC_POOL* Pool
    );

typedef
void
(*QUIC_POOL_UNINITIALIZE)(
    _Inout_ QUIC_POOL* Pool
    );

typedef
void*
(*QUIC_POOL_ALLOC)(
    _Inout_ QUIC_POOL* Pool
    );

typedef
void
(*QUIC_POOL_FREE)(
    _Inout_ QUIC_POOL* Pool,
    _In_ void* Entry
    );

typedef
void
(*QUIC_LOG)(
    _In_ const char* Fmt,
    _In_ va_list args
    );

typedef
QUIC_RECV_DATA*
(*QUIC_DATAPATH_RECVCONTEXT_TO_RECVBUFFER)(
    _In_ const QUIC_RECV_PACKET* const RecvPacket
    );

typedef
QUIC_RECV_PACKET*
(*QUIC_DATAPATH_RECVBUFFER_TO_RECVCONTEXT)(
    _In_ const QUIC_RECV_DATA* const RecvDatagram
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_INITIALIZE)(
    _In_ uint32_t ClientRecvContextLength,
    _In_ const QUIC_DATAPATH_CALLBACKS* Callback,
    _Out_ QUIC_DATAPATH** NewDatapath
    );

typedef
void
(*QUIC_DATAPATH_UNINITIALIZE)(
    _In_ QUIC_DATAPATH* Datapath
    );

typedef
BOOLEAN
(*QUIC_DATAPATH_IS_PADDING_PREFERRED)(
    _In_ QUIC_DATAPATH* Datapath
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_RESOLVE_ADDRESS)(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    );

typedef
QUIC_STATUS
(*QUIC_SOCKET_CREATE)(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ QUIC_SOCKET_TYPE Type,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_SOCKET** Socket
    );

typedef
void
(*QUIC_SOCKET_DELETE)(
    _In_ QUIC_SOCKET* Socket
    );

typedef
uint16_t
(*QUIC_DATPATH_SOCKET_GET_LOCAL_MTU)(
    _In_ QUIC_SOCKET* Socket
    );

typedef
void
(*QUIC_SOCKET_GET_LOCAL_ADDRESS)(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

typedef
void
(*QUIC_SOCKET_GET_REMOTE_ADDRESS)(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

typedef
void
(*QUIC_RECV_DATA_RETURN)(
    _In_ QUIC_RECV_DATA* RecvDataChain
    );

typedef
QUIC_SEND_DATA*
(*QUIC_SEND_DATA_ALLOC)(
    _In_ QUIC_SOCKET* Socket,
    _In_ QUIC_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    );

typedef
void
(*QUIC_SEND_DATA_FREE)(
    _In_ QUIC_SEND_DATA* SendData
    );

typedef
QUIC_BUFFER*
(*QUIC_SEND_DATA_ALLOC_BUFFER)(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    );

typedef
void
(*QUIC_SEND_DATA_FREE_BUFFER)(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    );

typedef
BOOLEAN
(*QUIC_SEND_DATA_IS_FULL)(
    _In_ QUIC_SEND_DATA* SendData
    );

typedef
QUIC_STATUS
(*QUIC_SOCKET_SEND)(
    _In_ QUIC_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_SEND_DATA* SendData
    );

typedef
QUIC_STATUS
(*QUIC_SOCKET_SET_PARAM)(
    _In_ QUIC_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    );

typedef
QUIC_STATUS
(*QUIC_SOCKET_GET_PARAM)(
    _In_ QUIC_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    );

typedef
QUIC_STATUS
(*QUIC_RANDOM)(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

typedef struct QUIC_PLATFORM_DISPATCH {
    QUIC_ALLOC Alloc;
    QUIC_FREE Free;
    QUIC_POOL_INITIALIZE PoolInitialize;
    QUIC_POOL_UNINITIALIZE PoolUninitialize;
    QUIC_POOL_ALLOC PoolAlloc;
    QUIC_POOL_FREE PoolFree;

    QUIC_LOG Log;

    QUIC_RANDOM Random;

    QUIC_DATAPATH_INITIALIZE DatapathInitialize;
    QUIC_DATAPATH_UNINITIALIZE DatapathUninitialize;
    QUIC_DATAPATH_RECVCONTEXT_TO_RECVBUFFER DatapathRecvContextToRecvPacket;
    QUIC_DATAPATH_RECVBUFFER_TO_RECVCONTEXT DatapathRecvPacketToRecvContext;
    QUIC_DATAPATH_IS_PADDING_PREFERRED DatapathIsPaddingPreferred;
    QUIC_DATAPATH_RESOLVE_ADDRESS DatapathResolveAddress;
    QUIC_SOCKET_CREATE SocketCreate;
    QUIC_SOCKET_DELETE SocketDelete;
    QUIC_DATPATH_SOCKET_GET_LOCAL_MTU SocketGetLocalMtu;
    QUIC_SOCKET_GET_LOCAL_ADDRESS SocketGetLocalAddress;
    QUIC_SOCKET_GET_REMOTE_ADDRESS SocketGetRemoteAddress;
    QUIC_RECV_DATA_RETURN RecvDataReturn;
    QUIC_SEND_DATA_ALLOC SendDataAlloc;
    QUIC_SEND_DATA_FREE SendDataFree;
    QUIC_SEND_DATA_IS_FULL SendDataIsFull;
    QUIC_SEND_DATA_ALLOC_BUFFER SendDataAllocBuffer;
    QUIC_SEND_DATA_FREE_BUFFER SendDataFreeBuffer;
    QUIC_SOCKET_SEND SocketSend;
    QUIC_SOCKET_SET_PARAM SocketSetParam;
    QUIC_SOCKET_GET_PARAM SocketGetParam;

} QUIC_PLATFORM_DISPATCH;

extern QUIC_PLATFORM_DISPATCH* PlatDispatch;

#endif // QUIC_PLATFORM_DISPATCH_TABLE
