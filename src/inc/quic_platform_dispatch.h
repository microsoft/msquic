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
    _In_ QUIC_TRACE_LEVEL Level,
    _In_ const char* Fmt,
    _In_ va_list args
    );

typedef
QUIC_RECV_DATAGRAM*
(*QUIC_DATAPATH_RECVCONTEXT_TO_RECVBUFFER)(
    _In_ const QUIC_RECV_PACKET* const RecvPacket
    );

typedef
QUIC_RECV_PACKET*
(*QUIC_DATAPATH_RECVBUFFER_TO_RECVCONTEXT)(
    _In_ const QUIC_RECV_DATAGRAM* const RecvDatagram
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_INITIALIZE)(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDatapath
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
    _Inout_ QUIC_ADDR * Address
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_BINDING_CREATE)(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** Binding
    );

typedef
void
(*QUIC_DATAPATH_BINDING_DELETE)(
    _In_ QUIC_DATAPATH_BINDING* Binding
    );

typedef
uint16_t
(*QUIC_DATPATH_BINDING_GET_LOCAL_MTU)(
    _In_ QUIC_DATAPATH_BINDING* Binding
    );

typedef
void
(*QUIC_DATAPATH_BINDING_GET_LOCAL_ADDRESS)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    );

typedef
void
(*QUIC_DATAPATH_BINDING_GET_REMOTE_ADDRESS)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    );

typedef
void
(*QUIC_DATAPATH_BINDING_RETURN_RECV_BUFFER)(
    _In_ QUIC_RECV_DATAGRAM* RecvPacketChain
    );

typedef
QUIC_DATAPATH_SEND_CONTEXT*
(*QUIC_DATAPATH_BINDING_ALLOC_SEND_CONTEXT)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    );

typedef
void
(*QUIC_DATAPATH_BINDING_FREE_SEND_CONTEXT)(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
QUIC_BUFFER*
(*QUIC_DATAPATH_BINDING_ALLOC_SEND_BUFFER)(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    );

typedef
void
(*QUIC_DATAPATH_BINDING_FREE_SEND_BUFFER)(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* SendBuffer
    );

typedef
BOOLEAN
(*QUIC_DATAPATH_BINDING_IS_SEND_CONTEXT_FULL)(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_BINDING_SEND_TO)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_BINDING_SEND_FROM_TO)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_BINDING_SET_PARAM)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    );

typedef
QUIC_STATUS
(*QUIC_DATAPATH_BINDING_GET_PARAM)(
    _In_ QUIC_DATAPATH_BINDING* Binding,
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
    QUIC_DATAPATH_BINDING_CREATE DatapathBindingCreate;
    QUIC_DATAPATH_BINDING_DELETE DatapathBindingDelete;
    QUIC_DATPATH_BINDING_GET_LOCAL_MTU DatapathBindingGetLocalMtu;
    QUIC_DATAPATH_BINDING_GET_LOCAL_ADDRESS DatapathBindingGetLocalAddress;
    QUIC_DATAPATH_BINDING_GET_REMOTE_ADDRESS DatapathBindingGetRemoteAddress;
    QUIC_DATAPATH_BINDING_RETURN_RECV_BUFFER DatapathBindingReturnRecvPacket;
    QUIC_DATAPATH_BINDING_ALLOC_SEND_CONTEXT DatapathBindingAllocSendContext;
    QUIC_DATAPATH_BINDING_FREE_SEND_CONTEXT DatapathBindingFreeSendContext;
    QUIC_DATAPATH_BINDING_IS_SEND_CONTEXT_FULL DatapathBindingIsSendContextFull;
    QUIC_DATAPATH_BINDING_ALLOC_SEND_BUFFER DatapathBindingAllocSendBuffer;
    QUIC_DATAPATH_BINDING_FREE_SEND_BUFFER DatapathBindingFreeSendBuffer;
    QUIC_DATAPATH_BINDING_SEND_TO DatapathBindingSendTo;
    QUIC_DATAPATH_BINDING_SEND_FROM_TO DatapathBindingSendFromTo;
    QUIC_DATAPATH_BINDING_SET_PARAM DatapathBindingSetParam;
    QUIC_DATAPATH_BINDING_GET_PARAM DatapathBindingGetParam;

} QUIC_PLATFORM_DISPATCH;

extern QUIC_PLATFORM_DISPATCH* PlatDispatch;

#endif // QUIC_PLATFORM_DISPATCH_TABLE
