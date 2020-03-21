/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Version 1 Declarations
//

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicRegistrationOpen(
    _In_opt_ const QUIC_REGISTRATION_CONFIG* Config,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicRegistrationClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Registration
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSecConfigCreate(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ _Pre_defensive_
        QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicSecConfigDelete(
    _In_ _Pre_defensive_ QUIC_SEC_CONFIG* SecurityConfig
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSessionOpen(
    _In_ _Pre_defensive_ HQUIC RegistrationContext,
    _In_reads_z_(QUIC_MAX_ALPN_LENGTH)
        const char* Alpn,    // Application-Layer Protocol Negotiation
    _In_opt_ void* Context,
    _Outptr_ _At_(*Session, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *Session
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicSessionClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Session
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicSessionShutdown(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicListenerOpen(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ _Pre_defensive_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Listener, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *Listener
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicListenerStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ const QUIC_ADDR* LocalAddress
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerStop(
    _In_ _Pre_defensive_ HQUIC Handle
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionOpen(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *Connection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicConnectionClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicConnectionShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamOpen(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Stream, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *Stream
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicStreamClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_START_FLAGS Flags
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamSend(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER * const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveComplete(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ uint64_t BufferLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveSetEnabled(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ BOOLEAN IsEnabled
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSetParam(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicGetParam(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );
