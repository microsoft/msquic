/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This module provides the implementation for most of the MsQuic* APIs.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "api.c.clog.h"
#endif

#define IS_REGISTRATION_HANDLE(Handle) \
( \
    (Handle) != NULL && (Handle)->Type == QUIC_HANDLE_TYPE_REGISTRATION \
)

#define IS_CONN_HANDLE(Handle) \
( \
    (Handle) != NULL && \
    ((Handle)->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT || (Handle)->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) \
)

#define IS_STREAM_HANDLE(Handle) \
( \
    (Handle) != NULL && (Handle)->Type == QUIC_HANDLE_TYPE_STREAM \
)

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionOpen(
    _In_ _Pre_defensive_ HQUIC RegistrationHandle,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *NewConnection
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_CONNECTION* Connection = NULL;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_OPEN,
        RegistrationHandle);

    if (!IS_REGISTRATION_HANDLE(RegistrationHandle) ||
        NewConnection == NULL ||
        Handler == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Registration = (QUIC_REGISTRATION*)RegistrationHandle;

    if ((Connection = QuicConnAlloc(Registration, NULL)) == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Connection->ClientCallbackHandler = Handler;
    Connection->ClientContext = Context;

    QuicRegistrationQueueNewConnection(Registration, Connection);

    *NewConnection = (HQUIC)Connection;
    Status = QUIC_STATUS_SUCCESS;

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand the free happens on the worker
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicConnectionClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    QUIC_CONNECTION* Connection;

    CXPLAT_PASSIVE_CODE();

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_CLOSE,
        Handle);

    if (!IS_CONN_HANDLE(Handle)) {
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Connection = (QUIC_CONNECTION*)Handle;

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);
    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == CxPlatCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        QuicConnCloseHandle(Connection);

    } else {

        CXPLAT_EVENT CompletionEvent;
        QUIC_OPERATION Oper = { 0 };
        QUIC_API_CONTEXT ApiCtx;

        Oper.Type = QUIC_OPER_TYPE_API_CALL;
        Oper.FreeAfterProcess = FALSE;
        Oper.API_CALL.Context = &ApiCtx;

        ApiCtx.Type = QUIC_API_TYPE_CONN_CLOSE;
        CxPlatEventInitialize(&CompletionEvent, TRUE, FALSE);
        ApiCtx.Completed = &CompletionEvent;
        ApiCtx.Status = NULL;

        //
        // Queue the operation and wait for it to be processed.
        //
        QuicConnQueueOper(Connection, &Oper);
        QuicTraceEvent(
            ApiWaitOperation,
            "[ api] Waiting on operation");
        CxPlatEventWaitForever(CompletionEvent);
        CxPlatEventUninitialize(CompletionEvent);
    }

    //
    // Connection can only be released by the application after the released
    // flag was set, in response to the CONN_CLOSE operation was processed.
    //
    CXPLAT_TEL_ASSERT(Connection->State.HandleClosed);

    //
    // Release the reference to the Connection.
    //
    QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);

Error:

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}
#pragma warning(pop)

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicConnectionShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    )
{
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_SHUTDOWN,
        Handle);

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
        CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        goto Error;
    }

    if (ErrorCode > QUIC_UINT62_MAX) {
        QUIC_CONN_VERIFY(Connection, ErrorCode <= QUIC_UINT62_MAX);
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == CxPlatCurThreadID()) ||
        !Connection->State.HandleClosed);

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        if (InterlockedCompareExchange16(
                (short*)&Connection->BackUpOperUsed, 1, 0) != 0) {
            goto Error; // It's already started the shutdown.
        }
        Oper = &Connection->BackUpOper;
        Oper->FreeAfterProcess = FALSE;
        Oper->Type = QUIC_OPER_TYPE_API_CALL;
        Oper->API_CALL.Context = &Connection->BackupApiContext;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
    Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = Flags;
    Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = ErrorCode;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueHighestPriorityOper(Connection, Oper);

Error:

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ HQUIC ConfigHandle,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    QUIC_CONFIGURATION* Configuration;
    QUIC_OPERATION* Oper;
    char* ServerNameCopy = NULL;

    CXPLAT_PASSIVE_CODE();

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_START,
        Handle);

    if (ConfigHandle == NULL ||
        ConfigHandle->Type != QUIC_HANDLE_TYPE_CONFIGURATION ||
        ServerPort == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    //
    // Make sure the connection is to a IPv4 or IPv6 address or unspecified.
    //
    if (Family != QUIC_ADDRESS_FAMILY_UNSPEC &&
        Family != QUIC_ADDRESS_FAMILY_INET &&
        Family != QUIC_ADDRESS_FAMILY_INET6) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
        CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (QuicConnIsServer(Connection) ||
        (!Connection->State.RemoteAddressSet && ServerName == NULL)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Connection->State.Started || Connection->State.ClosedLocally) {
        Status = QUIC_STATUS_INVALID_STATE; // TODO - Support the Connect after close/previous connect failure?
        goto Error;
    }

    Configuration = (QUIC_CONFIGURATION*)ConfigHandle;

    if (Configuration->SecurityConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (ServerName != NULL) {
        //
        // Validate the server name length.
        //
        size_t ServerNameLength = strnlen(ServerName, QUIC_MAX_SNI_LENGTH + 1);
        if (ServerNameLength == QUIC_MAX_SNI_LENGTH + 1) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }

        //
        // Allocate copy of the server name, to save with the connection.
        //
#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed by the connection.")
        ServerNameCopy = CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_SERVERNAME);
        if (ServerNameCopy == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server name",
                ServerNameLength + 1);
            goto Error;
        }

        CxPlatCopyMemory(ServerNameCopy, ServerName, ServerNameLength);
        ServerNameCopy[ServerNameLength] = 0;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);
    CXPLAT_DBG_ASSERT(!QuicConnIsServer(Connection));
    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CONN_START operation",
            0);
        goto Error;
    }

    QuicConfigurationAddRef(Configuration);
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_START;
    Oper->API_CALL.Context->CONN_START.Configuration = Configuration;
    Oper->API_CALL.Context->CONN_START.ServerName = ServerNameCopy;
    Oper->API_CALL.Context->CONN_START.ServerPort = ServerPort;
    Oper->API_CALL.Context->CONN_START.Family = Family;
    ServerNameCopy = NULL;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    if (ServerNameCopy != NULL) {
        CXPLAT_FREE(ServerNameCopy, QUIC_POOL_SERVERNAME);
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionSetConfiguration(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ HQUIC ConfigHandle
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    QUIC_CONFIGURATION* Configuration;
    QUIC_OPERATION* Oper;

    CXPLAT_PASSIVE_CODE();

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_SET_CONFIGURATION,
        Handle);

    if (ConfigHandle == NULL ||
        ConfigHandle->Type != QUIC_HANDLE_TYPE_CONFIGURATION) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
        CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (!QuicConnIsServer(Connection)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Connection->Configuration != NULL) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    Configuration = (QUIC_CONFIGURATION*)ConfigHandle;

    if (Configuration->SecurityConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);
    CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CONN_SET_CONFIGURATION operation",
            0);
        goto Error;
    }

    QuicConfigurationAddRef(Configuration);
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SET_CONFIGURATION;
    Oper->API_CALL.Context->CONN_SET_CONFIGURATION.Configuration = Configuration;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionSendResumptionTicket(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_SEND_RESUMPTION_FLAGS Flags,
    _In_ uint16_t DataLength,
    _In_reads_bytes_opt_(DataLength)
        const uint8_t* ResumptionData
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;
    uint8_t* ResumptionDataCopy = NULL;

    CXPLAT_PASSIVE_CODE();

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
        Handle);

    if (DataLength > QUIC_MAX_RESUMPTION_APP_DATA_LENGTH ||
        (ResumptionData == NULL && DataLength != 0)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Flags > (QUIC_SEND_RESUMPTION_FLAG_FINAL | QUIC_SEND_RESUMPTION_FLAG_NONE)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
        CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

    if (!QuicConnIsServer(Connection)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (!Connection->State.ResumptionEnabled ||
        !Connection->State.Connected ||
        !Connection->Crypto.TlsState.HandshakeComplete) {
        Status = QUIC_STATUS_INVALID_STATE; // TODO - Support queueing up the ticket to send once connected.
        goto Error;
    }

    if (DataLength > 0) {
        ResumptionDataCopy = CXPLAT_ALLOC_NONPAGED(DataLength, QUIC_POOL_APP_RESUMPTION_DATA);
        if (ResumptionDataCopy == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Resumption data copy",
                DataLength);
            goto Error;
        }
        CxPlatCopyMemory(ResumptionDataCopy, ResumptionData, DataLength);
    }

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CONN_SEND_RESUMPTION_TICKET operation",
            0);
        goto Error;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET;
    Oper->API_CALL.Context->CONN_SEND_RESUMPTION_TICKET.Flags = Flags;
    Oper->API_CALL.Context->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData = ResumptionDataCopy;
    Oper->API_CALL.Context->CONN_SEND_RESUMPTION_TICKET.AppDataLength = DataLength;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_SUCCESS;
    ResumptionDataCopy = NULL;

Error:

    if (ResumptionDataCopy != NULL) {
        CXPLAT_FREE(ResumptionDataCopy, QUIC_POOL_APP_RESUMPTION_DATA);
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamOpen(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewStream, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *NewStream
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_OPEN,
        Handle);

    if (NewStream == NULL ||
        Handler == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
        CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (QuicConnIsClosed(Connection)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    Status =
        QuicStreamInitialize(
            Connection,
            FALSE,
            !!(Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL),
            !!(Flags & QUIC_STREAM_OPEN_FLAG_0_RTT),
            (QUIC_STREAM**)NewStream);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    (*(QUIC_STREAM**)NewStream)->ClientCallbackHandler = Handler;
    (*(QUIC_STREAM**)NewStream)->ClientContext = Context;

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand the free happens on the worker
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicStreamClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;

    CXPLAT_PASSIVE_CODE();

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_CLOSE,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == CxPlatCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        QuicStreamClose(Stream);

    } else {

        QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

        BOOLEAN AlreadyShutdownComplete = Stream->ClientCallbackHandler == NULL;
        if (AlreadyShutdownComplete) {
            //
            // No need to wait for the close if already shutdown complete.
            //
            QUIC_OPERATION* Oper =
                QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
            if (Oper != NULL) {
                Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_CLOSE;
                Oper->API_CALL.Context->STRM_CLOSE.Stream = Stream;
                QuicConnQueueOper(Connection, Oper);
                goto Error;
            }
        }

        CXPLAT_EVENT CompletionEvent;
        QUIC_OPERATION Oper = { 0 };
        QUIC_API_CONTEXT ApiCtx;

        Oper.Type = QUIC_OPER_TYPE_API_CALL;
        Oper.FreeAfterProcess = FALSE;
        Oper.API_CALL.Context = &ApiCtx;

        ApiCtx.Type = QUIC_API_TYPE_STRM_CLOSE;
        CxPlatEventInitialize(&CompletionEvent, TRUE, FALSE);
        ApiCtx.Completed = &CompletionEvent;
        ApiCtx.Status = NULL;
        ApiCtx.STRM_CLOSE.Stream = Stream;

        //
        // Queue the operation and wait for it to be processed.
        //
        QuicConnQueueOper(Connection, &Oper);
        QuicTraceEvent(
            ApiWaitOperation,
            "[ api] Waiting on operation");
        CxPlatEventWaitForever(CompletionEvent);
        CxPlatEventUninitialize(CompletionEvent);
    }

Error:

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}
#pragma warning(pop)

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_START_FLAGS Flags
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_START,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Stream->Flags.Started) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    if (Connection->WorkerThreadID == CxPlatCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        Status = QuicStreamStart(Stream, Flags, FALSE);

    } else if (Flags & QUIC_STREAM_START_FLAG_ASYNC) {

        QUIC_OPERATION* Oper =
            QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
        if (Oper == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "STRM_START operation",
                0);
            goto Exit;
        }
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_START;
        Oper->API_CALL.Context->STRM_START.Stream = Stream;
        Oper->API_CALL.Context->STRM_START.Flags = Flags;

        //
        // Async stream operations need to hold a ref on the stream so that the
        // stream isn't freed before the operation can be processed. The ref is
        // released after the operation is processed.
        //
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

        //
        // Queue the operation but don't wait for the completion.
        //
        QuicConnQueueOper(Connection, Oper);
        Status = QUIC_STATUS_PENDING;

    } else {

        QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

        CXPLAT_EVENT CompletionEvent;
        QUIC_OPERATION Oper = { 0 };
        QUIC_API_CONTEXT ApiCtx;

        Oper.Type = QUIC_OPER_TYPE_API_CALL;
        Oper.FreeAfterProcess = FALSE;
        Oper.API_CALL.Context = &ApiCtx;

        ApiCtx.Type = QUIC_API_TYPE_STRM_START;
        CxPlatEventInitialize(&CompletionEvent, TRUE, FALSE);
        ApiCtx.Completed = &CompletionEvent;
        ApiCtx.Status = &Status;
        ApiCtx.STRM_START.Stream = Stream;
        ApiCtx.STRM_START.Flags = Flags;

        //
        // Queue the operation and wait for it to be processed.
        //
        QuicConnQueueOper(Connection, &Oper);
        QuicTraceEvent(
            ApiWaitOperation,
            "[ api] Waiting on operation");
        CxPlatEventWaitForever(CompletionEvent);
        CxPlatEventUninitialize(CompletionEvent);
    }

Exit:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_SHUTDOWN,
        Handle);

    if (!IS_STREAM_HANDLE(Handle) ||
        Flags == 0 || Flags == QUIC_STREAM_SHUTDOWN_SILENT) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (ErrorCode > QUIC_UINT62_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Flags & QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL &&
        Flags != QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL) {
        //
        // Not allowed to use the graceful shutdown flag with any other flag.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Flags & QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE &&
        Flags != (QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND)) {
        //
        // Immediate shutdown requires both directions to be aborted.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == CxPlatCurThreadID()) ||
        !Connection->State.HandleClosed);

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "STRM_SHUTDOWN operation",
            0);
        goto Error;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_SHUTDOWN;
    Oper->API_CALL.Context->STRM_SHUTDOWN.Stream = Stream;
    Oper->API_CALL.Context->STRM_SHUTDOWN.Flags = Flags;
    Oper->API_CALL.Context->STRM_SHUTDOWN.ErrorCode = ErrorCode;

    //
    // Async stream operations need to hold a ref on the stream so that the
    // stream isn't freed before the operation can be processed. The ref is
    // released after the operation is processed.
    //
    QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

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
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    uint64_t TotalLength;
    QUIC_SEND_REQUEST* SendRequest;
    BOOLEAN QueueOper = TRUE;
    QUIC_OPERATION* Oper;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_SEND,
        Handle);

    if (!IS_STREAM_HANDLE(Handle) ||
        Buffers == NULL ||
        BufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == CxPlatCurThreadID()) ||
        !Connection->State.HandleClosed);

    TotalLength = 0;
    for (uint32_t i = 0; i < BufferCount; ++i) {
        TotalLength += Buffers[i].Length;
    }

    if (TotalLength > UINT32_MAX) {
        QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Send request total length exceeds max");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (TotalLength == 0 && !(Flags & QUIC_SEND_FLAG_FIN)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (QuicStreamCompleteSendRequest).")
    SendRequest = CxPlatPoolAlloc(&Connection->Worker->SendRequestPool);
    if (SendRequest == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Stream Send request",
            0);
        goto Exit;
    }

    SendRequest->Next = NULL;
    SendRequest->Buffers = Buffers;
    SendRequest->BufferCount = BufferCount;
    SendRequest->Flags = Flags & ~QUIC_SEND_FLAGS_INTERNAL;
    SendRequest->TotalLength = TotalLength;
    SendRequest->ClientContext = ClientSendContext;

    CxPlatDispatchLockAcquire(&Stream->ApiSendRequestLock);
    if (!Stream->Flags.SendEnabled) {
        Status = QUIC_STATUS_INVALID_STATE;
    } else {
        QUIC_SEND_REQUEST** ApiSendRequestsTail = &Stream->ApiSendRequests;
        while (*ApiSendRequestsTail != NULL) {
            ApiSendRequestsTail = &((*ApiSendRequestsTail)->Next);
            QueueOper = FALSE; // Not necessary if the previous send hasn't been flushed yet.
        }
        *ApiSendRequestsTail = SendRequest;
        Status = QUIC_STATUS_SUCCESS;
    }
    CxPlatDispatchLockRelease(&Stream->ApiSendRequestLock);

    if (QUIC_FAILED(Status)) {
        CxPlatPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
        goto Exit;
    }

    if (QueueOper) {
        Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
        if (Oper == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "STRM_SEND operation",
                0);
            goto Exit;
        }
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_SEND;
        Oper->API_CALL.Context->STRM_SEND.Stream = Stream;

        //
        // Async stream operations need to hold a ref on the stream so that the
        // stream isn't freed before the operation can be processed. The ref is
        // released after the operation is processed.
        //
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

        //
        // Queue the operation but don't wait for the completion.
        //
        QuicConnQueueOper(Connection, Oper);
    }

    Status = QUIC_STATUS_PENDING;

Exit:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveSetEnabled(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ BOOLEAN IsEnabled
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == CxPlatCurThreadID()) ||
        !Connection->State.HandleClosed);

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "STRM_RECV_SET_ENABLED, operation",
            0);
        goto Error;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_RECV_SET_ENABLED;
    Oper->API_CALL.Context->STRM_RECV_SET_ENABLED.Stream = Stream;
    Oper->API_CALL.Context->STRM_RECV_SET_ENABLED.IsEnabled = IsEnabled;

    //
    // Async stream operations need to hold a ref on the stream so that the
    // stream isn't freed before the operation can be processed. The ref is
    // released after the operation is processed.
    //
    QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveComplete(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ uint64_t BufferLength
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    CXPLAT_TEL_ASSERT(!Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == CxPlatCurThreadID()) ||
        !Connection->State.HandleClosed);

    if (!Stream->Flags.Started || !Stream->Flags.ReceiveCallPending) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "STRM_RECV_COMPLETE operation",
            0);
        goto Exit;
    }

    Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_RECV_COMPLETE;
    Oper->API_CALL.Context->STRM_RECV_COMPLETE.Stream = Stream;
    Oper->API_CALL.Context->STRM_RECV_COMPLETE.BufferLength = BufferLength;

    //
    // Async stream operations need to hold a ref on the stream so that the
    // stream isn't freed before the operation can be processed. The ref is
    // released after the operation is processed.
    //
    QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_SUCCESS;

Exit:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSetParam(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    CXPLAT_PASSIVE_CODE();

    if ((Handle == NULL) ^ (Level == QUIC_PARAM_LEVEL_GLOBAL)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_SET_PARAM,
        Handle);

    QUIC_STATUS Status;

    if (Level == QUIC_PARAM_LEVEL_GLOBAL) {
        //
        // Global parameters are processed inline.
        //
        Status = QuicLibrarySetGlobalParam(Param, BufferLength, Buffer);
        goto Error;
    }

    if (Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION ||
        Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION ||
        Handle->Type == QUIC_HANDLE_TYPE_LISTENER) {
        //
        // Registration, Configuration and Listener parameters are processed inline.
        //
        Status = QuicLibrarySetParam(Handle, Level, Param, BufferLength, Buffer);
        goto Error;
    }

    QUIC_CONNECTION* Connection;
    CXPLAT_EVENT CompletionEvent;

    if (Handle->Type == QUIC_HANDLE_TYPE_STREAM) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = ((QUIC_STREAM*)Handle)->Connection;
    } else if (Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER ||
        Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == CxPlatCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        Status = QuicLibrarySetParam(Handle, Level, Param, BufferLength, Buffer);
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

    QUIC_OPERATION Oper = { 0 };
    QUIC_API_CONTEXT ApiCtx;

    Oper.Type = QUIC_OPER_TYPE_API_CALL;
    Oper.FreeAfterProcess = FALSE;
    Oper.API_CALL.Context = &ApiCtx;

    ApiCtx.Type = QUIC_API_TYPE_SET_PARAM;
    CxPlatEventInitialize(&CompletionEvent, TRUE, FALSE);
    ApiCtx.Completed = &CompletionEvent;
    ApiCtx.Status = &Status;
    ApiCtx.SET_PARAM.Handle = Handle;
    ApiCtx.SET_PARAM.Level = Level;
    ApiCtx.SET_PARAM.Param = Param;
    ApiCtx.SET_PARAM.BufferLength = BufferLength;
    ApiCtx.SET_PARAM.Buffer = Buffer;

    //
    // Queue the operation and wait for it to be processed.
    //
    QuicConnQueueOper(Connection, &Oper);
    QuicTraceEvent(
        ApiWaitOperation,
        "[ api] Waiting on operation");
    CxPlatEventWaitForever(CompletionEvent);
    CxPlatEventUninitialize(CompletionEvent);

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicGetParam(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    CXPLAT_PASSIVE_CODE();

    if (((Handle == NULL) ^ (Level == QUIC_PARAM_LEVEL_GLOBAL)) ||
        BufferLength == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_STATUS Status;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_GET_PARAM,
        Handle);

    if (Level == QUIC_PARAM_LEVEL_GLOBAL) {
        //
        // Global parameters are processed inline.
        //
        Status = QuicLibraryGetGlobalParam(Param, BufferLength, Buffer);
        goto Error;
    }

    if (Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION ||
        Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION ||
        Handle->Type == QUIC_HANDLE_TYPE_LISTENER) {
        //
        // Registration, Configuration and Listener parameters are processed inline.
        //
        Status = QuicLibraryGetParam(Handle, Level, Param, BufferLength, Buffer);
        goto Error;
    }

    QUIC_CONNECTION* Connection;
    CXPLAT_EVENT CompletionEvent;

    if (Handle->Type == QUIC_HANDLE_TYPE_STREAM) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = ((QUIC_STREAM*)Handle)->Connection;
    } else if (Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER ||
        Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == CxPlatCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        Status = QuicLibraryGetParam(Handle, Level, Param, BufferLength, Buffer);
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

    QUIC_OPERATION Oper = { 0 };
    QUIC_API_CONTEXT ApiCtx;

    Oper.Type = QUIC_OPER_TYPE_API_CALL;
    Oper.FreeAfterProcess = FALSE;
    Oper.API_CALL.Context = &ApiCtx;

    ApiCtx.Type = QUIC_API_TYPE_GET_PARAM;
    CxPlatEventInitialize(&CompletionEvent, TRUE, FALSE);
    ApiCtx.Completed = &CompletionEvent;
    ApiCtx.Status = &Status;
    ApiCtx.GET_PARAM.Handle = Handle;
    ApiCtx.GET_PARAM.Level = Level;
    ApiCtx.GET_PARAM.Param = Param;
    ApiCtx.GET_PARAM.BufferLength = BufferLength;
    ApiCtx.GET_PARAM.Buffer = Buffer;

    //
    // Queue the operation and wait for it to be processed.
    //
    QuicConnQueueOper(Connection, &Oper);
    QuicTraceEvent(
        ApiWaitOperation,
        "[ api] Waiting on operation");
    CxPlatEventWaitForever(CompletionEvent);
    CxPlatEventUninitialize(CompletionEvent);

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicDatagramSend(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    uint64_t TotalLength;
    QUIC_SEND_REQUEST* SendRequest;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_DATAGRAM_SEND,
        Handle);

    if (!IS_CONN_HANDLE(Handle) ||
        Buffers == NULL ||
        BufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Connection = (QUIC_CONNECTION*)Handle;

    CXPLAT_TEL_ASSERT(!Connection->State.Freed);

    TotalLength = 0;
    for (uint32_t i = 0; i < BufferCount; ++i) {
        TotalLength += Buffers[i].Length;
    }

    if (TotalLength > UINT16_MAX) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Send request total length exceeds max");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (...).")
    SendRequest = CxPlatPoolAlloc(&Connection->Worker->SendRequestPool);
    if (SendRequest == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    SendRequest->Next = NULL;
    SendRequest->Buffers = Buffers;
    SendRequest->BufferCount = BufferCount;
    SendRequest->Flags = Flags;
    SendRequest->TotalLength = TotalLength;
    SendRequest->ClientContext = ClientSendContext;

    Status = QuicDatagramQueueSend(&Connection->Datagram, SendRequest);

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}
