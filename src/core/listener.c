/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Listener API and Logic

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "listener.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerStopAsync(
    _In_ QUIC_LISTENER* Listener
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicListenerOpen(
    _In_ _Pre_defensive_ HQUIC RegistrationHandle,
    _In_ _Pre_defensive_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewListener, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *NewListener
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_LISTENER* Listener = NULL;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_OPEN,
        RegistrationHandle);

    if (RegistrationHandle == NULL ||
        RegistrationHandle->Type != QUIC_HANDLE_TYPE_REGISTRATION ||
        NewListener == NULL ||
        Handler == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Registration = (QUIC_REGISTRATION*)RegistrationHandle;

    Listener = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_LISTENER), QUIC_POOL_LISTENER);
    if (Listener == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "listener",
            sizeof(QUIC_LISTENER));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Listener, sizeof(QUIC_LISTENER));
    Listener->Type = QUIC_HANDLE_TYPE_LISTENER;
    Listener->Registration = Registration;
    Listener->ClientCallbackHandler = Handler;
    Listener->ClientContext = Context;
    Listener->Stopped = TRUE;
    CxPlatEventInitialize(&Listener->StopEvent, TRUE, TRUE);

#ifdef QUIC_SILO
    Listener->Silo = QuicSiloGetCurrentServer();
    QuicSiloAddRef(Listener->Silo);
#endif

    BOOLEAN Result = CxPlatRundownAcquire(&Registration->Rundown);
    CXPLAT_DBG_ASSERT(Result); UNREFERENCED_PARAMETER(Result);

    QuicTraceEvent(
        ListenerCreated,
        "[list][%p] Created, Registration=%p",
        Listener,
        Listener->Registration);
    *NewListener = (HQUIC)Listener;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {

        if (Listener != NULL) {
            CXPLAT_FREE(Listener, QUIC_POOL_LISTENER);
        }
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerFree(
    _In_ QUIC_LISTENER* Listener
    )
{
    QUIC_REGISTRATION* Registration = Listener->Registration;

    QuicTraceEvent(
        ListenerDestroyed,
        "[list][%p] Destroyed",
        Listener);

    CXPLAT_DBG_ASSERT(Listener->Stopped);

#ifdef QUIC_SILO
    QuicSiloRelease(Listener->Silo);
#endif

    CxPlatRefUninitialize(&Listener->RefCount);
    CxPlatEventUninitialize(Listener->StopEvent);
    CXPLAT_DBG_ASSERT(Listener->AlpnList == NULL);
    CXPLAT_FREE(Listener, QUIC_POOL_LISTENER);
    CxPlatRundownRelease(&Registration->Rundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    if (Handle == NULL) {
        return;
    }

    CXPLAT_TEL_ASSERT(Handle->Type == QUIC_HANDLE_TYPE_LISTENER);
    _Analysis_assume_(Handle->Type == QUIC_HANDLE_TYPE_LISTENER);
    if (Handle->Type != QUIC_HANDLE_TYPE_LISTENER) {
        return;
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_CLOSE,
        Handle);

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    QUIC_LISTENER* Listener = (QUIC_LISTENER*)Handle;

    QUIC_LIB_VERIFY(!Listener->AppClosed);
    Listener->AppClosed = TRUE;

    if (Listener->StopCompleteThreadID == CxPlatCurThreadID()) {
        //
        // We're currently in the stop complete event, so we can't free the
        // listener until that callback unwinds.
        //
        Listener->NeedsCleanup = TRUE;

    } else {
        //
        // Make sure the listener has unregistered from the binding, all other
        // references have been released, and the stop complete event has been
        // delivered.
        //
        QuicListenerStopAsync(Listener);
        CxPlatEventWaitForever(Listener->StopEvent);

        QuicListenerFree(Listener);
    }

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicListenerStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ const QUIC_ADDR* LocalAddress
    )
{
    QUIC_STATUS Status;
    QUIC_LISTENER* Listener;
    uint8_t* AlpnList;
    uint32_t AlpnListLength;
    BOOLEAN PortUnspecified;
    QUIC_ADDR BindingLocalAddress = {0};

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_START,
        Handle);

    if (Handle == NULL ||
        Handle->Type != QUIC_HANDLE_TYPE_LISTENER ||
        AlpnBuffers == NULL ||
        AlpnBufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    AlpnListLength = 0;
    for (uint32_t i = 0; i < AlpnBufferCount; ++i) {
        if (AlpnBuffers[i].Length == 0 ||
            AlpnBuffers[i].Length > QUIC_MAX_ALPN_LENGTH) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }
        AlpnListLength += sizeof(uint8_t) + AlpnBuffers[i].Length;
    }
    if (AlpnListLength > UINT16_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    CXPLAT_ANALYSIS_ASSERT(AlpnListLength <= UINT16_MAX);

    if (LocalAddress && !QuicAddrIsValid(LocalAddress)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Listener = (QUIC_LISTENER*)Handle;

    if (!Listener->Stopped) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    AlpnList = CXPLAT_ALLOC_NONPAGED(AlpnListLength, QUIC_POOL_ALPN);
    if (AlpnList == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "AlpnList" ,
            AlpnListLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Listener->AlpnList = AlpnList;
    Listener->AlpnListLength = (uint16_t)AlpnListLength;

    for (uint32_t i = 0; i < AlpnBufferCount; ++i) {
        AlpnList[0] = (uint8_t)AlpnBuffers[i].Length;
        AlpnList++;

        CxPlatCopyMemory(
            AlpnList,
            AlpnBuffers[i].Buffer,
            AlpnBuffers[i].Length);
        AlpnList += AlpnBuffers[i].Length;
    }

    if (LocalAddress != NULL) {
        CxPlatCopyMemory(&Listener->LocalAddress, LocalAddress, sizeof(QUIC_ADDR));
        Listener->WildCard = QuicAddrIsWildCard(LocalAddress);
        PortUnspecified = QuicAddrGetPort(LocalAddress) == 0;
    } else {
        CxPlatZeroMemory(&Listener->LocalAddress, sizeof(Listener->LocalAddress));
        Listener->WildCard = TRUE;
        PortUnspecified = TRUE;
    }

    //
    // Listeners always grab the dual-mode wildcard binding for the specified
    // (if available) UDP port and then manually filter on the specific address
    // (if available) at the QUIC layer.
    //
    QuicAddrSetFamily(&BindingLocalAddress, QUIC_ADDRESS_FAMILY_INET6);
    QuicAddrSetPort(&BindingLocalAddress,
        PortUnspecified ? 0 : QuicAddrGetPort(LocalAddress));

    if (!QuicLibraryOnListenerRegistered(Listener)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &BindingLocalAddress;
    UdpConfig.RemoteAddress = NULL;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_SHARE | CXPLAT_SOCKET_SERVER_OWNED; // Listeners always share the binding.
    UdpConfig.InterfaceIndex = 0;
#ifdef QUIC_COMPARTMENT_ID
    UdpConfig.CompartmentId = QuicCompartmentIdGetCurrent();
#endif
#ifdef QUIC_OWNING_PROCESS
    UdpConfig.OwningProcess = NULL;     // Owning process not supported for listeners.
#endif
#ifdef QUIC_USE_RAW_DATAPATH
    UdpConfig.CibirIdLength = Listener->CibirId[0];
    UdpConfig.CibirIdOffsetSrc = MsQuicLib.CidServerIdLength + 2;
    UdpConfig.CibirIdOffsetDst = MsQuicLib.CidServerIdLength + 2;
    if (UdpConfig.CibirIdLength) {
        CXPLAT_DBG_ASSERT(UdpConfig.CibirIdLength <= sizeof(UdpConfig.CibirId));
        CxPlatCopyMemory(
            UdpConfig.CibirId,
            &Listener->CibirId[2],
            UdpConfig.CibirIdLength);
    }
#endif

    CXPLAT_TEL_ASSERT(Listener->Binding == NULL);
    Status =
        QuicLibraryGetBinding(
            &UdpConfig,
            &Listener->Binding);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "Get binding");
        goto Error;
    }

    Listener->Stopped = FALSE;
    CxPlatEventReset(Listener->StopEvent);
    CxPlatRefInitialize(&Listener->RefCount);

    if (!QuicBindingRegisterListener(Listener->Binding, Listener)) {
        QuicTraceEvent(
            ListenerError,
            "[list][%p] ERROR, %s.",
            Listener,
            "Register with binding");
        QuicListenerRelease(Listener, FALSE);
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    if (PortUnspecified) {
        QuicBindingGetLocalAddress(Listener->Binding, &BindingLocalAddress);
        QuicAddrSetPort(
            &Listener->LocalAddress,
            QuicAddrGetPort(&BindingLocalAddress));
    }

    QuicTraceEvent(
        ListenerStarted,
        "[list][%p] Started, Binding=%p, LocalAddr=%!ADDR!, ALPN=%!ALPN!",
        Listener,
        Listener->Binding,
        CASTED_CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Listener->AlpnListLength, Listener->AlpnList));

Error:

    if (QUIC_FAILED(Status)) {
        if (Listener->Binding != NULL) {
            QuicLibraryReleaseBinding(Listener->Binding);
            Listener->Binding = NULL;
        }
        if (Listener->AlpnList != NULL) {
            CXPLAT_FREE(Listener->AlpnList, QUIC_POOL_ALPN);
            Listener->AlpnList = NULL;
        }
        Listener->AlpnListLength = 0;
    }

Exit:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicListenerIndicateEvent(
    _In_ QUIC_LISTENER* Listener,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    CXPLAT_FRE_ASSERT(Listener->ClientCallbackHandler);
    return
        Listener->ClientCallbackHandler(
            (HQUIC)Listener,
            Listener->ClientContext,
            Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerStopComplete(
    _In_ QUIC_LISTENER* Listener,
    _In_ BOOLEAN IndicateEvent
    )
{
    QuicTraceEvent(
        ListenerStopped,
        "[list][%p] Stopped",
        Listener);

    if (Listener->AlpnList != NULL) {
        CXPLAT_FREE(Listener->AlpnList, QUIC_POOL_ALPN);
        Listener->AlpnList = NULL;
    }

    if (IndicateEvent) {
        QUIC_LISTENER_EVENT Event;
        Event.Type = QUIC_LISTENER_EVENT_STOP_COMPLETE;
        Event.STOP_COMPLETE.AppCloseInProgress = Listener->AppClosed;

        QuicListenerAttachSilo(Listener);

        QuicTraceLogVerbose(
            ListenerIndicateStopComplete,
            "[list][%p] Indicating STOP_COMPLETE",
            Listener);

        Listener->StopCompleteThreadID = CxPlatCurThreadID();
        (void)QuicListenerIndicateEvent(Listener, &Event);
        Listener->StopCompleteThreadID = 0;

        QuicListenerDetachSilo();
    }

    Listener->Stopped = TRUE;
    CxPlatEventSet(Listener->StopEvent);

    if (Listener->NeedsCleanup) {
        QuicListenerFree(Listener);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerRelease(
    _In_ QUIC_LISTENER* Listener,
    _In_ BOOLEAN IndicateEvent
    )
{
    if (CxPlatRefDecrement(&Listener->RefCount)) {
        QuicListenerStopComplete(Listener, IndicateEvent);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerStopAsync(
    _In_ QUIC_LISTENER* Listener
    )
{
    if (Listener->Binding != NULL) {
        QuicBindingUnregisterListener(Listener->Binding, Listener);
        QuicLibraryReleaseBinding(Listener->Binding);
        Listener->Binding = NULL;

        QuicListenerRelease(Listener, TRUE);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerStop(
    _In_ _Pre_defensive_ HQUIC Handle
    )
{
    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_STOP,
        Handle);

    if (Handle != NULL && Handle->Type == QUIC_HANDLE_TYPE_LISTENER) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_LISTENER* Listener = (QUIC_LISTENER*)Handle;
        QuicListenerStopAsync(Listener);
    }

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicListenerTraceRundown(
    _In_ QUIC_LISTENER* Listener
    )
{
    QuicTraceEvent(
        ListenerRundown,
        "[list][%p] Rundown, Registration=%p",
        Listener,
        Listener->Registration);
    if (Listener->Binding != NULL) {
        QuicTraceEvent(
            ListenerStarted,
            "[list][%p] Started, Binding=%p, LocalAddr=%!ADDR!, ALPN=%!ALPN!",
            Listener,
            Listener->Binding,
            CASTED_CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress),
            CASTED_CLOG_BYTEARRAY(Listener->AlpnListLength, Listener->AlpnList));
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
const uint8_t*
QuicListenerFindAlpnInList(
    _In_ const QUIC_LISTENER* Listener,
    _In_ uint16_t OtherAlpnListLength,
    _In_reads_(OtherAlpnListLength)
        const uint8_t* OtherAlpnList
    )
{
    const uint8_t* AlpnList = Listener->AlpnList;
    uint16_t AlpnListLength = Listener->AlpnListLength;

    //
    // We want to respect the server's ALPN preference order (i.e. Listener) and
    // not the client's. So we loop over every ALPN in the listener and then see
    // if there is a match in the client's list.
    //

    while (AlpnListLength != 0) {
        CXPLAT_ANALYSIS_ASSUME(AlpnList[0] + 1 <= AlpnListLength);
        const uint8_t* Result =
            CxPlatTlsAlpnFindInList(
                OtherAlpnListLength,
                OtherAlpnList,
                AlpnList[0],
                AlpnList + 1);
        if (Result != NULL) {
            //
            // Return AlpnList instead of Result, since Result points into what
            // might be a temporary buffer.
            //
            return AlpnList;
        }
        AlpnListLength -= AlpnList[0] + 1;
        AlpnList += AlpnList[0] + 1;
    }

    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicListenerHasAlpnOverlap(
    _In_ const QUIC_LISTENER* Listener1,
    _In_ const QUIC_LISTENER* Listener2
    )
{
    return
        QuicListenerFindAlpnInList(
            Listener1,
            Listener2->AlpnListLength,
            Listener2->AlpnList) != NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicListenerMatchesAlpn(
    _In_ const QUIC_LISTENER* Listener,
    _In_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    const uint8_t* Alpn =
        QuicListenerFindAlpnInList(Listener, Info->ClientAlpnListLength, Info->ClientAlpnList);
    if (Alpn != NULL) {
        Info->NegotiatedAlpnLength = Alpn[0]; // The length prefixed to the ALPN buffer.
        Info->NegotiatedAlpn = Alpn + 1;
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicListenerClaimConnection(
    _In_ QUIC_LISTENER* Listener,
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_NEW_CONNECTION_INFO* Info
    )
{
    CXPLAT_DBG_ASSERT(Listener != NULL);
    CXPLAT_DBG_ASSERT(Connection->State.ExternalOwner == FALSE);

    //
    // Internally, the connection matches the listener. Update the associated
    // connection state. Next, call up to the application layer to accept the
    // connection and return the server configuration.
    //

    Connection->State.ListenerAccepted = TRUE;
    Connection->State.ExternalOwner = TRUE;

    QUIC_LISTENER_EVENT Event;
    Event.Type = QUIC_LISTENER_EVENT_NEW_CONNECTION;
    Event.NEW_CONNECTION.Info = Info;
    Event.NEW_CONNECTION.Connection = (HQUIC)Connection;

    QuicListenerAttachSilo(Listener);

    QuicTraceLogVerbose(
        ListenerIndicateNewConnection,
        "[list][%p] Indicating NEW_CONNECTION %p",
        Listener,
        Connection);

    QUIC_STATUS Status = QuicListenerIndicateEvent(Listener, &Event);

    QuicListenerDetachSilo();

    if (QUIC_FAILED(Status)) {
        CXPLAT_FRE_ASSERTMSG(
            !Connection->State.HandleClosed,
            "App MUST not close and reject connection!");
        Connection->State.ExternalOwner = FALSE;
        QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "NEW_CONNECTION callback");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_CONNECTION_REFUSED);
        return FALSE;
    }

    //
    // The application layer has accepted the connection.
    //
    CXPLAT_FRE_ASSERTMSG(
        Connection->State.HandleClosed ||
        Connection->ClientCallbackHandler != NULL,
        "App MUST set callback handler or close connection!");

    Connection->State.UpdateWorker = TRUE;

    return !Connection->State.HandleClosed;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerAcceptConnection(
    _In_ QUIC_LISTENER* Listener,
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_NEW_CONNECTION_INFO* Info
    )
{
    if (!QuicRegistrationAcceptConnection(
            Listener->Registration,
            Connection)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Connection rejected by registration (overloaded)");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_CONNECTION_REFUSED);
        Listener->TotalRejectedConnections++;
        return;
    }

    if (!QuicConnRegister(Connection, Listener->Registration)) {
        return;
    }

    memcpy(Connection->CibirId, Listener->CibirId, sizeof(Listener->CibirId));

    if (Connection->CibirId[0] != 0) {
        QuicTraceLogConnInfo(
            CibirIdSet,
            Connection,
            "CIBIR ID set (len %hhu, offset %hhu)",
            Connection->CibirId[0],
            Connection->CibirId[1]);
    }

    if (!QuicConnGenerateNewSourceCid(Connection, TRUE)) {
        return;
    }

    if (!QuicListenerClaimConnection(Listener, Connection, Info)) {
        Listener->TotalRejectedConnections++;
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_APP_REJECT);
        return;
    }

    Listener->TotalAcceptedConnections++;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicListenerParamSet(
    _In_ QUIC_LISTENER* Listener,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    if (Param == QUIC_PARAM_LISTENER_CIBIR_ID) {
        if (BufferLength > QUIC_MAX_CIBIR_LENGTH + 1) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (BufferLength == 0) {
            CxPlatZeroMemory(Listener->CibirId, sizeof(Listener->CibirId));
            return QUIC_STATUS_SUCCESS;
        }
        if (BufferLength < 2) { // Must have at least the offset and 1 byte of payload.
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (((uint8_t*)Buffer)[0] != 0) {
            return QUIC_STATUS_NOT_SUPPORTED; // Not yet supproted.
        }

        Listener->CibirId[0] = (uint8_t)BufferLength - 1;
        memcpy(Listener->CibirId + 1, Buffer, BufferLength);

        QuicTraceLogVerbose(
            ListenerCibirIdSet,
            "[list][%p] CIBIR ID set (len %hhu, offset %hhu)",
            Listener,
            Listener->CibirId[0],
            Listener->CibirId[1]);

        return QUIC_STATUS_SUCCESS;
    }

    return QUIC_STATUS_INVALID_PARAMETER;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicListenerParamGet(
    _In_ QUIC_LISTENER* Listener,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

    case QUIC_PARAM_LISTENER_LOCAL_ADDRESS:

        if (*BufferLength < sizeof(QUIC_ADDR)) {
            *BufferLength = sizeof(QUIC_ADDR);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_ADDR);
        CxPlatCopyMemory(Buffer, &Listener->LocalAddress, sizeof(QUIC_ADDR));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_LISTENER_STATS:

        if (*BufferLength < sizeof(QUIC_LISTENER_STATISTICS)) {
            *BufferLength = sizeof(QUIC_LISTENER_STATISTICS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_LISTENER_STATISTICS);
        QUIC_LISTENER_STATISTICS* Stats = (QUIC_LISTENER_STATISTICS*)Buffer;

        Stats->TotalAcceptedConnections = Listener->TotalAcceptedConnections;
        Stats->TotalRejectedConnections = Listener->TotalRejectedConnections;

        if (Listener->Binding != NULL) {
            Stats->BindingRecvDroppedPackets = Listener->Binding->Stats.Recv.DroppedPackets;
        } else {
            Stats->BindingRecvDroppedPackets = 0;
        }

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_LISTENER_CIBIR_ID:

        if (Listener->CibirId[0] == 0) {
            *BufferLength = 0;
            return QUIC_STATUS_SUCCESS;
        }

        if (*BufferLength < (uint32_t)Listener->CibirId[0] + 1) {
            *BufferLength = Listener->CibirId[0] + 1;
            return QUIC_STATUS_BUFFER_TOO_SMALL;
        }

        if (Buffer == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        *BufferLength = Listener->CibirId[0] + 1;
        memcpy(Buffer, Listener->CibirId + 1, Listener->CibirId[0]);

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
