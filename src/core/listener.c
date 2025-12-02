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

BOOLEAN
QuicListenerIsOnWorker(
    _In_ QUIC_LISTENER* Listener
    )
{
    if (Listener->Partitioned) {
        return QuicWorkerPoolIsInPartition(
            Listener->Registration->WorkerPool, Listener->PartitionIndex);
    }

    return TRUE;
}

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
    Listener->DosModeEventsEnabled = FALSE;
    CxPlatEventInitialize(&Listener->StopEvent, TRUE, TRUE);
    CxPlatRefInitialize(&Listener->RefCount);

#ifdef QUIC_SILO
    Listener->Silo = QuicSiloGetCurrentServerSilo();
    QuicSiloAddRef(Listener->Silo);
#endif

    BOOLEAN RegistrationShuttingDown;

    BOOLEAN Result = QuicRegistrationRundownAcquire(Registration, QUIC_REG_REF_LISTENER);
    CXPLAT_DBG_ASSERT(Result); UNREFERENCED_PARAMETER(Result);

    CxPlatDispatchLockAcquire(&Registration->ConnectionLock);
    RegistrationShuttingDown = Registration->ShuttingDown;
    if (!RegistrationShuttingDown) {
        CxPlatListInsertTail(&Registration->Listeners, &Listener->RegistrationLink);
    }
    CxPlatDispatchLockRelease(&Registration->ConnectionLock);

    if (RegistrationShuttingDown) {
        QuicRegistrationRundownRelease(Registration, QUIC_REG_REF_LISTENER);
        CxPlatEventUninitialize(Listener->StopEvent);
        CXPLAT_FREE(Listener, QUIC_POOL_LISTENER);
        Listener = NULL;
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }
    QuicTraceEvent(
        ListenerCreated,
        "[list][%p] Created, Registration=%p",
        Listener,
        Listener->Registration);
    *NewListener = (HQUIC)Listener;
    Status = QUIC_STATUS_SUCCESS;

Error:

    CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status) || Listener == NULL);

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

    CxPlatDispatchLockAcquire(&Listener->Registration->ConnectionLock);
    if (!Listener->Registration->ShuttingDown) {
        CxPlatListEntryRemove(&Listener->RegistrationLink);
    }
    CxPlatDispatchLockRelease(&Listener->Registration->ConnectionLock);

    CxPlatRefUninitialize(&Listener->RefCount);
    CxPlatRefUninitialize(&Listener->StartRefCount);
    CxPlatEventUninitialize(Listener->StopEvent);
    CXPLAT_DBG_ASSERT(Listener->AlpnList == NULL);
    CXPLAT_FREE(Listener, QUIC_POOL_LISTENER);
    QuicRegistrationRundownRelease(Registration, QUIC_REG_REF_LISTENER);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    CXPLAT_TEL_ASSERT(Handle == NULL || Handle->Type == QUIC_HANDLE_TYPE_LISTENER);
    if (Handle == NULL || Handle->Type != QUIC_HANDLE_TYPE_LISTENER) {
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

    //
    // If we're currently in the stop complete event, there's no need to
    // implicitly perform the stop.
    //
    if (Listener->StopCompleteThreadID != CxPlatCurThreadID()) {
        //
        // Make sure the listener has unregistered from the binding, all other
        // references have been released, and the stop complete event has been
        // delivered.
        //
        QuicListenerStopAsync(Listener);
        CxPlatEventWaitForever(Listener->StopEvent);
    }

    QuicListenerRelease(Listener);

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
    if (Listener->Partitioned) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_PARTITIONED;
        UdpConfig.PartitionIndex = Listener->PartitionIndex;
    }

    // for RAW datapath
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

    if (MsQuicLib.Settings.XdpEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    if (MsQuicLib.Settings.QTIPEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
    }

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
    CxPlatRefInitialize(&Listener->StartRefCount);

    Status = QuicBindingRegisterListener(Listener->Binding, Listener);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "Register with binding");
        QuicListenerStartRelease(Listener, FALSE);
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
    CXPLAT_PASSIVE_CODE();
    CXPLAT_FRE_ASSERT(Listener->ClientCallbackHandler);
    CXPLAT_DBG_ASSERT(!Listener->Partitioned || QuicListenerIsOnWorker(Listener));
    return
        Listener->ClientCallbackHandler(
            (HQUIC)Listener,
            Listener->ClientContext,
            Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicListenerIndicateDispatchEvent(
    _In_ QUIC_LISTENER* Listener,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    CXPLAT_DBG_ASSERT(Event->Type == QUIC_LISTENER_EVENT_DOS_MODE_CHANGED);
    CXPLAT_DBG_ASSERT(!Listener->Partitioned || QuicListenerIsOnWorker(Listener));
    CXPLAT_FRE_ASSERT(Listener->ClientCallbackHandler);
    return
        Listener->ClientCallbackHandler(
            (HQUIC)Listener,
            Listener->ClientContext,
            Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerEndStopComplete(
    _In_ QUIC_LISTENER* Listener
    )
{
    Listener->Stopped = TRUE;
    CxPlatEventSet(Listener->StopEvent);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerIndicateStopComplete(
    _In_ QUIC_LISTENER* Listener
    )
{
    QUIC_LISTENER_EVENT Event;
    Event.Type = QUIC_LISTENER_EVENT_STOP_COMPLETE;
    Event.STOP_COMPLETE.AppCloseInProgress = Listener->AppClosed;

    //
    // Take an internal cleanup reference to prevent an inline ListenerClose
    // freeing the listener from under us.
    //
    QuicListenerReference(Listener);

    QuicListenerAttachSilo(Listener);

    QuicTraceLogVerbose(
        ListenerIndicateStopComplete,
        "[list][%p] Indicating STOP_COMPLETE",
        Listener);

    Listener->StopCompleteThreadID = CxPlatCurThreadID();
    (void)QuicListenerIndicateEvent(Listener, &Event);
    Listener->StopCompleteThreadID = 0;

    QuicListenerDetachSilo();

    QuicListenerRelease(Listener);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerBeginStopComplete(
    _In_ QUIC_LISTENER* Listener,
    _In_ BOOLEAN IndicateEvent
    )
{
    BOOLEAN EndStopComplete = TRUE;

    QuicTraceEvent(
        ListenerStopped,
        "[list][%p] Stopped",
        Listener);

    //
    // Ensure the listener is not freed while processing this function.
    //
    QuicListenerReference(Listener);

    if (Listener->AlpnList != NULL) {
        CXPLAT_FREE(Listener->AlpnList, QUIC_POOL_ALPN);
        Listener->AlpnList = NULL;
    }

    if (IndicateEvent) {
        if (Listener->Partitioned) {
            EndStopComplete = FALSE;
            Listener->NeedsStopCompleteEvent = TRUE;
            QuicWorkerQueueListener(Listener->Worker, Listener);
        } else {
            QuicListenerIndicateStopComplete(Listener);
        }
    }

    if (EndStopComplete) {
        QuicListenerEndStopComplete(Listener);
    }

    QuicListenerRelease(Listener);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicListenerStartReference(
    _In_ QUIC_LISTENER* Listener
    )
{
    CxPlatRefIncrement(&Listener->StartRefCount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerStartRelease(
    _In_ QUIC_LISTENER* Listener,
    _In_ BOOLEAN IndicateEvent
    )
{
    if (CxPlatRefDecrement(&Listener->StartRefCount)) {
        QuicListenerBeginStopComplete(Listener, IndicateEvent);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicListenerReference(
    _In_ QUIC_LISTENER* Listener
    )
{
    CxPlatRefIncrement(&Listener->RefCount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerRelease(
    _In_ QUIC_LISTENER* Listener
    )
{
    if (CxPlatRefDecrement(&Listener->RefCount)) {
        QuicListenerFree(Listener);
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

        QuicListenerStartRelease(Listener, TRUE);
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

    if (Listener->Partitioned) {
        Connection->State.Partitioned = TRUE;
        //
        // The connection should not have already migrated partitions within a
        // partitioned listener above a a partitioned binding. The current
        // thread should also be within the partition by the same virtue, and is
        // asserted in QuicListenerIndicateEvent.
        //
        CXPLAT_DBG_ASSERT(Connection->Partition->Index == Listener->PartitionIndex);
    }

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

    if (!Connection->State.ShutdownComplete) {
        Connection->State.UpdateWorker = TRUE;
    }

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
        QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_LOAD_REJECT);
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
        QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_APP_REJECT);
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

    if (Param == QUIC_PARAM_DOS_MODE_EVENTS) {
        if (BufferLength == sizeof(BOOLEAN)) {
            Listener->DosModeEventsEnabled = *(BOOLEAN*)Buffer;
            if (MsQuicLib.SendRetryEnabled && Listener->DosModeEventsEnabled) {
                QuicListenerHandleDosModeStateChange(Listener, MsQuicLib.SendRetryEnabled, FALSE);
            }
            return QUIC_STATUS_SUCCESS;
        }
    }

    if (Param == QUIC_PARAM_LISTENER_PARTITION_INDEX) {
        uint16_t PartitionIndex;
        if (BufferLength != sizeof(uint16_t)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        PartitionIndex = *(uint16_t*)Buffer;
        if (PartitionIndex >= MsQuicLib.PartitionCount ||
            Listener->Registration->NoPartitioning ||
            Listener->Partitioned ||
            !Listener->Stopped) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
#if defined(__linux__) && !defined(CXPLAT_USE_IO_URING) && !defined(CXPLAT_LINUX_XDP_ENABLED)
        Listener->PartitionIndex = PartitionIndex;
        Listener->Partitioned = TRUE;
        QuicWorkerAssignListener(
            &Listener->Registration->WorkerPool->Workers[PartitionIndex], Listener);
        QuicTraceLogVerbose(
            ListenerPartitionIndexSet,
            "[list][%p] PartitionIndex set (index %hu)",
            Listener,
            Listener->PartitionIndex);
        return QUIC_STATUS_SUCCESS;
#else
        return QUIC_STATUS_NOT_SUPPORTED;
#endif
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

    case QUIC_PARAM_DOS_MODE_EVENTS:

        if (*BufferLength < sizeof(Listener->DosModeEventsEnabled)) {
            *BufferLength = sizeof(Listener->DosModeEventsEnabled);
            return QUIC_STATUS_BUFFER_TOO_SMALL;
        }

        if (Buffer == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        *BufferLength = sizeof(Listener->DosModeEventsEnabled);
        memcpy(Buffer, &Listener->DosModeEventsEnabled, sizeof(Listener->DosModeEventsEnabled));
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_LISTENER_PARTITION_INDEX:

        if (*BufferLength < sizeof(Listener->PartitionIndex)) {
            *BufferLength = sizeof(Listener->PartitionIndex);
            return QUIC_STATUS_BUFFER_TOO_SMALL;
        }

        if (Buffer == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (!Listener->Partitioned) {
            return QUIC_STATUS_INVALID_STATE;
        }

        *BufferLength = sizeof(Listener->PartitionIndex);
        *(uint16_t*)Buffer = Listener->PartitionIndex;
        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicListenerHandleDosModeStateChange(
    _In_ QUIC_LISTENER* Listener,
    _In_ BOOLEAN DosModeEnabled,
    _In_ BOOLEAN OnWorker
    )
{
    if (Listener->DosModeEventsEnabled) {
        if (!Listener->Partitioned || OnWorker) {
            QUIC_LISTENER_EVENT Event;
            Event.Type = QUIC_LISTENER_EVENT_DOS_MODE_CHANGED;
            Event.DOS_MODE_CHANGED.DosModeEnabled = DosModeEnabled;

            QuicListenerAttachSilo(Listener);

            (void)QuicListenerIndicateDispatchEvent(Listener, &Event);

            QuicListenerDetachSilo();
        } else {
            //
            // Best effort mode synchronization: the non-partitioned case is
            // also racy.
            //
            Listener->DosModeEnabled = DosModeEnabled;
            if (!InterlockedFetchAndSetBoolean(&Listener->NeedsDosModeModeEvent)) {
                QuicListenerStartReference(Listener);
                QuicWorkerQueueListener(Listener->Worker, Listener);
            }
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicListenerDrainOperations(
    _In_ QUIC_LISTENER* Listener
    )
{
    CXPLAT_PASSIVE_CODE();

    if (Listener->NeedsDosModeModeEvent) {
        BOOLEAN DosModeEnabled;
        CXPLAT_FRE_ASSERT(InterlockedFetchAndClearBoolean(&Listener->NeedsDosModeModeEvent));
        DosModeEnabled = Listener->DosModeEnabled;
        QuicListenerHandleDosModeStateChange(Listener, DosModeEnabled, TRUE);
        QuicListenerStartRelease(Listener, TRUE);
    }

    if (Listener->NeedsStopCompleteEvent) {
        Listener->NeedsStopCompleteEvent = FALSE;
        //
        // This must be the final event indication.
        //
        QuicListenerIndicateStopComplete(Listener);
        QuicListenerEndStopComplete(Listener);
    }

    return FALSE;
}
