/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The connection is the topmost structure that all connection-specific state
    and logic is derived from. Connections are only ever processed by one
    thread at a time. Other threads may queue operations on the connection, but
    the operations are only drained and processed serially, by a single thread;
    though the thread that does the draining may change over time. All
    events/triggers/API calls are processed via operations.

    The connection drains operations in the QuicConnDrainOperations function.
    The only requirement here is that this function is not called in parallel
    on multiple threads. The function will drain up to QUIC_SETTINGS_INTERNAL's
    MaxOperationsPerDrain operations per call, so as to not starve any other
    work.

    While most of the connection specific work is managed by other modules,
    the following things are managed in this file:

    Connection Lifetime - Initialization, handshake and state changes, shutdown,
    closure and cleanup are located here.

    Receive Path - The per-connection packet receive path is here. This is the
    logic that happens after the global receive callback has processed the
    packet initially and done the necessary processing to pass the packet to
    the correct connection.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "connection.c.clog.h"
#endif

typedef struct QUIC_RECEIVE_PROCESSING_STATE {
    BOOLEAN ResetIdleTimeout;
    BOOLEAN UpdatePartitionId;
    uint16_t PartitionIndex;
} QUIC_RECEIVE_PROCESSING_STATE;


_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnApplyNewSettings(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OverWrite,
    _In_ const QUIC_SETTINGS_INTERNAL* NewSettings
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicConnAlloc(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_PARTITION* Partition,
    _In_opt_ QUIC_WORKER* Worker,
    _In_opt_ const QUIC_RX_PACKET* Packet,
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem))
        QUIC_CONNECTION** NewConnection
    )
{
    BOOLEAN IsServer = Packet != NULL;
    *NewConnection = NULL;
    QUIC_STATUS Status;

    const uint16_t PartitionId = QuicPartitionIdCreate(Partition->Index);
    CXPLAT_DBG_ASSERT(Partition->Index == QuicPartitionIdGetIndex(PartitionId));

    QUIC_CONNECTION* Connection = CxPlatPoolAlloc(&Partition->ConnectionPool);
    if (Connection == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Connection, sizeof(QUIC_CONNECTION));
    Connection->Partition = Partition;

#if DEBUG
    InterlockedIncrement(&MsQuicLib.ConnectionCount);
#endif
    QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_CREATED);
    QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_ACTIVE);

    Connection->Stats.CorrelationId =
        InterlockedIncrement64((int64_t*)&MsQuicLib.ConnectionCorrelationId) - 1;
    QuicTraceEvent(
        ConnCreated,
        "[conn][%p] Created, IsServer=%hhu, CorrelationId=%llu",
        Connection,
        IsServer,
        Connection->Stats.CorrelationId);

    Connection->RefCount = 1;
#if DEBUG
    Connection->RefTypeCount[QUIC_CONN_REF_HANDLE_OWNER] = 1;
#endif
    Connection->PartitionID = PartitionId;
    Connection->State.Allocated = TRUE;
    Connection->State.ShareBinding = IsServer;
    Connection->State.FixedBit = TRUE;
    Connection->Stats.Timing.Start = CxPlatTimeUs64();
    Connection->SourceCidLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
    Connection->AckDelayExponent = QUIC_ACK_DELAY_EXPONENT;
    Connection->PacketTolerance = QUIC_MIN_ACK_SEND_NUMBER;
    Connection->PeerPacketTolerance = QUIC_MIN_ACK_SEND_NUMBER;
    Connection->ReorderingThreshold = QUIC_MIN_REORDERING_THRESHOLD;
    Connection->PeerReorderingThreshold = QUIC_MIN_REORDERING_THRESHOLD;
    Connection->PeerTransportParams.AckDelayExponent = QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT;
    Connection->ReceiveQueueTail = &Connection->ReceiveQueue;
    QuicSettingsCopy(&Connection->Settings, &MsQuicLib.Settings);
    Connection->Settings.IsSetFlags = 0; // Just grab the global values, not IsSet flags.
    CxPlatDispatchLockInitialize(&Connection->ReceiveQueueLock);
    CxPlatListInitializeHead(&Connection->DestCids);
    QuicStreamSetInitialize(&Connection->Streams);
    QuicSendBufferInitialize(&Connection->SendBuffer);
    QuicOperationQueueInitialize(&Connection->OperQ);
    QuicSendInitialize(&Connection->Send, &Connection->Settings);
    QuicCongestionControlInitialize(&Connection->CongestionControl, &Connection->Settings);
    QuicLossDetectionInitialize(&Connection->LossDetection);
    QuicDatagramInitialize(&Connection->Datagram);
    QuicRangeInitialize(
        QUIC_MAX_RANGE_DECODE_ACKS,
        &Connection->DecodedAckRanges);

    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); i++) {
        Status =
            QuicPacketSpaceInitialize(
                Connection,
                (QUIC_ENCRYPT_LEVEL)i,
                &Connection->Packets[i]);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    QUIC_PATH* Path = &Connection->Paths[0];
    QuicPathInitialize(Connection, Path);
    Path->IsActive = TRUE;
    Connection->PathsCount = 1;

    Connection->EarliestExpirationTime = UINT64_MAX;
    for (QUIC_CONN_TIMER_TYPE Type = 0; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        Connection->ExpirationTimes[Type] = UINT64_MAX;
    }

    if (IsServer) {

        Connection->Type = QUIC_HANDLE_TYPE_CONNECTION_SERVER;
        if (MsQuicLib.Settings.LoadBalancingMode == QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            CxPlatRandom(1, Connection->ServerID); // Randomize the first byte.
            if (QuicAddrGetFamily(&Packet->Route->LocalAddress) == QUIC_ADDRESS_FAMILY_INET) {
                CxPlatCopyMemory(
                    Connection->ServerID + 1,
                    &Packet->Route->LocalAddress.Ipv4.sin_addr,
                    4);
            } else {
                CxPlatCopyMemory(
                    Connection->ServerID + 1,
                    ((uint8_t*)&Packet->Route->LocalAddress.Ipv6.sin6_addr) + 12,
                    4);
            }
        } else if (MsQuicLib.Settings.LoadBalancingMode == QUIC_LOAD_BALANCING_SERVER_ID_FIXED) {
            CxPlatRandom(1, Connection->ServerID); // Randomize the first byte.
            CxPlatCopyMemory(
                Connection->ServerID + 1,
                &MsQuicLib.Settings.FixedServerID,
                sizeof(MsQuicLib.Settings.FixedServerID));
        }

        Connection->Stats.QuicVersion = Packet->Invariant->LONG_HDR.Version;
        QuicConnOnQuicVersionSet(Connection);
        QuicCopyRouteInfo(&Path->Route, Packet->Route);
        Connection->State.LocalAddressSet = TRUE;
        Connection->State.RemoteAddressSet = TRUE;

        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));

        QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress));

        Path->DestCid =
            QuicCidNewDestination(Packet->SourceCidLen, Packet->SourceCid);
        if (Path->DestCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        QUIC_CID_SET_PATH(Connection, Path->DestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;
        CxPlatListInsertTail(&Connection->DestCids, &Path->DestCid->Link);
        QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));

        QUIC_CID_HASH_ENTRY* SourceCid =
            QuicCidNewSource(Connection, Packet->DestCidLen, Packet->DestCid);
        if (SourceCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        SourceCid->CID.IsInitial = TRUE;
        SourceCid->CID.UsedByPeer = TRUE;
        CxPlatListPushEntry(&Connection->SourceCids, &SourceCid->Link);
        QuicTraceEvent(
            ConnSourceCidAdded,
            "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
            Connection,
            SourceCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));

        //
        // Server lazily finishes initialization in response to first operation.
        //

    } else {
        Connection->Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection->State.ExternalOwner = TRUE;
        Path->IsPeerValidated = TRUE;
        Path->Allowance = UINT32_MAX;

        Path->DestCid = QuicCidNewRandomDestination();
        if (Path->DestCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        QUIC_CID_SET_PATH(Connection, Path->DestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;
        Connection->DestCidCount++;
        CxPlatListInsertTail(&Connection->DestCids, &Path->DestCid->Link);
        QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));

        Connection->State.Initialized = TRUE;
        QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
    }

    QuicPathValidate(Path);
    if (Worker != NULL) {
        QuicWorkerAssignConnection(Worker, Connection);
    }
    if (!QuicConnRegister(Connection, Registration)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    *NewConnection = Connection;
    return QUIC_STATUS_SUCCESS;

Error:

    Connection->State.HandleClosed = TRUE;
    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); i++) {
        if (Connection->Packets[i] != NULL) {
            QuicPacketSpaceUninitialize(Connection->Packets[i]);
            Connection->Packets[i] = NULL;
        }
    }
    if (Packet != NULL && Connection->SourceCids.Next != NULL) {
        CXPLAT_FREE(
            CXPLAT_CONTAINING_RECORD(
                Connection->SourceCids.Next,
                QUIC_CID_HASH_ENTRY,
                Link),
            QUIC_POOL_CIDHASH);
        Connection->SourceCids.Next = NULL;
    }
    while (!CxPlatListIsEmpty(&Connection->DestCids)) {
        QUIC_CID_LIST_ENTRY *CID =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->DestCids),
                QUIC_CID_LIST_ENTRY,
                Link);
        CXPLAT_FREE(CID, QUIC_POOL_CIDLIST);
    }
    QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnFree(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection
    )
{
    QUIC_PARTITION* Partition = Connection->Partition;
    CXPLAT_FRE_ASSERT(!Connection->State.Freed);
    CXPLAT_TEL_ASSERT(Connection->RefCount == 0);
    if (Connection->State.ExternalOwner) {
        CXPLAT_TEL_ASSERT(Connection->State.HandleClosed);
    }
    CXPLAT_TEL_ASSERT(Connection->SourceCids.Next == NULL);
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Connection->Streams.ClosedStreams));
    QuicRangeUninitialize(&Connection->DecodedAckRanges);
    QuicCryptoUninitialize(&Connection->Crypto);
    QuicLossDetectionUninitialize(&Connection->LossDetection);
    QuicSendUninitialize(&Connection->Send);
    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); i++) {
        if (Connection->Packets[i] != NULL) {
            QuicPacketSpaceUninitialize(Connection->Packets[i]);
            Connection->Packets[i] = NULL;
        }
    }
#if DEBUG
    while (!CxPlatListIsEmpty(&Connection->Streams.AllStreams)) {
        QUIC_STREAM *Stream =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->Streams.AllStreams),
                QUIC_STREAM,
                AllStreamsLink);
        CXPLAT_DBG_ASSERTMSG(Stream != NULL, "Stream was leaked!");
    }
#endif
    while (!CxPlatListIsEmpty(&Connection->DestCids)) {
        QUIC_CID_LIST_ENTRY *CID =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->DestCids),
                QUIC_CID_LIST_ENTRY,
                Link);
        CXPLAT_FREE(CID, QUIC_POOL_CIDLIST);
    }
    QuicConnUnregister(Connection);
    if (Connection->Worker != NULL) {
        QuicTimerWheelRemoveConnection(&Connection->Worker->TimerWheel, Connection);
        QuicOperationQueueClear(&Connection->OperQ, Partition);
    }
    if (Connection->ReceiveQueue != NULL) {
        QUIC_RX_PACKET* Packet = Connection->ReceiveQueue;
        do {
            Packet->QueuedOnConnection = FALSE;
        } while ((Packet = (QUIC_RX_PACKET*)Packet->Next) != NULL);
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)Connection->ReceiveQueue);
        Connection->ReceiveQueue = NULL;
    }
    QUIC_PATH* Path = &Connection->Paths[0];
    if (Path->Binding != NULL) {
        QuicLibraryReleaseBinding(Path->Binding);
        Path->Binding = NULL;
    }
    CxPlatDispatchLockUninitialize(&Connection->ReceiveQueueLock);
    QuicOperationQueueUninitialize(&Connection->OperQ);
    QuicStreamSetUninitialize(&Connection->Streams);
    QuicSendBufferUninitialize(&Connection->SendBuffer);
    QuicDatagramSendShutdown(&Connection->Datagram);
    QuicDatagramUninitialize(&Connection->Datagram);
    if (Connection->Configuration != NULL) {
        QuicConfigurationRelease(Connection->Configuration);
        Connection->Configuration = NULL;
    }
    if (Connection->RemoteServerName != NULL) {
        CXPLAT_FREE(Connection->RemoteServerName, QUIC_POOL_SERVERNAME);
    }
    if (Connection->OrigDestCID != NULL) {
        CXPLAT_FREE(Connection->OrigDestCID, QUIC_POOL_CID);
    }
    if (Connection->HandshakeTP != NULL) {
        QuicCryptoTlsCleanupTransportParameters(Connection->HandshakeTP);
        CxPlatPoolFree(Connection->HandshakeTP);
        Connection->HandshakeTP = NULL;
    }
    QuicCryptoTlsCleanupTransportParameters(&Connection->PeerTransportParams);
    QuicSettingsCleanup(&Connection->Settings);
    if (Connection->State.Started && !Connection->State.Connected) {
        QuicPerfCounterIncrement(Partition, QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL);
    }
    if (Connection->State.Connected) {
        QuicPerfCounterDecrement(Partition, QUIC_PERF_COUNTER_CONN_CONNECTED);
    }
    if (Connection->Registration != NULL) {
        CxPlatRundownRelease(&Connection->Registration->Rundown);
    }
    if (Connection->CloseReasonPhrase != NULL) {
        CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
    }
    Connection->State.Freed = TRUE;
    QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
    CxPlatPoolFree(Connection);

#if DEBUG
    InterlockedDecrement(&MsQuicLib.ConnectionCount);
#endif
    QuicPerfCounterDecrement(Partition, QUIC_PERF_COUNTER_CONN_ACTIVE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnShutdown(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ QUIC_VAR_INT ErrorCode,
    _In_ BOOLEAN ShutdownFromRegistration,
    _In_ BOOLEAN ShutdownFromTransport
    )
{
    if (ShutdownFromRegistration &&
        !Connection->State.Started &&
        QuicConnIsClient(Connection)) {
        return;
    }

    uint32_t CloseFlags =
        ShutdownFromTransport ? QUIC_CLOSE_INTERNAL : QUIC_CLOSE_APPLICATION;
    if (Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT ||
        (!Connection->State.Started && QuicConnIsClient(Connection))) {
        CloseFlags |= QUIC_CLOSE_SILENT;
    }
    if (Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_STATUS) {
        CloseFlags |= QUIC_CLOSE_QUIC_STATUS;
    }

    QuicConnCloseLocally(Connection, CloseFlags, ErrorCode, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnCloseHandle(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_TEL_ASSERT(!Connection->State.HandleClosed);
    Connection->State.HandleClosed = TRUE;

    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_SILENT | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)QUIC_STATUS_ABORTED,
        NULL);

    if (Connection->State.ProcessShutdownComplete) {
        QuicConnOnShutdownComplete(Connection);
    }

    QuicConnUnregister(Connection);

    QuicTraceEvent(
        ConnHandleClosed,
        "[conn][%p] Handle closed",
        Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnUnregister(
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->State.Registered) {
        CxPlatDispatchLockAcquire(&Connection->Registration->ConnectionLock);
        CxPlatListEntryRemove(&Connection->RegistrationLink);
        CxPlatDispatchLockRelease(&Connection->Registration->ConnectionLock);
        CxPlatRundownRelease(&Connection->Registration->Rundown);

        QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
        Connection->Registration = NULL;
        Connection->State.Registered = FALSE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
QuicConnRegister(
    _Inout_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_REGISTRATION* Registration
    )
{
    QuicConnUnregister(Connection);

    if (!CxPlatRundownAcquire(&Registration->Rundown)) {
        return FALSE;
    }
    Connection->State.Registered = TRUE;
    Connection->Registration = Registration;
#ifdef CxPlatVerifierEnabledByAddr
    Connection->State.IsVerifying = Registration->IsVerifying;
#endif
    BOOLEAN RegistrationShuttingDown;

    CxPlatDispatchLockAcquire(&Registration->ConnectionLock);
    RegistrationShuttingDown = Registration->ShuttingDown;
    if (!RegistrationShuttingDown) {
        if (Connection->Worker == NULL) {
            QuicRegistrationQueueNewConnection(Registration, Connection);
        }
        CxPlatListInsertTail(&Registration->Connections, &Connection->RegistrationLink);
    }
    CxPlatDispatchLockRelease(&Registration->ConnectionLock);

    if (RegistrationShuttingDown) {
        Connection->State.Registered = FALSE;
        Connection->Registration = NULL;
        CxPlatRundownRelease(&Registration->Rundown);
    } else {
        QuicTraceEvent(
            ConnRegistered,
            "[conn][%p] Registered with %p",
            Connection,
            Registration);
    }

    return !RegistrationShuttingDown;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueTraceRundown(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_OPERATION* Oper;
    if ((Oper = QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_TRACE_RUNDOWN)) != NULL) {
        QuicConnQueueOper(Connection, Oper);
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "trace rundown operation",
            0);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTraceRundownOper(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnRundown,
        "[conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu",
        Connection,
        QuicConnIsServer(Connection),
        Connection->Stats.CorrelationId);
    QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Connection->Worker);
    QuicTraceEvent(
        ConnEcnCapable,
        "[conn][%p] Ecn: IsCapable=%hu",
        Connection,
        Connection->Paths[0].EcnValidationState == ECN_VALIDATION_CAPABLE);
    CXPLAT_DBG_ASSERT(Connection->Registration);
    QuicTraceEvent(
        ConnRegistered,
        "[conn][%p] Registered with %p",
        Connection,
        Connection->Registration);
    if (Connection->Stats.QuicVersion != 0) {
        QuicTraceEvent(
            ConnVersionSet,
            "[conn][%p] QUIC Version: 0x%x",
            Connection,
            Connection->Stats.QuicVersion);
    }
    if (Connection->State.Started) {
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (Connection->State.LocalAddressSet || i != 0) {
                QuicTraceEvent(
                    ConnLocalAddrAdded,
                     "[conn][%p] New Local IP: %!ADDR!",
                    Connection,
                    CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].Route.LocalAddress), &Connection->Paths[i].Route.LocalAddress));
            }
            if (Connection->State.RemoteAddressSet || i != 0) {
                QuicTraceEvent(
                    ConnRemoteAddrAdded,
                    "[conn][%p] New Remote IP: %!ADDR!",
                    Connection,
                    CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].Route.RemoteAddress), &Connection->Paths[i].Route.RemoteAddress));
            }
        }
        for (CXPLAT_SLIST_ENTRY* Entry = Connection->SourceCids.Next;
                Entry != NULL;
                Entry = Entry->Next) {
            const QUIC_CID_HASH_ENTRY* SourceCid =
                CXPLAT_CONTAINING_RECORD(
                    Entry,
                    QUIC_CID_HASH_ENTRY,
                    Link);
            UNREFERENCED_PARAMETER(SourceCid);
            QuicTraceEvent(
                ConnSourceCidAdded,
                "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
                Connection,
                SourceCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
        }
        for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
                Entry != &Connection->DestCids;
                Entry = Entry->Flink) {
            const QUIC_CID_LIST_ENTRY* DestCid =
                CXPLAT_CONTAINING_RECORD(
                    Entry,
                    QUIC_CID_LIST_ENTRY,
                    Link);
            UNREFERENCED_PARAMETER(DestCid);
            QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                Connection,
                DestCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
        }
    }
    if (Connection->State.Connected) {
        QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);
    }
    if (Connection->State.HandleClosed) {
        QuicTraceEvent(
            ConnHandleClosed,
            "[conn][%p] Handle closed",
            Connection);
    }
    if (Connection->State.Started) {
        QuicConnLogStatistics(Connection);
    }

    QuicStreamSetTraceRundown(&Connection->Streams);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnIndicateEvent(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    CXPLAT_PASSIVE_CODE();
    QUIC_STATUS Status;
    if (Connection->ClientCallbackHandler != NULL) {
        //
        // MsQuic shouldn't indicate reentrancy to the app when at all possible.
        // The general exception to this rule is when the connection is being
        // closed because the API MUST block until all work is completed, so we
        // have to execute the event callbacks inline.
        //
        CXPLAT_DBG_ASSERT(
            !Connection->State.InlineApiExecution ||
            Connection->State.HandleClosed);
        Status =
            Connection->ClientCallbackHandler(
                (HQUIC)Connection,
                Connection->ClientContext,
                Event);
    } else {
        QUIC_CONN_VERIFY(
            Connection,
            Connection->State.HandleClosed ||
                Connection->State.ShutdownComplete ||
                !Connection->State.ExternalOwner);
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogConnWarning(
            ApiEventNoHandler,
            Connection,
            "Event silently discarded (no handler).");
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
#if DEBUG
    if (!Connection->State.Initialized) {
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        CXPLAT_DBG_ASSERT(Connection->SourceCids.Next != NULL || CxPlatIsRandomMemoryFailureEnabled());
    }
    if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
        if (Oper->API_CALL.Context->Type == QUIC_API_TYPE_CONN_SHUTDOWN) {
            CXPLAT_DBG_ASSERT(
                (Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode <= QUIC_VAR_INT_MAX) ||
                (Oper->API_CALL.Context->CONN_SHUTDOWN.Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_STATUS));
        }
    }
#endif
    if (QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueueConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueuePriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
#if DEBUG
    if (!Connection->State.Initialized) {
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        CXPLAT_DBG_ASSERT(Connection->SourceCids.Next != NULL || CxPlatIsRandomMemoryFailureEnabled());
    }
#endif
    if (QuicOperationEnqueuePriority(
            &Connection->OperQ,
            Connection->Partition,
            Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueuePriorityConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueHighestPriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
    if (QuicOperationEnqueueFront(
            &Connection->OperQ,
            Connection->Partition,
            Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueuePriorityConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdateRtt(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint64_t LatestRtt,
    _In_ uint64_t OurSendTimestamp,
    _In_ uint64_t PeerSendTimestamp
    )
{
    if (LatestRtt == 0) {
        //
        // RTT cannot be zero or several loss recovery algorithms break down.
        //
        LatestRtt = 1;
    }

    BOOLEAN NewMinRtt = FALSE;
    Path->LatestRttSample = LatestRtt;
    if (LatestRtt < Path->MinRtt) {
        Path->MinRtt = LatestRtt;
        NewMinRtt = TRUE;
    }
    if (LatestRtt > Path->MaxRtt) {
        Path->MaxRtt = LatestRtt;
    }

    if (!Path->GotFirstRttSample) {
        Path->GotFirstRttSample = TRUE;
        Path->SmoothedRtt = LatestRtt;
        Path->RttVariance = LatestRtt / 2;

    } else {
        if (Path->SmoothedRtt > LatestRtt) {
            Path->RttVariance = (3 * Path->RttVariance + Path->SmoothedRtt - LatestRtt) / 4;
        } else {
            Path->RttVariance = (3 * Path->RttVariance + LatestRtt - Path->SmoothedRtt) / 4;
        }
        Path->SmoothedRtt = (7 * Path->SmoothedRtt + LatestRtt) / 8;
    }

    if (OurSendTimestamp != UINT64_MAX) {
        if (Connection->Stats.Timing.PhaseShift == 0 || NewMinRtt) {
            Connection->Stats.Timing.PhaseShift =
                (int64_t)PeerSendTimestamp - (int64_t)OurSendTimestamp - (int64_t)LatestRtt / 2;
            Path->OneWayDelayLatest = Path->OneWayDelay = LatestRtt / 2;
            QuicTraceLogConnVerbose(
                PhaseShiftUpdated,
                Connection,
                "New Phase Shift: %lld us",
                Connection->Stats.Timing.PhaseShift);
        } else {
            Path->OneWayDelayLatest =
                (uint64_t)((int64_t)PeerSendTimestamp - (int64_t)OurSendTimestamp - Connection->Stats.Timing.PhaseShift);
            Path->OneWayDelay = (7 * Path->OneWayDelay + Path->OneWayDelayLatest) / 8;
        }
    }

    CXPLAT_DBG_ASSERT(Path->SmoothedRtt != 0);
    QuicTraceLogConnVerbose(
        RttUpdatedV2,
        Connection,
        "Updated Rtt=%u.%03u ms, Var=%u.%03u 1Way=%u.%03u ms",
        (uint32_t)(Path->SmoothedRtt / 1000), (uint32_t)(Path->SmoothedRtt % 1000),
        (uint32_t)(Path->RttVariance / 1000), (uint32_t)(Path->RttVariance % 1000),
        (uint32_t)(Path->OneWayDelay / 1000), (uint32_t)(Path->OneWayDelay % 1000));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_HASH_ENTRY*
QuicConnGenerateNewSourceCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsInitial
    )
{
    uint8_t TryCount = 0;
    QUIC_CID_HASH_ENTRY* SourceCid;

    if (!Connection->State.ShareBinding) {
        //
        // We aren't sharing the binding, therefore aren't actually using a CID.
        // No need to generate a new one.
        //
        return NULL;
    }

    //
    // Keep randomly generating new source CIDs until we find one that doesn't
    // collide with an existing one.
    //

    do {
        SourceCid =
            QuicCidNewRandomSource(
                Connection,
                Connection->ServerID,
                Connection->PartitionID,
                Connection->CibirId[0],
                Connection->CibirId+2);
        if (SourceCid == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "new Src CID",
                sizeof(QUIC_CID_HASH_ENTRY) + MsQuicLib.CidTotalLength);
            QuicConnFatalError(Connection, QUIC_STATUS_INTERNAL_ERROR, NULL);
            return NULL;
        }
        if (!QuicBindingAddSourceConnectionID(Connection->Paths[0].Binding, SourceCid)) {
            CXPLAT_FREE(SourceCid, QUIC_POOL_CIDHASH);
            SourceCid = NULL;
            if (++TryCount > QUIC_CID_MAX_COLLISION_RETRY) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Too many CID collisions");
                QuicConnFatalError(Connection, QUIC_STATUS_INTERNAL_ERROR, NULL);
                return NULL;
            }
            QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                Connection,
                "CID collision, trying again");
        }
    } while (SourceCid == NULL);

    QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
        Connection,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));

    SourceCid->CID.SequenceNumber = Connection->NextSourceCidSequenceNumber++;
    if (SourceCid->CID.SequenceNumber > 0) {
        SourceCid->CID.NeedsToSend = TRUE;
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID);
    }

    if (IsInitial) {
        SourceCid->CID.IsInitial = TRUE;
        CxPlatListPushEntry(&Connection->SourceCids, &SourceCid->Link);
    } else {
        CXPLAT_SLIST_ENTRY** Tail = &Connection->SourceCids.Next;
        while (*Tail != NULL) {
            Tail = &(*Tail)->Next;
        }
        *Tail = &SourceCid->Link;
        SourceCid->Link.Next = NULL;
    }

    return SourceCid;
}

uint8_t
QuicConnSourceCidsCount(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    uint8_t Count = 0;
    const CXPLAT_SLIST_ENTRY* Entry = Connection->SourceCids.Next;
    while (Entry != NULL) {
        ++Count;
        Entry = Entry->Next;
    }
    return Count;
}

//
// This generates new source CIDs for the peer to use to talk to us. If
// indicated, it invalidates all the existing ones, sets a a new retire prior to
// sequence number to send out and generates replacement CIDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnGenerateNewSourceCids(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN ReplaceExistingCids
    )
{
    if (!Connection->State.ShareBinding) {
        //
        // Can't generate any new CIDs, so this is a no-op.
        //
        return;
    }

    //
    // If we're replacing existing ones, then generate all new CIDs (up to the
    // limit). Otherwise, just generate whatever number we need to hit the
    // limit.
    //
    uint8_t NewCidCount;
    if (ReplaceExistingCids) {
        NewCidCount = Connection->SourceCidLimit;
        CXPLAT_SLIST_ENTRY* Entry = Connection->SourceCids.Next;
        while (Entry != NULL) {
            QUIC_CID_HASH_ENTRY* SourceCid =
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_CID_HASH_ENTRY, Link);
            SourceCid->CID.Retired = TRUE;
            Entry = Entry->Next;
        }
    } else {
        uint8_t CurrentCidCount = QuicConnSourceCidsCount(Connection);
        CXPLAT_DBG_ASSERT(CurrentCidCount <= Connection->SourceCidLimit);
        if (CurrentCidCount < Connection->SourceCidLimit) {
            NewCidCount = Connection->SourceCidLimit - CurrentCidCount;
        } else {
            NewCidCount = 0;
        }
    }

    for (uint8_t i = 0; i < NewCidCount; ++i) {
        if (QuicConnGenerateNewSourceCid(Connection, FALSE) == NULL) {
            break;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_LIST_ENTRY*
QuicConnGetUnusedDestCid(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (!DestCid->CID.UsedLocally && !DestCid->CID.Retired) {
            return DestCid;
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRetireCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CID_LIST_ENTRY* DestCid
    )
{
    QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
        Connection,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
    Connection->DestCidCount--;
    DestCid->CID.Retired = TRUE;
    DestCid->CID.NeedsToSend = TRUE;
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID);

    Connection->RetiredDestCidCount++;
    if (Connection->RetiredDestCidCount > 8 * QUIC_ACTIVE_CONNECTION_ID_LIMIT) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer exceeded retire CID limit");
        QuicConnSilentlyAbort(Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRetireCurrentDestCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    if (Path->DestCid->CID.Length == 0) {
        QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            Connection,
            "Can't retire current CID because it's zero length");
        return TRUE; // No need to update so treat as success.
    }

    QUIC_CID_LIST_ENTRY* NewDestCid = QuicConnGetUnusedDestCid(Connection);
    if (NewDestCid == NULL) {
        QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            Connection,
            "Can't retire current CID because we don't have a replacement");
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(Path->DestCid != NewDestCid);
    QUIC_CID_LIST_ENTRY* OldDestCid = Path->DestCid;
    QUIC_CID_CLEAR_PATH(Path->DestCid);
    QuicConnRetireCid(Connection, Path->DestCid);
    Path->DestCid = NewDestCid;
    QUIC_CID_SET_PATH(Connection, Path->DestCid, Path);
    QUIC_CID_VALIDATE_NULL(Connection, OldDestCid);
    Path->DestCid->CID.UsedLocally = TRUE;
    Connection->Stats.Misc.DestCidUpdateCount++;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnOnRetirePriorToUpdated(
    _In_ QUIC_CONNECTION* Connection
    )
{
    BOOLEAN ReplaceRetiredCids = FALSE;

    for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (DestCid->CID.SequenceNumber >= Connection->RetirePriorTo ||
            DestCid->CID.Retired) {
            continue;
        }

        if (DestCid->CID.UsedLocally) {
            ReplaceRetiredCids = TRUE;
        }

        QUIC_CID_CLEAR_PATH(DestCid);
        QuicConnRetireCid(Connection, DestCid);
    }

    return ReplaceRetiredCids;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnReplaceRetiredCids(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->DestCid == NULL || !Path->DestCid->CID.Retired) {
            continue;
        }

        QUIC_CID_VALIDATE_NULL(Connection, Path->DestCid); // Previously cleared on retire.
        QUIC_CID_LIST_ENTRY* NewDestCid = QuicConnGetUnusedDestCid(Connection);
        if (NewDestCid == NULL) {
            if (Path->IsActive) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Active path has no replacement for retired CID");
                QuicConnSilentlyAbort(Connection); // Must silently abort because we can't send anything now.
                return FALSE;
            }
            QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                Connection,
                "Non-active path has no replacement for retired CID.");
            CXPLAT_DBG_ASSERT(i != 0);
            QuicPathRemove(Connection, i--);
            continue;
        }

        CXPLAT_DBG_ASSERT(NewDestCid != Path->DestCid);
        Path->DestCid = NewDestCid;
        QUIC_CID_SET_PATH(Connection, NewDestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;
        Path->InitiatedCidUpdate = TRUE;
        QuicPathValidate(Path);
    }

#if DEBUG
    for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        CXPLAT_DBG_ASSERT(!DestCid->CID.Retired || DestCid->AssignedPath == NULL);
    }
#endif

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicGetEarliestExpirationTime(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    uint64_t EarliestExpirationTime = Connection->ExpirationTimes[0];
    for (QUIC_CONN_TIMER_TYPE Type = 1; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        if (Connection->ExpirationTimes[Type] < EarliestExpirationTime) {
            EarliestExpirationTime = Connection->ExpirationTimes[Type];
        }
    }
    return EarliestExpirationTime;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerSetEx(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type,
    _In_ uint64_t Delay,
    _In_ uint64_t TimeNow
    )
{
    const uint64_t NewExpirationTime = TimeNow + Delay;

    QuicTraceEvent(
        ConnSetTimer,
        "[conn][%p] Setting %hhu, delay=%llu us",
        Connection,
        (uint8_t)Type,
        Delay);

    Connection->ExpirationTimes[Type] = NewExpirationTime;
    uint64_t NewEarliestExpirationTime  = QuicGetEarliestExpirationTime(Connection);
    if (NewEarliestExpirationTime != Connection->EarliestExpirationTime) {
        Connection->EarliestExpirationTime = NewEarliestExpirationTime;
        QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerCancel(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type
    )
{
    CXPLAT_DBG_ASSERT(Connection->EarliestExpirationTime <= Connection->ExpirationTimes[Type]);

    if (Connection->EarliestExpirationTime == UINT64_MAX) {
        //
        // No timers are currently scheduled.
        //
        return;
    }

    if (Connection->ExpirationTimes[Type] == Connection->EarliestExpirationTime) {
        //
        // We might be canceling the earliest timer, so we need to find the new
        // expiration time for this connection.
        //
        Connection->ExpirationTimes[Type] = UINT64_MAX;
        uint64_t NewEarliestExpirationTime = QuicGetEarliestExpirationTime(Connection);

        if (NewEarliestExpirationTime != Connection->EarliestExpirationTime) {
            //
            // We've either found a new earliest expiration time, or there will be no timers scheduled.
            //
            Connection->EarliestExpirationTime = NewEarliestExpirationTime;
            QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);
        }
    } else {
        Connection->ExpirationTimes[Type] = UINT64_MAX;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerExpired(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ uint64_t TimeNow
    )
{
    BOOLEAN FlushSendImmediate = FALSE;

    Connection->EarliestExpirationTime = UINT64_MAX;

    //
    // Queue up operations for all expired timers and update the earliest expiration time
    // on the fly. Note that we must not call any functions that might update the timer wheel.
    //
    for (QUIC_CONN_TIMER_TYPE Type = 0; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        if (Connection->ExpirationTimes[Type] <= TimeNow) {
            Connection->ExpirationTimes[Type] = UINT64_MAX;
            QuicTraceEvent(
                ConnExpiredTimer,
                "[conn][%p] %hhu expired",
                Connection,
                (uint8_t)Type);
            if (Type == QUIC_CONN_TIMER_ACK_DELAY) {
                QuicTraceEvent(
                    ConnExecTimerOper,
                    "[conn][%p] Execute: %u",
                    Connection,
                    QUIC_CONN_TIMER_ACK_DELAY);
                QuicSendProcessDelayedAckTimer(&Connection->Send);
                FlushSendImmediate = TRUE;
            } else if (Type == QUIC_CONN_TIMER_PACING) {
                QuicTraceEvent(
                    ConnExecTimerOper,
                    "[conn][%p] Execute: %u",
                    Connection,
                    QUIC_CONN_TIMER_PACING);
                FlushSendImmediate = TRUE;
            } else {
                QUIC_OPERATION* Oper;
                if ((Oper = QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_TIMER_EXPIRED)) != NULL) {
                    Oper->TIMER_EXPIRED.Type = Type;
                    QuicConnQueueOper(Connection, Oper);
                } else {
                    //
                    // TODO: ideally, we should put this event back to the timer wheel
                    // so it can fire again later.
                    //
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "expired timer operation",
                        0);
                }
            }
        } else if (Connection->ExpirationTimes[Type] < Connection->EarliestExpirationTime) {
            Connection->EarliestExpirationTime = Connection->ExpirationTimes[Type];
        }
    }

    QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);

    if (FlushSendImmediate) {
        //
        // We don't want to actually call the flush immediate above as it can
        // cause a new timer to be inserted, messing up timer loop.
        //
        (void)QuicSendFlush(&Connection->Send);
    }
}

//
// Sends a shutdown being notification to the app, which represents the first
// indication that we know the connection is closed (locally or remotely).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnIndicateShutdownBegin(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_CONNECTION_EVENT Event;
    if (Connection->State.AppClosed) {
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
        Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = Connection->CloseErrorCode;
        QuicTraceLogConnVerbose(
            IndicateShutdownByPeer,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]",
            Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
    } else {
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
        Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = Connection->CloseStatus;
        Event.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode = Connection->CloseErrorCode;
        QuicTraceLogConnVerbose(
            IndicateShutdownByTransport,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]",
            Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
    }
    (void)QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnShutdownComplete(
    _In_ QUIC_CONNECTION* Connection
    )
{
    Connection->State.ProcessShutdownComplete = FALSE;
    if (Connection->State.ShutdownComplete) {
        return;
    }
    Connection->State.ShutdownComplete = TRUE;
    Connection->State.UpdateWorker = FALSE;

    QuicTraceEvent(
        ConnShutdownComplete,
        "[conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.",
        Connection,
        Connection->State.ShutdownCompleteTimedOut);

    //
    // Clean up any pending state that is irrelevant now.
    //
    QUIC_PATH* Path = &Connection->Paths[0];
    if (Path->Binding != NULL) {
        if (Path->EncryptionOffloading) {
            QuicPathUpdateQeo(Connection, Path, CXPLAT_QEO_OPERATION_REMOVE);
        }

        //
        // Remove all entries in the binding's lookup tables so we don't get any
        // more packets queued.
        //
        QuicBindingRemoveConnection(Connection->Paths[0].Binding, Connection);
    }

    //
    // Clean up the rest of the internal state.
    //
    QuicTimerWheelRemoveConnection(&Connection->Worker->TimerWheel, Connection);
    QuicLossDetectionUninitialize(&Connection->LossDetection);
    QuicSendUninitialize(&Connection->Send);
    QuicDatagramSendShutdown(&Connection->Datagram);

    if (Connection->State.ExternalOwner) {

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        Event.SHUTDOWN_COMPLETE.HandshakeCompleted =
            Connection->State.Connected;
        Event.SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown =
            !Connection->State.ShutdownCompleteTimedOut;
        Event.SHUTDOWN_COMPLETE.AppCloseInProgress =
            Connection->State.HandleClosed;

        QuicTraceLogConnVerbose(
            IndicateConnectionShutdownComplete,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
        (void)QuicConnIndicateEvent(Connection, &Event);

        // This need to be later than QuicLossDetectionUninitialize to indicate
        // status change of Datagram frame for an app to free its buffer
        Connection->ClientCallbackHandler = NULL;
    } else {
        //
        // If the connection was never indicated to the application, then the
        // "owner" ref still resides with the stack and needs to be released.
        //
        QuicConnUnregister(Connection);
        QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);
    }
}

QUIC_STATUS
QuicErrorCodeToStatus(
    QUIC_VAR_INT ErrorCode
    )
{
    switch (ErrorCode) {
    case QUIC_ERROR_NO_ERROR:                       return QUIC_STATUS_SUCCESS;
    case QUIC_ERROR_CONNECTION_REFUSED:             return QUIC_STATUS_CONNECTION_REFUSED;
    case QUIC_ERROR_PROTOCOL_VIOLATION:             return QUIC_STATUS_PROTOCOL_ERROR;
    case QUIC_ERROR_APPLICATION_ERROR:
    case QUIC_ERROR_CRYPTO_USER_CANCELED:           return QUIC_STATUS_USER_CANCELED;
    case QUIC_ERROR_CRYPTO_HANDSHAKE_FAILURE:       return QUIC_STATUS_HANDSHAKE_FAILURE;
    case QUIC_ERROR_CRYPTO_NO_APPLICATION_PROTOCOL: return QUIC_STATUS_ALPN_NEG_FAILURE;
    case QUIC_ERROR_VERSION_NEGOTIATION_ERROR:      return QUIC_STATUS_VER_NEG_ERROR;
    default:
        if (IS_QUIC_CRYPTO_ERROR(ErrorCode)) {
            return QUIC_STATUS_TLS_ALERT(ErrorCode);
        }
        return QUIC_STATUS_INTERNAL_ERROR;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTryClose(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ uint64_t ErrorCode,
    _In_reads_bytes_opt_(RemoteReasonPhraseLength)
         const char* RemoteReasonPhrase,
    _In_ uint16_t RemoteReasonPhraseLength
    )
{
    BOOLEAN ClosedRemotely = !!(Flags & QUIC_CLOSE_REMOTE);
    BOOLEAN SilentClose = !!(Flags & QUIC_CLOSE_SILENT);

    if ((ClosedRemotely && Connection->State.ClosedRemotely) ||
        (!ClosedRemotely && Connection->State.ClosedLocally)) {
        //
        // Already closed.
        //
        if (SilentClose &&
            Connection->State.ClosedLocally &&
            !Connection->State.ClosedRemotely) {
            //
            // Silent close forced after we already started the close process.
            //
            Connection->State.ShutdownCompleteTimedOut = FALSE;
            Connection->State.ProcessShutdownComplete = TRUE;
        }
        return;
    }

    if (ClosedRemotely) {
        Connection->State.ClosedRemotely = TRUE;
    } else {
        Connection->State.ClosedLocally = TRUE;
        if (!Connection->State.ExternalOwner) {
            //
            // Don't continue processing the connection, since it has been
            // closed locally and it's not referenced externally.
            //
            QuicTraceLogConnVerbose(
                AbandonInternallyClosed,
                Connection,
                "Abandoning internal, closed connection");
            Connection->State.ProcessShutdownComplete = TRUE;
        }
    }

    BOOLEAN ResultQuicStatus = !!(Flags & QUIC_CLOSE_QUIC_STATUS);

    BOOLEAN IsFirstCloseForConnection = TRUE;

    if (ClosedRemotely && !Connection->State.ClosedLocally) {

        //
        // Peer closed first.
        //

        if (!Connection->State.Connected && QuicConnIsClient(Connection)) {
            //
            // If the server terminates a connection attempt, close immediately
            // without going through the draining period.
            //
            SilentClose = TRUE;
        }

        if (!SilentClose) {
            //
            // Enter 'draining period' to flush out any leftover packets.
            //
            QuicConnTimerSet(
                Connection,
                QUIC_CONN_TIMER_SHUTDOWN,
                CXPLAT_MAX(MS_TO_US(15), Connection->Paths[0].SmoothedRtt * 2));

            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }

    } else if (!ClosedRemotely && !Connection->State.ClosedRemotely) {

        //
        // Locally closed first.
        //

        if (!SilentClose) {
            //
            // Enter 'closing period' to wait for a (optional) connection close
            // response.
            //
            uint64_t Pto =
                QuicLossDetectionComputeProbeTimeout(
                    &Connection->LossDetection,
                    &Connection->Paths[0],
                    QUIC_CLOSE_PTO_COUNT);
            QuicConnTimerSet(
                Connection,
                QUIC_CONN_TIMER_SHUTDOWN,
                Pto);

            QuicSendSetSendFlag(
                &Connection->Send,
                (Flags & QUIC_CLOSE_APPLICATION) ?
                    QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE :
                    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }

    } else {

        QuicTraceLogConnInfo(
            CloseComplete,
            Connection,
            "Connection close complete");

        //
        // Peer acknowledged our local close.
        //

        if (QuicConnIsClient(Connection)) {
            //
            // Client side can immediately clean up once its close frame was
            // acknowledged because we will close the socket during clean up,
            // which will automatically handle any leftover packets that
            // get received afterward by dropping them.
            //

        } else if (!SilentClose) {
            //
            // Server side transitions from the 'closing period' to the
            // 'draining period' and waits an additional 2 RTT just to make
            // sure all leftover packets have been flushed out.
            //
            QuicConnTimerSet(
                Connection,
                QUIC_CONN_TIMER_SHUTDOWN,
                CXPLAT_MAX(MS_TO_US(15), Connection->Paths[0].SmoothedRtt * 2));
        }

        IsFirstCloseForConnection = FALSE;
    }

    if (IsFirstCloseForConnection) {
        //
        // Default to the timed out state.
        //
        Connection->State.ShutdownCompleteTimedOut = TRUE;

        //
        // Cancel all non-shutdown related timers.
        //
        for (QUIC_CONN_TIMER_TYPE TimerType = QUIC_CONN_TIMER_IDLE;
            TimerType < QUIC_CONN_TIMER_SHUTDOWN;
            ++TimerType) {
            QuicConnTimerCancel(Connection, TimerType);
        }

        if (ResultQuicStatus) {
            Connection->CloseStatus = (QUIC_STATUS)ErrorCode;
            Connection->CloseErrorCode = QUIC_ERROR_INTERNAL_ERROR;
        } else {
            Connection->CloseStatus = QuicErrorCodeToStatus(ErrorCode);
            CXPLAT_DBG_ASSERT(ErrorCode <= QUIC_VAR_INT_MAX);
            Connection->CloseErrorCode = ErrorCode;
            if (QuicErrorIsProtocolError(ErrorCode)) {
                QuicPerfCounterIncrement(
                    Connection->Partition, QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS);
            }
        }

        if (Flags & QUIC_CLOSE_APPLICATION) {
            Connection->State.AppClosed = TRUE;
        }

        if (Flags & QUIC_CLOSE_SEND_NOTIFICATION &&
            Connection->State.ExternalOwner) {
            QuicConnIndicateShutdownBegin(Connection);
        }

        if (Connection->CloseReasonPhrase != NULL) {
            CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
            Connection->CloseReasonPhrase = NULL;
        }

        if (RemoteReasonPhraseLength != 0) {
            Connection->CloseReasonPhrase =
                CXPLAT_ALLOC_NONPAGED(RemoteReasonPhraseLength + 1, QUIC_POOL_CLOSE_REASON);
            if (Connection->CloseReasonPhrase != NULL) {
                CxPlatCopyMemory(
                    Connection->CloseReasonPhrase,
                    RemoteReasonPhrase,
                    RemoteReasonPhraseLength);
                Connection->CloseReasonPhrase[RemoteReasonPhraseLength] = 0;
            } else {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "close reason",
                    RemoteReasonPhraseLength + 1);
            }
        }

        if (Connection->State.Started) {
            QuicConnLogStatistics(Connection);
        }

        if (Flags & QUIC_CLOSE_APPLICATION) {
            QuicTraceEvent(
                ConnAppShutdown,
                "[conn][%p] App Shutdown: %llu (Remote=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely);
        } else {
            QuicTraceEvent(
                ConnTransportShutdown,
                "[conn][%p] Transport Shutdown: %llu (Remote=%hhu) (QS=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely,
                !!(Flags & QUIC_CLOSE_QUIC_STATUS));
        }

        //
        // On initial close, we must shut down all the current streams and
        // clean up pending datagrams.
        //
        QuicStreamSetShutdown(&Connection->Streams);
        QuicDatagramSendShutdown(&Connection->Datagram);
    }

    if (SilentClose) {
        QuicSendClear(&Connection->Send);
    }

    if (SilentClose ||
        (Connection->State.ClosedRemotely && Connection->State.ClosedLocally)) {
        Connection->State.ShutdownCompleteTimedOut = FALSE;
        Connection->State.ProcessShutdownComplete = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessShutdownTimerOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // We now consider the peer closed, even if they didn't respond to our close
    // frame.
    //
    Connection->State.ClosedRemotely = TRUE;

    //
    // Now that we are closed in both directions, we can complete the shutdown
    // of the connection.
    //
    Connection->State.ProcessShutdownComplete = TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCloseLocally(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ uint64_t ErrorCode,
    _In_opt_z_ const char* ErrorMsg
    )
{
    CXPLAT_DBG_ASSERT(ErrorMsg == NULL || strlen(ErrorMsg) < UINT16_MAX);
    QuicConnTryClose(
        Connection,
        Flags,
        ErrorCode,
        ErrorMsg,
        ErrorMsg == NULL ? 0 : (uint16_t)strlen(ErrorMsg));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnQuicVersionSet(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnVersionSet,
        "[conn][%p] QUIC Version: 0x%x",
        Connection,
        Connection->Stats.QuicVersion);

    switch (Connection->Stats.QuicVersion) {
    case QUIC_VERSION_1:
    case QUIC_VERSION_DRAFT_29:
    case QUIC_VERSION_MS_1:
    case QUIC_VERSION_2:
    default:
        Connection->State.HeaderProtectionEnabled = TRUE;
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnStart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_opt_z_ const char* ServerName,
    _In_ uint16_t ServerPort, // Host byte order
    _In_ QUIC_CONN_START_FLAGS StartFlags
    )
{
    QUIC_STATUS Status;
    QUIC_PATH* Path = &Connection->Paths[0];
    CXPLAT_DBG_ASSERT(QuicConnIsClient(Connection));

    if (Connection->State.ClosedLocally || Connection->State.Started) {
        if (ServerName != NULL) {
            CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
        }
        return QUIC_STATUS_INVALID_STATE;
    }

    BOOLEAN RegistrationShutingDown;
    uint64_t ShutdownErrorCode;
    QUIC_CONNECTION_SHUTDOWN_FLAGS ShutdownFlags;
    CxPlatDispatchLockAcquire(&Connection->Registration->ConnectionLock);
    ShutdownErrorCode = Connection->Registration->ShutdownErrorCode;
    ShutdownFlags = Connection->Registration->ShutdownFlags;
    RegistrationShutingDown = Connection->Registration->ShuttingDown;
    CxPlatDispatchLockRelease(&Connection->Registration->ConnectionLock);

    if (RegistrationShutingDown) {
        QuicConnShutdown(Connection, ShutdownFlags, ShutdownErrorCode, FALSE, FALSE);
        if (ServerName != NULL) {
            CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
        }
        return QUIC_STATUS_INVALID_STATE;
    }

    CXPLAT_TEL_ASSERT(Path->Binding == NULL);

    QuicConnApplyNewSettings(
        Connection,
        FALSE,
        &Configuration->Settings);

    if (!Connection->State.RemoteAddressSet) {

        CXPLAT_DBG_ASSERT(ServerName != NULL);
        QuicAddrSetFamily(&Path->Route.RemoteAddress, Family);

#ifdef QUIC_COMPARTMENT_ID
        BOOLEAN RevertCompartmentId = FALSE;
        QUIC_COMPARTMENT_ID PrevCompartmentId = QuicCompartmentIdGetCurrent();
        if (PrevCompartmentId != Configuration->CompartmentId) {
            Status = QuicCompartmentIdSetCurrent(Configuration->CompartmentId);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection, Status,
                    "Set current compartment Id");
                goto Exit;
            }
            RevertCompartmentId = TRUE;
        }
#endif

        //
        // Resolve the server name to IP address.
        //
        Status =
            CxPlatDataPathResolveAddress(
                MsQuicLib.Datapath,
                ServerName,
                &Path->Route.RemoteAddress);

#ifdef QUIC_COMPARTMENT_ID
        if (RevertCompartmentId) {
            (void)QuicCompartmentIdSetCurrent(PrevCompartmentId);
        }
#endif

        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

        Connection->State.RemoteAddressSet = TRUE;
    }

    if (QuicAddrIsWildCard(&Path->Route.RemoteAddress)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Invalid wildcard remote address in connection start");
        goto Exit;
    }

    QuicAddrSetPort(&Path->Route.RemoteAddress, ServerPort);
    QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress));

    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = Connection->State.LocalAddressSet ? &Path->Route.LocalAddress : NULL;
    UdpConfig.RemoteAddress = &Path->Route.RemoteAddress;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = Connection->State.LocalInterfaceSet ? (uint32_t)Path->Route.LocalAddress.Ipv6.sin6_scope_id : 0, // NOLINT(google-readability-casting)
    UdpConfig.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);
#ifdef QUIC_COMPARTMENT_ID
    UdpConfig.CompartmentId = Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
    UdpConfig.OwningProcess = Configuration->OwningProcess;
#endif

    if (Connection->State.ShareBinding) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
    }
    if (Connection->Settings.XdpEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    if (Connection->Settings.QTIPEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
    }
    if (Connection->Settings.RioEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_RIO;
    }

    //
    // Get the binding for the current local & remote addresses.
    //
    Status =
        QuicLibraryGetBinding(
            &UdpConfig,
            &Path->Binding);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    //
    // Clients only need to generate a non-zero length source CID if it
    // intends to share the UDP binding.
    //
    QUIC_CID_HASH_ENTRY* SourceCid;
    if (Connection->State.ShareBinding) {
        SourceCid =
            QuicCidNewRandomSource(
                Connection,
                NULL,
                Connection->PartitionID,
                Connection->CibirId[0],
                Connection->CibirId+2);
    } else {
        SourceCid = QuicCidNewNullSource(Connection);
    }
    if (SourceCid == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Connection->NextSourceCidSequenceNumber++;
    QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
        Connection,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
    CxPlatListPushEntry(&Connection->SourceCids, &SourceCid->Link);

    if (!QuicBindingAddSourceConnectionID(Path->Binding, SourceCid)) {
        QuicLibraryReleaseBinding(Path->Binding);
        Path->Binding = NULL;
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Connection->State.LocalAddressSet = TRUE;
    QuicBindingGetLocalAddress(Path->Binding, &Path->Route.LocalAddress);
    QuicTraceEvent(
        ConnLocalAddrAdded,
        "[conn][%p] New Local IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));

    //
    // Save the server name.
    //
    Connection->RemoteServerName = ServerName;
    ServerName = NULL;

    Status = QuicCryptoInitialize(&Connection->Crypto);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    //
    // Start the handshake.
    //
    Status = QuicConnSetConfiguration(Connection, Configuration);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

Exit:

    if (ServerName != NULL) {
        CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
    }

    if (QUIC_FAILED(Status)) {
        QuicConnCloseLocally(
            Connection,
            StartFlags & QUIC_CONN_START_FLAG_FAIL_SILENTLY ?
                QUIC_CLOSE_SILENT | QUIC_CLOSE_QUIC_STATUS :
                QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)Status,
            NULL);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRestart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN CompleteReset
    )
{
    CXPLAT_TEL_ASSERT(Connection->State.Started);

    QuicTraceLogConnInfo(
        Restart,
        Connection,
        "Restart (CompleteReset=%hhu)",
        CompleteReset);

    if (CompleteReset) {
        //
        // Don't reset current RTT measurements unless doing a full reset.
        //
        QUIC_PATH* Path = &Connection->Paths[0];
        Path->GotFirstRttSample = FALSE;
        Path->SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
        Path->RttVariance = Path->SmoothedRtt / 2;
    }

    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); ++i) {
        CXPLAT_DBG_ASSERT(Connection->Packets[i] != NULL);
        QuicPacketSpaceReset(Connection->Packets[i]);
    }

    QuicCongestionControlReset(&Connection->CongestionControl, TRUE);
    QuicSendReset(&Connection->Send);
    QuicLossDetectionReset(&Connection->LossDetection);
    QuicCryptoTlsCleanupTransportParameters(&Connection->PeerTransportParams);

    if (CompleteReset) {
        CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);

        QUIC_TRANSPORT_PARAMETERS LocalTP = { 0 };
        QUIC_STATUS Status =
            QuicConnGenerateLocalTransportParameters(Connection, &LocalTP);
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(Status)); // Can't fail since it passed already.
        UNREFERENCED_PARAMETER(Status);

        Status =
            QuicCryptoInitializeTls(
                &Connection->Crypto,
                Connection->Configuration->SecurityConfig,
                &LocalTP);
        if (QUIC_FAILED(Status)) {
            QuicConnFatalError(Connection, Status, NULL);
        }

        QuicCryptoTlsCleanupTransportParameters(&LocalTP);

    } else {
        QuicCryptoReset(&Connection->Crypto);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnSendResumptionTicket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t AppDataLength,
    _In_reads_bytes_opt_(AppDataLength)
        const uint8_t* AppResumptionData
    )
{
    QUIC_STATUS Status;
    uint8_t* TicketBuffer = NULL;
    uint32_t TicketLength = 0;
    uint8_t AlpnLength = Connection->Crypto.TlsState.NegotiatedAlpn[0];

    if (Connection->HandshakeTP == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status =
        QuicCryptoEncodeServerTicket(
            Connection,
            Connection->Stats.QuicVersion,
            AppDataLength,
            AppResumptionData,
            Connection->HandshakeTP,
            AlpnLength,
            Connection->Crypto.TlsState.NegotiatedAlpn + 1,
            &TicketBuffer,
            &TicketLength);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status = QuicCryptoProcessAppData(&Connection->Crypto, TicketLength, TicketBuffer);

Error:
    if (TicketBuffer != NULL) {
        CXPLAT_FREE(TicketBuffer, QUIC_POOL_SERVER_CRYPTO_TICKET);
    }

    if (AppResumptionData != NULL) {
        CXPLAT_FREE(AppResumptionData, QUIC_POOL_APP_RESUMPTION_DATA);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvResumptionTicket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TicketLength,
    _In_reads_(TicketLength)
        const uint8_t* Ticket
    )
{
    BOOLEAN ResumptionAccepted = FALSE;
    QUIC_TRANSPORT_PARAMETERS ResumedTP = {0};
    CxPlatZeroMemory(&ResumedTP, sizeof(ResumedTP));
    if (QuicConnIsServer(Connection)) {
        if (Connection->Crypto.TicketValidationRejecting) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket rejected by server app asynchronously");
            Connection->Crypto.TicketValidationRejecting = FALSE;
            Connection->Crypto.TicketValidationPending = FALSE;
            goto Error;
        }
        Connection->Crypto.TicketValidationPending = TRUE;

        const uint8_t* AppData = NULL;
        uint32_t AppDataLength = 0;

        QUIC_STATUS Status =
            QuicCryptoDecodeServerTicket(
                Connection,
                TicketLength,
                Ticket,
                Connection->Configuration->AlpnList,
                Connection->Configuration->AlpnListLength,
                &ResumedTP,
                &AppData,
                &AppDataLength);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        //
        // Validate resumed TP are <= current settings
        //
        if (ResumedTP.ActiveConnectionIdLimit > QUIC_ACTIVE_CONNECTION_ID_LIMIT ||
            ResumedTP.InitialMaxData > Connection->Send.MaxData ||
            ResumedTP.InitialMaxStreamDataBidiLocal > Connection->Settings.StreamRecvWindowBidiLocalDefault ||
            ResumedTP.InitialMaxStreamDataBidiRemote > Connection->Settings.StreamRecvWindowBidiRemoteDefault ||
            ResumedTP.InitialMaxStreamDataUni > Connection->Settings.StreamRecvWindowUnidiDefault ||
            ResumedTP.InitialMaxUniStreams > Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount ||
            ResumedTP.InitialMaxBidiStreams > Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            //
            // Server settings have changed since the resumption ticket was
            // encoded, so reject resumption.
            //
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket transport params greater than current server settings");
            goto Error;
        }

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_RESUMED;
        Event.RESUMED.ResumptionStateLength = (uint16_t)AppDataLength;
        Event.RESUMED.ResumptionState = (AppDataLength > 0) ? AppData : NULL;
        QuicTraceLogConnVerbose(
            IndicateResumed,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_RESUMED");
        Status = QuicConnIndicateEvent(Connection, &Event);
        if (Status == QUIC_STATUS_SUCCESS) {
            QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app accepted resumption ticket",
                Connection);
            ResumptionAccepted = TRUE;
            Connection->Crypto.TicketValidationPending = FALSE;
        } else if (Status == QUIC_STATUS_PENDING) {
            QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app asynchronously validating resumption ticket",
                Connection);
            ResumptionAccepted = TRUE;
        } else {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket rejected by server app");
            ResumptionAccepted = FALSE;
            Connection->Crypto.TicketValidationPending = FALSE;
        }

    } else {

        const uint8_t* ClientTicket = NULL;
        uint32_t ClientTicketLength = 0;

        CXPLAT_DBG_ASSERT(Connection->State.PeerTransportParameterValid);

        if (QUIC_SUCCEEDED(
            QuicCryptoEncodeClientTicket(
                Connection,
                TicketLength,
                Ticket,
                &Connection->PeerTransportParams,
                Connection->Stats.QuicVersion,
                &ClientTicket,
                &ClientTicketLength))) {

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED;
            Event.RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength = ClientTicketLength;
            Event.RESUMPTION_TICKET_RECEIVED.ResumptionTicket = ClientTicket;
            QuicTraceLogConnVerbose(
                IndicateResumptionTicketReceived,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED");
            (void)QuicConnIndicateEvent(Connection, &Event);

            CXPLAT_FREE(ClientTicket, QUIC_POOL_CLIENT_CRYPTO_TICKET);
            ResumptionAccepted = TRUE;
        }
    }

Error:

    QuicCryptoTlsCleanupTransportParameters(&ResumedTP);
    return ResumptionAccepted;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCleanupServerResumptionState(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
    if (!Connection->State.ResumptionEnabled) {
        if (Connection->HandshakeTP != NULL) {
            QuicCryptoTlsCleanupTransportParameters(Connection->HandshakeTP);
            CxPlatPoolFree(Connection->HandshakeTP);
            Connection->HandshakeTP = NULL;
        }

        QUIC_CRYPTO* Crypto = &Connection->Crypto;

        QuicTraceLogConnInfo(
            CryptoStateDiscard,
            Connection,
            "TLS state no longer needed");
        if (Crypto->TLS != NULL) {
            CxPlatTlsUninitialize(Crypto->TLS);
            Crypto->TLS = NULL;
        }
        if (Crypto->Initialized) {
            QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
            QuicRangeUninitialize(&Crypto->SparseAckRanges);
            CXPLAT_FREE(Crypto->TlsState.Buffer, QUIC_POOL_TLS_BUFFER);
            Crypto->TlsState.Buffer = NULL;
            Crypto->Initialized = FALSE;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPostAcceptValidatePeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnGenerateLocalTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_TRANSPORT_PARAMETERS* LocalTP
    )
{
    CXPLAT_TEL_ASSERT(Connection->Configuration != NULL);

    CXPLAT_DBG_ASSERT(Connection->SourceCids.Next != NULL);
    const QUIC_CID_HASH_ENTRY* SourceCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->SourceCids.Next,
            QUIC_CID_HASH_ENTRY,
            Link);

    LocalTP->InitialMaxData = Connection->Send.MaxData;
    LocalTP->InitialMaxStreamDataBidiLocal = Connection->Settings.StreamRecvWindowBidiLocalDefault;
    LocalTP->InitialMaxStreamDataBidiRemote = Connection->Settings.StreamRecvWindowBidiRemoteDefault;
    LocalTP->InitialMaxStreamDataUni = Connection->Settings.StreamRecvWindowUnidiDefault;
    LocalTP->MaxUdpPayloadSize =
        MaxUdpPayloadSizeFromMTU(
            CxPlatSocketGetLocalMtu(
                Connection->Paths[0].Binding->Socket,
                &Connection->Paths[0].Route));
    LocalTP->MaxAckDelay = QuicConnGetAckDelay(Connection);
    LocalTP->MinAckDelay =
        MsQuicLib.ExecutionConfig != NULL &&
        MsQuicLib.ExecutionConfig->PollingIdleTimeoutUs != 0 ?
            0 : MS_TO_US(MsQuicLib.TimerResolutionMs);
    LocalTP->ActiveConnectionIdLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
    LocalTP->Flags =
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE |
        QUIC_TP_FLAG_MAX_ACK_DELAY |
        QUIC_TP_FLAG_MIN_ACK_DELAY |
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;

    if (Connection->Settings.IdleTimeoutMs != 0) {
        LocalTP->Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
        LocalTP->IdleTimeout = Connection->Settings.IdleTimeoutMs;
    }

    if (Connection->AckDelayExponent != QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT) {
        LocalTP->Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
        LocalTP->AckDelayExponent = Connection->AckDelayExponent;
    }

    LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
    LocalTP->InitialSourceConnectionIDLength = SourceCid->CID.Length;
    CxPlatCopyMemory(
        LocalTP->InitialSourceConnectionID,
        SourceCid->CID.Data,
        SourceCid->CID.Length);

    if (Connection->Settings.DatagramReceiveEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
        LocalTP->MaxDatagramFrameSize = QUIC_DEFAULT_MAX_DATAGRAM_LENGTH;
    }

    if (Connection->State.Disable1RttEncrytion) {
        LocalTP->Flags |= QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION;
    }

    if (Connection->CibirId[0] != 0) {
        LocalTP->Flags |= QUIC_TP_FLAG_CIBIR_ENCODING;
        LocalTP->CibirLength = Connection->CibirId[0];
        LocalTP->CibirOffset = Connection->CibirId[1];
    }

    if (Connection->Settings.VersionNegotiationExtEnabled
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
        && !Connection->State.DisableVneTp
#endif
        ) {
        uint32_t VersionInfoLength = 0;
        LocalTP->VersionInfo =
            QuicVersionNegotiationExtEncodeVersionInfo(Connection, &VersionInfoLength);
        if (LocalTP->VersionInfo != NULL) {
            LocalTP->Flags |= QUIC_TP_FLAG_VERSION_NEGOTIATION;
            LocalTP->VersionInfoLength = VersionInfoLength;
        } else {
            LocalTP->VersionInfoLength = 0;
        }
    }

    if (Connection->Settings.GreaseQuicBitEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_GREASE_QUIC_BIT;
    }

    if (Connection->Settings.ReliableResetEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_RELIABLE_RESET_ENABLED;
    }

    if (Connection->Settings.OneWayDelayEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED |
                          QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED;
    }

    if (QuicConnIsServer(Connection)) {

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LocalTP->InitialMaxBidiStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LocalTP->InitialMaxUniStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;
        }

        if (!Connection->Settings.MigrationEnabled) {
            LocalTP->Flags |= QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION;
        }

        LocalTP->Flags |= QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
        QUIC_STATUS Status =
            QuicLibraryGenerateStatelessResetToken(
                Connection->Partition,
                SourceCid->CID.Data,
                LocalTP->StatelessResetToken);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "QuicLibraryGenerateStatelessResetToken");
            return Status;
        }

        if (Connection->OrigDestCID != NULL) {
            CXPLAT_DBG_ASSERT(Connection->OrigDestCID->Length <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
            LocalTP->Flags |= QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID;
            LocalTP->OriginalDestinationConnectionIDLength = Connection->OrigDestCID->Length;
            CxPlatCopyMemory(
                LocalTP->OriginalDestinationConnectionID,
                Connection->OrigDestCID->Data,
                Connection->OrigDestCID->Length);

            if (Connection->State.HandshakeUsedRetryPacket) {
                CXPLAT_DBG_ASSERT(SourceCid->Link.Next != NULL);
                const QUIC_CID_HASH_ENTRY* PrevSourceCid =
                    CXPLAT_CONTAINING_RECORD(
                        SourceCid->Link.Next,
                        QUIC_CID_HASH_ENTRY,
                        Link);

                LocalTP->Flags |= QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID;
                LocalTP->RetrySourceConnectionIDLength = PrevSourceCid->CID.Length;
                CxPlatCopyMemory(
                    LocalTP->RetrySourceConnectionID,
                    PrevSourceCid->CID.Data,
                    PrevSourceCid->CID.Length);
            }
        }

    } else {

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LocalTP->InitialMaxBidiStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LocalTP->InitialMaxUniStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnSetConfiguration(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONFIGURATION* Configuration
    )
{
    if (Connection->Configuration != NULL || QuicConnIsClosed(Connection)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_STATUS Status;
    QUIC_TRANSPORT_PARAMETERS LocalTP = { 0 };

    CXPLAT_TEL_ASSERT(Connection->Configuration == NULL);
    CXPLAT_TEL_ASSERT(Configuration != NULL);
    CXPLAT_TEL_ASSERT(Configuration->SecurityConfig != NULL);

    QuicTraceLogConnInfo(
        SetConfiguration,
        Connection,
        "Configuration set, %p",
        Configuration);

    QuicConfigurationAddRef(Configuration);
    QuicConfigurationAttachSilo(Configuration);
    Connection->Configuration = Configuration;

    if (QuicConnIsServer(Connection)) {
        QuicConnApplyNewSettings(
            Connection,
            FALSE,
            &Configuration->Settings);
    }

    if (QuicConnIsClient(Connection)) {

        if (Connection->Stats.QuicVersion == 0) {
            //
            // Only initialize the version if not already done (by the
            // application layer).
            //
            Connection->Stats.QuicVersion = QUIC_VERSION_LATEST;
            QuicConnOnQuicVersionSet(Connection);
            Status = QuicCryptoOnVersionChange(&Connection->Crypto);
            if (QUIC_FAILED(Status)) {
                goto Error;
            }
        }

        CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->DestCids));
        const QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Connection->DestCids.Flink,
                QUIC_CID_LIST_ENTRY,
                Link);

        //
        // Save the original CID for later validation in the TP.
        //
        Connection->OrigDestCID =
            CXPLAT_ALLOC_NONPAGED(
                sizeof(QUIC_CID) +
                DestCid->CID.Length,
                QUIC_POOL_CID);
        if (Connection->OrigDestCID == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "OrigDestCID",
                sizeof(QUIC_CID) + DestCid->CID.Length);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Connection->OrigDestCID->Length = DestCid->CID.Length;
        CxPlatCopyMemory(
            Connection->OrigDestCID->Data,
            DestCid->CID.Data,
            DestCid->CID.Length);

    } else {
        if (!QuicConnPostAcceptValidatePeerTransportParameters(Connection)) {
            QuicConnTransportError(Connection, QUIC_ERROR_CONNECTION_REFUSED);
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Cleanup;
        }

        Status =
            QuicCryptoReNegotiateAlpn(
                Connection,
                Connection->Configuration->AlpnListLength,
                Connection->Configuration->AlpnList);
        if (QUIC_FAILED(Status)) {
            goto Cleanup;
        }
        Connection->Crypto.TlsState.ClientAlpnList = NULL;
        Connection->Crypto.TlsState.ClientAlpnListLength = 0;
    }

    Status = QuicConnGenerateLocalTransportParameters(Connection, &LocalTP);
    if (QUIC_FAILED(Status)) {
        goto Cleanup;
    }

    //
    // Persist the transport parameters used during handshake for resumption.
    // (if resumption is enabled)
    //
    if (QuicConnIsServer(Connection) && Connection->HandshakeTP != NULL) {
        CXPLAT_DBG_ASSERT(Connection->State.ResumptionEnabled);
        QuicCryptoTlsCopyTransportParameters(&LocalTP, Connection->HandshakeTP);
    }

    Connection->State.Started = TRUE;
    Connection->Stats.Timing.Start = CxPlatTimeUs64();
    QuicTraceEvent(
        ConnHandshakeStart,
        "[conn][%p] Handshake start",
        Connection);

    Status =
        QuicCryptoInitializeTls(
            &Connection->Crypto,
            Configuration->SecurityConfig,
            &LocalTP);

Cleanup:

    QuicCryptoTlsCleanupTransportParameters(&LocalTP);

Error:

    QuicConfigurationDetachSilo();

    return Status;
}

BOOLEAN
QuicConnValidateTransportParameterCIDs(
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer didn't provide the initial source CID in TP");
        return FALSE;
    }

    const QUIC_CID_LIST_ENTRY* DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);
    if (DestCid->CID.Length != Connection->PeerTransportParams.InitialSourceConnectionIDLength ||
        memcmp(DestCid->CID.Data, Connection->PeerTransportParams.InitialSourceConnectionID, DestCid->CID.Length) != 0) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Initial source CID from TP doesn't match");
        return FALSE;
    }

    if (QuicConnIsClient(Connection)) {
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Server didn't provide the original destination CID in TP");
            return FALSE;
        }
        CXPLAT_DBG_ASSERT(Connection->OrigDestCID);
        if (Connection->OrigDestCID->Length != Connection->PeerTransportParams.OriginalDestinationConnectionIDLength ||
            memcmp(Connection->OrigDestCID->Data, Connection->PeerTransportParams.OriginalDestinationConnectionID, Connection->OrigDestCID->Length) != 0) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Original destination CID from TP doesn't match");
            return FALSE;
        }
        if (Connection->State.HandshakeUsedRetryPacket) {
            if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server didn't provide the retry source CID in TP");
                return FALSE;
            }
            // TODO - Validate
        } else {
            if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server incorrectly provided the retry source CID in TP");
                return FALSE;
            }
        }
    }

    return TRUE;
}

QUIC_STATUS
QuicConnProcessPeerVersionNegotiationTP(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_STATUS Status;
    if (QuicConnIsServer(Connection)) {
        //
        // Check whether version is in (App-specified) list of acceptable versions.
        //
        uint32_t SupportedVersionsLength = 0;
        const uint32_t* SupportedVersions = NULL;
        if (MsQuicLib.Settings.IsSet.VersionSettings) {
            SupportedVersionsLength = MsQuicLib.Settings.VersionSettings->AcceptableVersionsLength;
            SupportedVersions = MsQuicLib.Settings.VersionSettings->AcceptableVersions;
        } else {
            SupportedVersionsLength = ARRAYSIZE(DefaultSupportedVersionsList);
            SupportedVersions = DefaultSupportedVersionsList;
        }

        uint32_t CurrentVersionIndex = 0;
        for (; CurrentVersionIndex < SupportedVersionsLength; ++CurrentVersionIndex) {
            if (Connection->Stats.QuicVersion == SupportedVersions[CurrentVersionIndex]) {
                break;
            }
        }
        if (CurrentVersionIndex == SupportedVersionsLength) {
            CXPLAT_DBG_ASSERTMSG(FALSE,"Incompatible Version Negotation should happen in binding layer");
            //
            // Current version not supported, start incompatible version negotiation.
            // This path should only hit when the AcceptableVersions are changed globally
            // between when the first flight was received, and this point.
            //
            return QUIC_STATUS_VER_NEG_ERROR;
        }

        QUIC_VERSION_INFORMATION_V1 ClientVI;
        Status =
            QuicVersionNegotiationExtParseVersionInfo(
                Connection,
                Connection->PeerTransportParams.VersionInfo,
                (uint16_t)Connection->PeerTransportParams.VersionInfoLength,
                &ClientVI);
        if (QUIC_FAILED(Status)) {
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        if (ClientVI.ChosenVersion == 0) {
            QuicTraceLogConnError(
                VersionInfoChosenVersionZero,
                Connection,
                "Version Info Chosen Version is zero!");
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        //
        // Assume QuicVersion on the Connection is the long header value
        // and verify it matches the VNE TP.
        //
        if (Connection->Stats.QuicVersion != ClientVI.ChosenVersion) {
            QuicTraceLogConnError(
                ClientVersionInfoVersionMismatch,
                Connection,
                "Client Chosen Version doesn't match long header. 0x%x != 0x%x",
                ClientVI.ChosenVersion,
                Connection->Stats.QuicVersion);
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        //
        // Attempt to upgrade the connection to a compatible version the server prefers.
        //
        for (uint32_t ServerVersionIdx = 0; ServerVersionIdx < CurrentVersionIndex; ++ServerVersionIdx) {
            if (QuicIsVersionReserved(SupportedVersions[ServerVersionIdx])) {
                continue;
            }
            for (uint32_t ClientVersionIdx = 0; ClientVersionIdx < ClientVI.AvailableVersionsCount; ++ClientVersionIdx) {
                if (ClientVI.AvailableVersions[ClientVersionIdx] == 0) {
                    QuicTraceLogConnError(
                        VersionInfoOtherVersionZero,
                        Connection,
                        "Version Info.AvailableVersions contains a zero version! Index = %u",
                        ClientVersionIdx);
                    QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
                    return QUIC_STATUS_PROTOCOL_ERROR;
                }
                if (!QuicIsVersionReserved(ClientVI.AvailableVersions[ClientVersionIdx]) &&
                    ClientVI.AvailableVersions[ClientVersionIdx] == SupportedVersions[ServerVersionIdx] &&
                    QuicVersionNegotiationExtAreVersionsCompatible(
                        ClientVI.ChosenVersion,
                        ClientVI.AvailableVersions[ClientVersionIdx])) {
                    QuicTraceLogConnVerbose(
                        ClientVersionNegotiationCompatibleVersionUpgrade,
                        Connection,
                        "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                        Connection->Stats.QuicVersion,
                        SupportedVersions[ServerVersionIdx]);
                    Connection->Stats.QuicVersion = SupportedVersions[ServerVersionIdx];
                    QuicConnOnQuicVersionSet(Connection);
                    Status = QuicCryptoOnVersionChange(&Connection->Crypto);
                    if (QUIC_FAILED(Status)) {
                        QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                        return QUIC_STATUS_INTERNAL_ERROR;
                    }
                }
            }
        }
        //
        // If the version negotiation upgrade failed, just continue
        // with the current version.
        //
    } else {
        //
        // Client must perform downgrade prevention
        //
        QUIC_VERSION_INFORMATION_V1 ServerVI = {0};
        Status =
            QuicVersionNegotiationExtParseVersionInfo(
                Connection,
                Connection->PeerTransportParams.VersionInfo,
                (uint16_t)Connection->PeerTransportParams.VersionInfoLength,
                &ServerVI);
        if (QUIC_FAILED(Status)) {
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        if (ServerVI.ChosenVersion == 0) {
            QuicTraceLogConnError(
                VersionInfoChosenVersionZero,
                Connection,
                "Version Info Chosen Version is zero!");
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        if (Connection->Stats.QuicVersion != ServerVI.ChosenVersion) {
            QuicTraceLogConnError(
                ServerVersionInfoVersionMismatch,
                Connection,
                "Server Chosen Version doesn't match long header. 0x%x != 0x%x",
                ServerVI.ChosenVersion,
                Connection->Stats.QuicVersion);
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        uint32_t ClientChosenVersion = 0;
        BOOLEAN OriginalVersionFound = FALSE;
        for (uint32_t i = 0; i < ServerVI.AvailableVersionsCount; ++i) {
            if (ServerVI.AvailableVersions[i] == 0) {
                QuicTraceLogConnError(
                    VersionInfoOtherVersionZero,
                    Connection,
                    "Version Info Available Versions contains a zero version! Index = %u",
                    i);
                QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            //
            // Keep this logic up to date with the logic in QuicConnRecvVerNeg
            //
            if (Connection->Stats.VersionNegotiation &&
                ClientChosenVersion == 0 &&
                QuicVersionNegotiationExtIsVersionClientSupported(Connection, ServerVI.AvailableVersions[i])) {
                ClientChosenVersion = ServerVI.AvailableVersions[i];
            }
            if (Connection->OriginalQuicVersion == ServerVI.AvailableVersions[i]) {
                OriginalVersionFound = TRUE;
            }
        }
        if (ClientChosenVersion == 0 &&
            QuicVersionNegotiationExtIsVersionClientSupported(Connection, ServerVI.ChosenVersion)) {
            ClientChosenVersion = ServerVI.ChosenVersion;
        }
        if (ClientChosenVersion == 0 || (ClientChosenVersion != Connection->OriginalQuicVersion &&
            ClientChosenVersion != ServerVI.ChosenVersion)) {
            QuicTraceLogConnError(
                ClientChosenVersionMismatchServerChosenVersion,
                Connection,
                "Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x",
                ClientChosenVersion,
                ServerVI.ChosenVersion);
            QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }
        //
        // If the client has already received a version negotiation packet, do
        // extra validation.
        //
        if (Connection->PreviousQuicVersion != 0) {
            if (Connection->PreviousQuicVersion == ServerVI.ChosenVersion) {
                QuicTraceLogConnError(
                    ServerVersionInformationPreviousVersionIsChosenVersion,
                    Connection,
                    "Previous Client Version is Server Chosen Version: 0x%x",
                    Connection->PreviousQuicVersion);
                QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            //
            // Ensure the version which generated a VN packet is not in the AvailableVersions.
            //
            if (!QuicIsVersionReserved(Connection->PreviousQuicVersion)) {
                for (uint32_t i = 0; i < ServerVI.AvailableVersionsCount; ++i) {
                    if (Connection->PreviousQuicVersion == ServerVI.AvailableVersions[i]) {
                        QuicTraceLogConnError(
                            ServerVersionInformationPreviousVersionInOtherVerList,
                            Connection,
                            "Previous Client Version in Server Available Versions list: 0x%x",
                            Connection->PreviousQuicVersion);
                        QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                        return QUIC_STATUS_PROTOCOL_ERROR;
                    }
                }
            }
        }
        //
        // If Compatible Version Negotiation was performed, do extra validation
        //
        if (Connection->State.CompatibleVerNegotiationAttempted) {
            if (!QuicVersionNegotiationExtAreVersionsCompatible(
                Connection->OriginalQuicVersion, ServerVI.ChosenVersion)) {
                QuicTraceLogConnError(
                    CompatibleVersionNegotiationNotCompatible,
                    Connection,
                    "Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
                QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            if (!OriginalVersionFound) {
                QuicTraceLogConnError(
                    CompatibleVersionNegotiationOriginalVersionNotFound,
                    Connection,
                    "OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
                QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            Connection->State.CompatibleVerNegotiationCompleted = TRUE;
            QuicTraceLogConnVerbose(
                CompatibleVersionUpgradeComplete,
                Connection,
                "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                Connection->OriginalQuicVersion,
                Connection->Stats.QuicVersion);
        }
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnProcessPeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN FromResumptionTicket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QuicTraceLogConnInfo(
        PeerTPSet,
        Connection,
        "Peer Transport Parameters Set");
    Connection->State.PeerTransportParameterValid = TRUE;

    if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        CXPLAT_DBG_ASSERT(Connection->PeerTransportParams.ActiveConnectionIdLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
        if (Connection->SourceCidLimit > Connection->PeerTransportParams.ActiveConnectionIdLimit) {
            Connection->SourceCidLimit = (uint8_t) Connection->PeerTransportParams.ActiveConnectionIdLimit;
        }
    } else {
        Connection->SourceCidLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT;
    }

    if (!FromResumptionTicket) {
        if (Connection->Settings.VersionNegotiationExtEnabled &&
            Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
            Status = QuicConnProcessPeerVersionNegotiationTP(Connection);
            if (QUIC_FAILED(Status)) {
                //
                // If the Version Info failed to parse, indicate the failure up the stack to perform
                // Incompatible Version Negotiation or so the connection can be closed.
                //
                goto Error;
            }
        }
        if (QuicConnIsClient(Connection) &&
            (Connection->State.CompatibleVerNegotiationAttempted || Connection->PreviousQuicVersion != 0) &&
            !(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION)) {
            //
            // Client responded to a version negotiation packet, or compatible version negotiation,
            // but server didn't send Version Info TP. Kill the connection.
            //
            QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
            Status = QUIC_STATUS_PROTOCOL_ERROR;
            goto Error;
        }

        if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
            CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->DestCids));
            CXPLAT_DBG_ASSERT(QuicConnIsClient(Connection));
            QUIC_CID_LIST_ENTRY* DestCid =
                CXPLAT_CONTAINING_RECORD(
                    Connection->DestCids.Flink,
                    QUIC_CID_LIST_ENTRY,
                    Link);
            CxPlatCopyMemory(
                DestCid->ResetToken,
                Connection->PeerTransportParams.StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
            DestCid->CID.HasResetToken = TRUE;
        }

        if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
            /*QuicTraceLogConnInfo(
                PeerPreferredAddress,
                Connection,
                "Peer configured preferred address %!ADDR!",
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress));*/

            //
            // TODO - Implement preferred address feature.
            //
        }

        if (Connection->Settings.GreaseQuicBitEnabled &&
            (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT) > 0) {
            //
            // Endpoints that receive the grease_quic_bit transport parameter from
            // a peer SHOULD set the QUIC Bit to an unpredictable value extension
            // assigns specific meaning to the value of the bit.
            //
            uint8_t RandomValue;
            (void) CxPlatRandom(sizeof(RandomValue), &RandomValue);
            Connection->State.FixedBit = (RandomValue % 2);
            Connection->Stats.GreaseBitNegotiated = TRUE;
        }

        if (Connection->Settings.ReliableResetEnabled) {
            Connection->State.ReliableResetStreamNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED;
            Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated = Connection->State.ReliableResetStreamNegotiated;

            QuicTraceLogConnVerbose(
                IndicateReliableResetNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED [IsNegotiated=%hhu]",
                Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (Connection->Settings.OneWayDelayEnabled) {
            Connection->State.TimestampSendNegotiated = // Peer wants to recv, so we can send
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
            Connection->State.TimestampRecvNegotiated = // Peer wants to send, so we can recv
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED;
            Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated = Connection->State.TimestampSendNegotiated;
            Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated = Connection->State.TimestampRecvNegotiated;

            QuicTraceLogConnVerbose(
                IndicateOneWayDelayNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED [Send=%hhu,Recv=%hhu]",
                Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated,
                Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        //
        // Fully validate all exchanged connection IDs.
        //
        if (!QuicConnValidateTransportParameterCIDs(Connection)) {
            goto Error;
        }

        if (QuicConnIsClient(Connection) &&
            !QuicConnPostAcceptValidatePeerTransportParameters(Connection)) {
            goto Error;
        }
    }

    Connection->Send.PeerMaxData =
        Connection->PeerTransportParams.InitialMaxData;

    QuicStreamSetInitializeTransportParameters(
        &Connection->Streams,
        Connection->PeerTransportParams.InitialMaxBidiStreams,
        Connection->PeerTransportParams.InitialMaxUniStreams,
        !FromResumptionTicket);

    QuicDatagramOnSendStateChanged(&Connection->Datagram);

    if (Connection->State.Started) {
        if (Connection->State.Disable1RttEncrytion &&
            Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION) {
            QuicTraceLogConnInfo(
                NegotiatedDisable1RttEncryption,
                Connection,
                "Negotiated Disable 1-RTT Encryption");
        } else {
            Connection->State.Disable1RttEncrytion = FALSE;
        }
    }

    return QUIC_STATUS_SUCCESS;

Error:
    //
    // Errors from Version Negotiation Extension parsing are treated differently
    // so Incompatible Version Negotiation can be done.
    //
    if (Status == QUIC_STATUS_SUCCESS) {
        QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
        Status = QUIC_STATUS_PROTOCOL_ERROR;
    }
    return Status;
}

//
// Called after the configuration has been set. This happens immediately on the
// client side, but not until after the listener accepted on the server side.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPostAcceptValidatePeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // CIBIR encoding transport parameter validation.
    //
    if (Connection->CibirId[0] != 0) {
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_CIBIR_ENCODING)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer isn't using CIBIR but we are");
            return FALSE;
        }
        if (Connection->PeerTransportParams.CibirLength != Connection->CibirId[0]) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer isn't using a matching CIBIR length");
            return FALSE;
        }
        if (Connection->PeerTransportParams.CibirOffset != Connection->CibirId[1]) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer isn't using a matching CIBIR offset");
            return FALSE;
        }
    } else { // CIBIR not in use
        if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_CIBIR_ENCODING) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer is using CIBIR but we aren't");
            return FALSE;
        }
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPeerCertReceived(
    _In_ QUIC_CONNECTION* Connection,
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_opt_ QUIC_CERTIFICATE_CHAIN* Chain,
    _In_ uint32_t DeferredErrorFlags,
    _In_ QUIC_STATUS DeferredStatus
    )
{
    QUIC_CONNECTION_EVENT Event;
    Connection->Crypto.CertValidationPending = TRUE;
    Event.Type = QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED;
    Event.PEER_CERTIFICATE_RECEIVED.Certificate = Certificate;
    Event.PEER_CERTIFICATE_RECEIVED.Chain = Chain;
    Event.PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags = DeferredErrorFlags;
    Event.PEER_CERTIFICATE_RECEIVED.DeferredStatus = DeferredStatus;
    QuicTraceLogConnVerbose(
        IndicatePeerCertificateReceived,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)",
        DeferredErrorFlags,
        DeferredStatus);
    QUIC_STATUS Status = QuicConnIndicateEvent(Connection, &Event);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Custom cert validation failed.");
        Connection->Crypto.CertValidationPending = FALSE;
        return FALSE;
    }
    if (Status == QUIC_STATUS_PENDING) {
        //
        // Don't set pending here because validation may have completed in the callback.
        //
        QuicTraceLogConnInfo(
            CustomCertValidationPending,
            Connection,
            "Custom cert validation is pending");
    } else if (Status == QUIC_STATUS_SUCCESS) {
        Connection->Crypto.CertValidationPending = FALSE;
    }
    return TRUE; // Treat pending as success to the TLS layer.
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueRecvPackets(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packets,
    _In_ uint32_t PacketChainLength,
    _In_ uint32_t PacketChainByteLength
    )
{
    QUIC_RX_PACKET** PacketsTail = (QUIC_RX_PACKET**)&Packets->Next;
    Packets->QueuedOnConnection = TRUE;
    Packets->AssignedToConnection = TRUE;
    while (*PacketsTail != NULL) {
        (*PacketsTail)->QueuedOnConnection = TRUE;
        (*PacketsTail)->AssignedToConnection = TRUE;
        PacketsTail = (QUIC_RX_PACKET**)&((*PacketsTail)->Next);
    }

    //
    // Base the limit of queued packets on the connection-wide flow control, but
    // allow at least a few packets even if the app configured an extremely
    // tiny FC window.
    //
    const uint32_t QueueLimit =
        CXPLAT_MAX(10, Connection->Settings.ConnFlowControlWindow >> 10);

    QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u UDP datagrams",
        PacketChainLength);

    BOOLEAN QueueOperation;
    CxPlatDispatchLockAcquire(&Connection->ReceiveQueueLock);
    if (Connection->ReceiveQueueCount >= QueueLimit) {
        QueueOperation = FALSE;
    } else {
        *Connection->ReceiveQueueTail = Packets;
        Connection->ReceiveQueueTail = PacketsTail;
        Packets = NULL;
        QueueOperation = (Connection->ReceiveQueueCount == 0);
        Connection->ReceiveQueueCount += PacketChainLength;
        Connection->ReceiveQueueByteCount += PacketChainByteLength;
    }
    CxPlatDispatchLockRelease(&Connection->ReceiveQueueLock);

    if (Packets != NULL) {
        QUIC_RX_PACKET* Packet = Packets;
        do {
            Packet->QueuedOnConnection = FALSE;
            QuicPacketLogDrop(Connection, Packet, "Max queue limit reached");
        } while ((Packet = (QUIC_RX_PACKET*)Packet->Next) != NULL);
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)Packets);
        return;
    }

    if (QueueOperation) {
        QUIC_OPERATION* ConnOper =
            QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_FLUSH_RECV);
        if (ConnOper != NULL) {
            QuicConnQueueOper(Connection, ConnOper);
        } else {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Flush Recv operation",
                0);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueUnreachable(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (Connection->Crypto.TlsState.ReadKey > QUIC_PACKET_KEY_INITIAL) {
        //
        // Only queue unreachable events at the beginning of the handshake.
        // Otherwise, it opens up an attack surface.
        //
        QuicTraceLogConnWarning(
            IgnoreUnreachable,
            Connection,
            "Ignoring received unreachable event (inline)");
        return;
    }

    QUIC_OPERATION* ConnOper =
        QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_UNREACHABLE);
    if (ConnOper != NULL) {
        ConnOper->UNREACHABLE.RemoteAddress = *RemoteAddress;
        QuicConnQueueOper(Connection, ConnOper);
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Unreachable operation",
            0);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_ROUTE_RESOLUTION_CALLBACK)
void
QuicConnQueueRouteCompletion(
    _Inout_ void* Context,
    _When_(Succeeded == FALSE, _Reserved_)
    _When_(Succeeded == TRUE, _In_reads_bytes_(6))
        const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    )
{
    QUIC_CONNECTION* Connection = (QUIC_CONNECTION*)Context;
    QUIC_OPERATION* ConnOper =
        QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_ROUTE_COMPLETION);
    if (ConnOper != NULL) {
        ConnOper->ROUTE.Succeeded = Succeeded;
        ConnOper->ROUTE.PathId = PathId;
        if (Succeeded) {
            memcpy(ConnOper->ROUTE.PhysicalAddress, PhysicalAddress, sizeof(ConnOper->ROUTE.PhysicalAddress));
        }
        QuicConnQueueOper(Connection, ConnOper);
    } else if (InterlockedCompareExchange16((short*)&Connection->BackUpOperUsed, 1, 0) == 0) {
        QUIC_OPERATION* Oper = &Connection->BackUpOper;
        Oper->FreeAfterProcess = FALSE;
        Oper->Type = QUIC_OPER_TYPE_API_CALL;
        Oper->API_CALL.Context = &Connection->BackupApiContext;
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
        Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT;
        Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = QUIC_ERROR_INTERNAL_ERROR;
        Oper->API_CALL.Context->CONN_SHUTDOWN.RegistrationShutdown = FALSE;
        Oper->API_CALL.Context->CONN_SHUTDOWN.TransportShutdown = TRUE;
        QuicConnQueueHighestPriorityOper(Connection, Oper);
    }

    QuicConnRelease(Connection, QUIC_CONN_REF_ROUTE);
}

//
// Updates the current destination CID to the received packet's source CID, if
// not already equal. Only used during the handshake, on the client side.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnUpdateDestCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* const Packet
    )
{
    CXPLAT_DBG_ASSERT(QuicConnIsClient(Connection));
    CXPLAT_DBG_ASSERT(!Connection->State.Connected);

    if (CxPlatListIsEmpty(&Connection->DestCids)) {
        CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled());
        QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
        return FALSE;
    }
    QUIC_CID_LIST_ENTRY* DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);
    CXPLAT_DBG_ASSERT(Connection->Paths[0].DestCid == DestCid);

    if (Packet->SourceCidLen != DestCid->CID.Length ||
        memcmp(Packet->SourceCid, DestCid->CID.Data, DestCid->CID.Length) != 0) {

        // TODO - Only update for the first packet of each type (Initial and Retry).

        QuicTraceEvent(
            ConnDestCidRemoved,
            "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
            Connection,
            DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));

        //
        // We have just received the a packet from a new source CID
        // from the server. Remove the current DestCid we have for the
        // server (which we randomly generated) and replace it with
        // the one we have just received.
        //
        if (Packet->SourceCidLen <= DestCid->CID.Length) {
            //
            // Since the current structure has enough room for the
            // new CID, we will just reuse it.
            //
            DestCid->CID.IsInitial = FALSE;
            DestCid->CID.Length = Packet->SourceCidLen;
            CxPlatCopyMemory(DestCid->CID.Data, Packet->SourceCid, DestCid->CID.Length);
        } else {
            //
            // There isn't enough room in the existing structure,
            // so we must allocate a new one and free the old one.
            //
            CxPlatListEntryRemove(&DestCid->Link);
            CXPLAT_FREE(DestCid, QUIC_POOL_CIDLIST);
            DestCid =
                QuicCidNewDestination(
                    Packet->SourceCidLen,
                    Packet->SourceCid);
            if (DestCid == NULL) {
                Connection->DestCidCount--;
                Connection->Paths[0].DestCid = NULL;
                QuicConnFatalError(Connection, QUIC_STATUS_OUT_OF_MEMORY, "Out of memory");
                return FALSE;
            }

            Connection->Paths[0].DestCid = DestCid;
            QUIC_CID_SET_PATH(Connection, DestCid, &Connection->Paths[0]);
            DestCid->CID.UsedLocally = TRUE;
            CxPlatListInsertHead(&Connection->DestCids, &DestCid->Link);
        }

        if (DestCid != NULL) {
            QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                Connection,
                DestCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
        }
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvVerNeg(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* const Packet
    )
{
    uint32_t SupportedVersion = 0;

    // TODO - Validate the packet's SourceCid is equal to our DestCid.

    const uint32_t* ServerVersionList =
        (const uint32_t*)(
        Packet->VerNeg->DestCid +
        Packet->VerNeg->DestCidLength +
        sizeof(uint8_t) +                                         // SourceCidLength field size
        Packet->VerNeg->DestCid[Packet->VerNeg->DestCidLength]);  // SourceCidLength
    uint16_t ServerVersionListLength =
        (Packet->AvailBufferLength - (uint16_t)((uint8_t*)ServerVersionList - Packet->AvailBuffer)) / sizeof(uint32_t);

    //
    // Go through the list and make sure it doesn't include our originally
    // requested version. If it does, we are supposed to ignore it. Cache the
    // first supported version.
    //
    QuicTraceLogVerbose(
        PacketRxVersionNegotiation,
        "[C][RX][-] VN");
    for (uint16_t i = 0; i < ServerVersionListLength; i++) {

        uint32_t ServerVersion;
        CxPlatCopyMemory(&ServerVersion, &ServerVersionList[i], sizeof(ServerVersion));

        QuicTraceLogVerbose(
            PacketRxVersionNegVer,
            "[C][RX][-]   Ver[%d]: 0x%x",
            (int32_t)i,
            CxPlatByteSwapUint32(ServerVersion));

        //
        // Check to see if this is the current version.
        //
        if (ServerVersion == Connection->Stats.QuicVersion && !QuicIsVersionReserved(ServerVersion)) {
            QuicPacketLogDrop(Connection, Packet, "Version Negotation that includes the current version");
            return;
        }

        //
        // Check to see if this is supported, if we haven't already found a
        // supported version.
        //
        if (SupportedVersion == 0 &&
            ((QuicConnIsClient(Connection) && QuicVersionNegotiationExtIsVersionClientSupported(Connection, ServerVersion)) ||
            (QuicConnIsServer(Connection) && QuicVersionNegotiationExtIsVersionServerSupported(ServerVersion)))) {
            SupportedVersion = ServerVersion;
        }
    }

    if (SupportedVersion == 0) {
        //
        // No match! Connection failure.
        //
        QuicTraceLogConnError(
            RecvVerNegNoMatch,
            Connection,
            "Version Negotation contained no supported versions");
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_VER_NEG_ERROR,
            NULL);
        return;
    }

    Connection->PreviousQuicVersion = Connection->Stats.QuicVersion;
    Connection->Stats.QuicVersion = SupportedVersion;
    QuicConnOnQuicVersionSet(Connection);
    QUIC_STATUS Status = QuicCryptoOnVersionChange(&Connection->Crypto);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogConnError(
            RecvVerNegCryptoError,
            Connection,
            "Failed to update crypto on ver neg");
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)Status,
            NULL);
        return;
    }
    QuicConnRestart(Connection, TRUE);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvRetry(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    //
    // Only clients should receive Retry packets.
    //
    if (QuicConnIsServer(Connection)) {
        QuicPacketLogDrop(Connection, Packet, "Retry sent to server");
        return;
    }

    //
    // Make sure we are in the correct state of the handshake.
    //
    if (Connection->State.GotFirstServerResponse) {
        QuicPacketLogDrop(Connection, Packet, "Already received server response");
        return;
    }

    //
    // Make sure the connection is still active
    //
    if (Connection->State.ClosedLocally || Connection->State.ClosedRemotely) {
        QuicPacketLogDrop(Connection, Packet, "Retry while shutting down");
        return;
    }

    //
    // Decode and validate the Retry packet.
    //

    if (Packet->AvailBufferLength - Packet->HeaderLength <= QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1) {
        QuicPacketLogDrop(Connection, Packet, "No room for Retry Token");
        return;
    }

    if (!QuicVersionNegotiationExtIsVersionClientSupported(Connection, Packet->LH->Version)) {
        QuicPacketLogDrop(Connection, Packet, "Retry Version not supported by client");
    }

    const QUIC_VERSION_INFO* VersionInfo = NULL;
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Packet->LH->Version) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }
    CXPLAT_FRE_ASSERT(VersionInfo != NULL);

    const uint8_t* Token = (Packet->AvailBuffer + Packet->HeaderLength);
    uint16_t TokenLength = Packet->AvailBufferLength - (Packet->HeaderLength + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1);

    QuicPacketLogHeader(
        Connection,
        TRUE,
        0,
        0,
        Packet->AvailBufferLength,
        Packet->AvailBuffer,
        0);

    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->DestCids));
    const QUIC_CID_LIST_ENTRY* DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);

    uint8_t CalculatedIntegrityValue[QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1];

    if (QUIC_FAILED(
        QuicPacketGenerateRetryIntegrity(
            VersionInfo,
            DestCid->CID.Length,
            DestCid->CID.Data,
            Packet->AvailBufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1,
            Packet->AvailBuffer,
            CalculatedIntegrityValue))) {
        QuicPacketLogDrop(Connection, Packet, "Failed to generate integrity field");
        return;
    }

    if (memcmp(
            CalculatedIntegrityValue,
            Packet->AvailBuffer + (Packet->AvailBufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1),
            QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1) != 0) {
        QuicPacketLogDrop(Connection, Packet, "Invalid integrity field");
        return;
    }

    //
    // Cache the Retry token.
    //

    Connection->Send.InitialToken = CXPLAT_ALLOC_PAGED(TokenLength, QUIC_POOL_INITIAL_TOKEN);
    if (Connection->Send.InitialToken == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "InitialToken",
            TokenLength);
        QuicPacketLogDrop(Connection, Packet, "InitialToken alloc failed");
        return;
    }

    Connection->Send.InitialTokenLength = TokenLength;
    memcpy((uint8_t*)Connection->Send.InitialToken, Token, TokenLength);

    //
    // Update the (destination) server's CID.
    //
    if (!QuicConnUpdateDestCid(Connection, Packet)) {
        return;
    }

    Connection->State.GotFirstServerResponse = TRUE;
    Connection->State.HandshakeUsedRetryPacket = TRUE;

    //
    // Update the Initial packet's key based on the new CID.
    //
    QuicPacketKeyFree(Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL]);
    QuicPacketKeyFree(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL]);
    Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] = NULL;
    Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] = NULL;

    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->DestCids));
    DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);

    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
        QuicPacketKeyCreateInitial(
            QuicConnIsServer(Connection),
            &VersionInfo->HkdfLabels,
            VersionInfo->Salt,
            DestCid->CID.Length,
            DestCid->CID.Data,
            &Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
            &Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL]))) {
        QuicConnFatalError(Connection, Status, "Failed to create initial keys");
        return;
    }

    Connection->Stats.StatelessRetry = TRUE;

    //
    // Restart the connection, using the new CID and Retry Token.
    //
    QuicConnRestart(Connection, FALSE);

    Packet->CompletelyValid = TRUE;
}

//
// Tries to get the requested decryption key or defers the packet for later
// processing.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnGetKeyOrDeferDatagram(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    if (Packet->KeyType > Connection->Crypto.TlsState.ReadKey) {

        //
        // We don't have the necessary key yet so try to defer the packet until
        // we get the key.
        //

        if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT &&
            Connection->Crypto.TlsState.EarlyDataState != CXPLAT_TLS_EARLY_DATA_UNKNOWN) {
            //
            // We don't have the 0-RTT key, but we aren't in an unknown
            // "early data" state, so it must be rejected/unsupported. Just drop
            // the packets.
            //
            CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.EarlyDataState != CXPLAT_TLS_EARLY_DATA_ACCEPTED);
            QuicPacketLogDrop(Connection, Packet, "0-RTT not currently accepted");

        } else {
            QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
            QUIC_PACKET_SPACE* Packets = Connection->Packets[EncryptLevel];
            if (Packets->DeferredPacketsCount == QUIC_MAX_PENDING_DATAGRAMS) {
                //
                // We already have too many packets queued up. Just drop this
                // one.
                //
                QuicPacketLogDrop(Connection, Packet, "Max deferred packet count reached");

            } else {
                QuicTraceLogConnVerbose(
                    DeferDatagram,
                    Connection,
                    "Deferring datagram (type=%hu)",
                    (uint16_t)Packet->KeyType);

                Packets->DeferredPacketsCount++;
                Packet->ReleaseDeferred = TRUE;

                //
                // Add it to the list of pending packets that are waiting on a
                // key to decrypt with.
                //
                QUIC_RX_PACKET** Tail = &Packets->DeferredPackets;
                while (*Tail != NULL) {
                    Tail = (QUIC_RX_PACKET**)&((*Tail)->Next);
                }
                *Tail = Packet;
                (*Tail)->Next = NULL;
            }
        }

        return FALSE;
    }

    if (QuicConnIsServer(Connection) && !Connection->State.HandshakeConfirmed &&
        Packet->KeyType == QUIC_PACKET_KEY_1_RTT) {
        //
        // A server MUST NOT process incoming 1-RTT protected packets before the TLS
        // handshake is complete.
        //
        return FALSE;
    }

    _Analysis_assume_(Packet->KeyType >= 0 && Packet->KeyType < QUIC_PACKET_KEY_COUNT);
    if (Connection->Crypto.TlsState.ReadKeys[Packet->KeyType] == NULL) {
        //
        // This key is no longer being accepted. Throw the packet away.
        //
        QuicPacketLogDrop(Connection, Packet, "Key no longer accepted");
        return FALSE;
    }

    return TRUE;
}

//
// Validates a received packet's header. Returns TRUE if the packet should be
// processed further.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicConnRecvHeader(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet,
    _Out_writes_all_(16) uint8_t* Cipher
    )
{
    //
    // Check invariants and packet version.
    //

    if (!Packet->ValidatedHeaderInv) {
        CXPLAT_DBG_ASSERT(Packet->DestCid != NULL); // This should only hit for coalesced packets.
        if (!QuicPacketValidateInvariant(Connection, Packet, Connection->State.ShareBinding)) {
            return FALSE;
        }
    }

    if (!Packet->IsShortHeader) {
        if (Packet->Invariant->LONG_HDR.Version != Connection->Stats.QuicVersion) {
            if (QuicConnIsClient(Connection) &&
                !Connection->State.CompatibleVerNegotiationAttempted &&
                QuicVersionNegotiationExtIsVersionCompatible(Connection, Packet->Invariant->LONG_HDR.Version)) {
                //
                // Server did compatible version negotiation, update local version
                // to proceed to TP processing. The TP processing must validate
                // this new version is the same as in the ChosenVersion field.
                //
                Connection->OriginalQuicVersion = Connection->Stats.QuicVersion;
                Connection->State.CompatibleVerNegotiationAttempted = TRUE;
                Connection->Stats.QuicVersion = Packet->Invariant->LONG_HDR.Version;
                QuicConnOnQuicVersionSet(Connection);
                if (QUIC_FAILED(QuicCryptoOnVersionChange(&Connection->Crypto))) {
                    return FALSE;
                }
                //
                // Do not return FALSE here, continue with the connection.
                //
            } else if (QuicConnIsClient(Connection) &&
                Packet->Invariant->LONG_HDR.Version == QUIC_VERSION_VER_NEG &&
                !Connection->Stats.VersionNegotiation) {
                //
                // Version negotiation packet received.
                //
                Connection->Stats.VersionNegotiation = TRUE;
                QuicConnRecvVerNeg(Connection, Packet);

                return FALSE;
            } else {
                QuicPacketLogDropWithValue(Connection, Packet, "Invalid version", CxPlatByteSwapUint32(Packet->Invariant->LONG_HDR.Version));
                return FALSE;
            }
        }
    } else {
        if (!QuicIsVersionSupported(Connection->Stats.QuicVersion)) {
            QuicPacketLogDrop(Connection, Packet, "SH packet during version negotiation");
            return FALSE;
        }
    }

    CXPLAT_FRE_ASSERT(QuicIsVersionSupported(Connection->Stats.QuicVersion));

    //
    // Begin non-version-independent logic. When future versions are supported,
    // there may be some switches based on packet version.
    //

    if (!Packet->IsShortHeader) {
#if DEBUG
        if (Connection->State.ShareBinding) {
            CXPLAT_DBG_ASSERT(Packet->DestCidLen >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
        } else {
            CXPLAT_DBG_ASSERT(Packet->DestCidLen == 0);
        }
#endif

        if ((Packet->LH->Version != QUIC_VERSION_2 && Packet->LH->Type == QUIC_RETRY_V1) ||
            (Packet->LH->Version == QUIC_VERSION_2 && Packet->LH->Type == QUIC_RETRY_V2)) {
            QuicConnRecvRetry(Connection, Packet);
            return FALSE;
        }

        const uint8_t* TokenBuffer = NULL;
        uint16_t TokenLength = 0;

        if (!Packet->ValidatedHeaderVer &&
            !QuicPacketValidateLongHeaderV1(
                Connection,
                QuicConnIsServer(Connection),
                Packet,
                &TokenBuffer,
                &TokenLength,
                Connection->Settings.GreaseQuicBitEnabled)) {
            return FALSE;
        }

        QUIC_PATH* Path = &Connection->Paths[0];
        if (!Path->IsPeerValidated && (Packet->ValidToken || TokenLength != 0)) {

            BOOLEAN InvalidRetryToken = FALSE;
            if (Packet->ValidToken) {
                CXPLAT_DBG_ASSERT(TokenBuffer == NULL);
                CXPLAT_DBG_ASSERT(TokenLength == 0);
                QuicPacketDecodeRetryTokenV1(Packet, &TokenBuffer, &TokenLength);
            } else {
                CXPLAT_DBG_ASSERT(TokenBuffer != NULL);
                if (!QuicPacketValidateInitialToken(
                        Connection,
                        Packet,
                        TokenLength,
                        TokenBuffer,
                        &InvalidRetryToken) &&
                    InvalidRetryToken) {
                    return FALSE;
                }
            }

            if (!InvalidRetryToken) {
                CXPLAT_DBG_ASSERT(TokenBuffer != NULL);
                CXPLAT_DBG_ASSERT(TokenLength == sizeof(QUIC_TOKEN_CONTENTS));

                QUIC_TOKEN_CONTENTS Token;
                if (!QuicRetryTokenDecrypt(Packet, TokenBuffer, &Token)) {
                    CXPLAT_DBG_ASSERT(FALSE); // Was already decrypted sucessfully once.
                    QuicPacketLogDrop(Connection, Packet, "Retry token decrypt failure");
                    return FALSE;
                }

                CXPLAT_DBG_ASSERT(Token.Encrypted.OrigConnIdLength <= sizeof(Token.Encrypted.OrigConnId));
                CXPLAT_DBG_ASSERT(QuicAddrCompare(&Path->Route.RemoteAddress, &Token.Encrypted.RemoteAddress));

                if (Connection->OrigDestCID != NULL) {
                    CXPLAT_FREE(Connection->OrigDestCID, QUIC_POOL_CID);
                }

                Connection->OrigDestCID =
                    CXPLAT_ALLOC_NONPAGED(
                        sizeof(QUIC_CID) +
                        Token.Encrypted.OrigConnIdLength,
                        QUIC_POOL_CID);
                if (Connection->OrigDestCID == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "OrigDestCID",
                        sizeof(QUIC_CID) + Token.Encrypted.OrigConnIdLength);
                    QuicPacketLogDrop(Connection, Packet, "OrigDestCID from Retry OOM");
                    return FALSE;
                }

                Connection->OrigDestCID->Length = Token.Encrypted.OrigConnIdLength;
                CxPlatCopyMemory(
                    Connection->OrigDestCID->Data,
                    Token.Encrypted.OrigConnId,
                    Token.Encrypted.OrigConnIdLength);
                Connection->State.HandshakeUsedRetryPacket = TRUE;

                QuicPathSetValid(Connection, Path, QUIC_PATH_VALID_INITIAL_TOKEN);
            }
        }

        if (Connection->OrigDestCID == NULL) {

            Connection->OrigDestCID =
                CXPLAT_ALLOC_NONPAGED(
                    sizeof(QUIC_CID) +
                    Packet->DestCidLen,
                    QUIC_POOL_CID);
            if (Connection->OrigDestCID == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + Packet->DestCidLen);
                QuicPacketLogDrop(Connection, Packet, "OrigDestCID OOM");
                return FALSE;
            }

            Connection->OrigDestCID->Length = Packet->DestCidLen;
            CxPlatCopyMemory(
                Connection->OrigDestCID->Data,
                Packet->DestCid,
                Packet->DestCidLen);
        }

        if (Packet->LH->Version == QUIC_VERSION_2) {
            Packet->KeyType = QuicPacketTypeToKeyTypeV2(Packet->LH->Type);
        } else {
            Packet->KeyType = QuicPacketTypeToKeyTypeV1(Packet->LH->Type);
        }
        Packet->Encrypted = TRUE;

    } else {

        if (!Packet->ValidatedHeaderVer &&
            !QuicPacketValidateShortHeaderV1(Connection, Packet, Connection->Settings.GreaseQuicBitEnabled)) {
            return FALSE;
        }

        Packet->KeyType = QUIC_PACKET_KEY_1_RTT;
        Packet->Encrypted =
            !Connection->State.Disable1RttEncrytion &&
            !Connection->Paths[0].EncryptionOffloading;
    }

    if (Packet->Encrypted &&
        Connection->State.HeaderProtectionEnabled &&
        Packet->PayloadLength < 4 + CXPLAT_HP_SAMPLE_LENGTH) {
        QuicPacketLogDrop(Connection, Packet, "Too short for HP");
        return FALSE;
    }

    //
    // If the key is not present then we will attempt to queue the packet
    // and defer processing for later.
    //
    // For compound packets, we defer processing the rest of the UDP packet
    // once we reach a QUIC packet we can't decrypt.
    //
    if (!QuicConnGetKeyOrDeferDatagram(Connection, Packet)) {
        return FALSE;
    }

    //
    // To decrypt the header, the payload after the header is used as the IV. We
    // don't actually know the length of the packet number so we assume maximum
    // (per spec) and start sampling 4 bytes after the start of the packet number.
    //
    CxPlatCopyMemory(
        Cipher,
        Packet->AvailBuffer + Packet->HeaderLength + 4,
        CXPLAT_HP_SAMPLE_LENGTH);

    return TRUE;
}

//
// Decodes and decompresses the packet number. If necessary, updates the key
// phase accordingly, to allow for decryption as the next step. Returns TRUE if
// the packet should continue to be processed further.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvPrepareDecrypt(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet,
    _In_reads_(16) const uint8_t* HpMask
    )
{
    CXPLAT_DBG_ASSERT(Packet->ValidatedHeaderInv);
    CXPLAT_DBG_ASSERT(Packet->ValidatedHeaderVer);
    CXPLAT_DBG_ASSERT(Packet->HeaderLength <= Packet->AvailBufferLength);
    CXPLAT_DBG_ASSERT(Packet->PayloadLength <= Packet->AvailBufferLength);
    CXPLAT_DBG_ASSERT(Packet->HeaderLength + Packet->PayloadLength <= Packet->AvailBufferLength);

    //
    // Packet->HeaderLength currently points to the start of the encrypted
    // packet number and Packet->PayloadLength includes the length of the rest
    // of the packet from that point on.
    //

    //
    // Decrypt the first byte of the header to get the packet number length.
    //
    uint8_t CompressedPacketNumberLength = 0;
    if (Packet->IsShortHeader) {
        ((uint8_t*)Packet->AvailBuffer)[0] ^= HpMask[0] & 0x1f; // Only the first 5 bits
        CompressedPacketNumberLength = Packet->SH->PnLength + 1;
    } else {
        ((uint8_t*)Packet->AvailBuffer)[0] ^= HpMask[0] & 0x0f; // Only the first 4 bits
        CompressedPacketNumberLength = Packet->LH->PnLength + 1;
    }

    CXPLAT_DBG_ASSERT(CompressedPacketNumberLength >= 1 && CompressedPacketNumberLength <= 4);
    CXPLAT_DBG_ASSERT(Packet->HeaderLength + CompressedPacketNumberLength <= Packet->AvailBufferLength);

    //
    // Decrypt the packet number now that we have the length.
    //
    for (uint8_t i = 0; i < CompressedPacketNumberLength; i++) {
        ((uint8_t*)Packet->AvailBuffer)[Packet->HeaderLength + i] ^= HpMask[1 + i];
    }

    //
    // Decode the packet number into the compressed packet number. The
    // compressed packet number only represents the least significant N bytes of
    // the true packet number.
    //

    uint64_t CompressedPacketNumber = 0;
    QuicPktNumDecode(
        CompressedPacketNumberLength,
        Packet->AvailBuffer + Packet->HeaderLength,
        &CompressedPacketNumber);

    Packet->HeaderLength += CompressedPacketNumberLength;
    Packet->PayloadLength -= CompressedPacketNumberLength;

    //
    // Decompress the packet number into the full packet number.
    //

    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    Packet->PacketNumber =
        QuicPktNumDecompress(
            Connection->Packets[EncryptLevel]->NextRecvPacketNumber,
            CompressedPacketNumber,
            CompressedPacketNumberLength);
    Packet->PacketNumberSet = TRUE;

    if (Packet->PacketNumber > QUIC_VAR_INT_MAX) {
        QuicPacketLogDrop(Connection, Packet, "Packet number too big");
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(Packet->IsShortHeader ||
        ((Packet->LH->Version != QUIC_VERSION_2 && Packet->LH->Type != QUIC_RETRY_V1) ||
        (Packet->LH->Version == QUIC_VERSION_2 && Packet->LH->Type != QUIC_RETRY_V2)));

    //
    // Ensure minimum encrypted payload length.
    //
    if (Packet->Encrypted &&
        Packet->PayloadLength < CXPLAT_ENCRYPTION_OVERHEAD) {
        QuicPacketLogDrop(Connection, Packet, "Payload length less than encryption tag");
        return FALSE;
    }

    QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    if (Packet->IsShortHeader && EncryptLevel == QUIC_ENCRYPT_LEVEL_1_RTT &&
        Packet->SH->KeyPhase != PacketSpace->CurrentKeyPhase) {
        if (Packet->PacketNumber < PacketSpace->ReadKeyPhaseStartPacketNumber) {
            //
            // The packet doesn't match our current key phase and the packet number
            // is less than the start of the current key phase, so this is likely
            // using the old keys.
            //
            QuicTraceLogConnVerbose(
                DecryptOldKey,
                Connection,
                "Using old key to decrypt");
            CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT_OLD] != NULL);
            CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT_OLD] != NULL);
            Packet->KeyType = QUIC_PACKET_KEY_1_RTT_OLD;
        } else {
            //
            // The packet doesn't match our key phase, and the packet number is higher
            // than the start of the current key phase, so most likely using a new key phase.
            // Update the keys and try it out. If this fails, the packet was invalid anyway.
            //
            QuicTraceLogConnVerbose(
                PossiblePeerKeyUpdate,
                Connection,
                "Possible peer initiated key update [packet %llu]",
                Packet->PacketNumber);

            QUIC_STATUS Status = QuicCryptoGenerateNewKeys(Connection);
            if (QUIC_FAILED(Status)) {
                QuicPacketLogDrop(Connection, Packet, "Generate new packet keys");
                return FALSE;
            }
            Packet->KeyType = QUIC_PACKET_KEY_1_RTT_NEW;
        }
    }

    return TRUE;
}

//
// Decrypts the packet's payload and authenticates the whole packet. On
// successful authentication of the packet, does some final processing of the
// packet header (key and CID updates). Returns TRUE if the packet should
// continue to be processed further.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvDecryptAndAuthenticate(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    CXPLAT_DBG_ASSERT(Packet->AvailBufferLength >= Packet->HeaderLength + Packet->PayloadLength);

    const uint8_t* Payload = Packet->AvailBuffer + Packet->HeaderLength;

    //
    // We need to copy the end of the packet before trying decryption, as a
    // failed decryption trashes the stateless reset token.
    //
    BOOLEAN CanCheckForStatelessReset = FALSE;
    uint8_t PacketResetToken[QUIC_STATELESS_RESET_TOKEN_LENGTH];
    if (QuicConnIsClient(Connection) &&
        Packet->IsShortHeader &&
        Packet->HeaderLength + Packet->PayloadLength >= QUIC_MIN_STATELESS_RESET_PACKET_LENGTH) {
        CanCheckForStatelessReset = TRUE;
        CxPlatCopyMemory(
            PacketResetToken,
            Payload + Packet->PayloadLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
            QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }

    CXPLAT_DBG_ASSERT(Packet->PacketId != 0);

    uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
    QuicCryptoCombineIvAndPacketNumber(
        Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->Iv,
        (uint8_t*)&Packet->PacketNumber,
        Iv);

    //
    // Decrypt the payload with the appropriate key.
    //
    if (Packet->Encrypted) {
        QuicTraceEvent(
            PacketDecrypt,
            "[pack][%llu] Decrypting",
            Packet->PacketId);
        if (QUIC_FAILED(
            CxPlatDecrypt(
                Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->PacketKey,
                Iv,
                Packet->HeaderLength,   // HeaderLength
                Packet->AvailBuffer,    // Header
                Packet->PayloadLength,  // BufferLength
                (uint8_t*)Payload))) {  // Buffer

            //
            // Check for a stateless reset packet.
            //
            if (CanCheckForStatelessReset) {
                for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
                        Entry != &Connection->DestCids;
                        Entry = Entry->Flink) {
                    //
                    // Loop through all our stored stateless reset tokens to see if
                    // we have a match.
                    //
                    QUIC_CID_LIST_ENTRY* DestCid =
                        CXPLAT_CONTAINING_RECORD(
                            Entry,
                            QUIC_CID_LIST_ENTRY,
                            Link);
                    if (DestCid->CID.HasResetToken &&
                        !DestCid->CID.Retired &&
                        memcmp(
                            DestCid->ResetToken,
                            PacketResetToken,
                            QUIC_STATELESS_RESET_TOKEN_LENGTH) == 0) {
                        QuicTraceLogVerbose(
                            PacketRxStatelessReset,
                            "[S][RX][-] SR %s",
                            QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
                        QuicTraceLogConnInfo(
                            RecvStatelessReset,
                            Connection,
                            "Received stateless reset");
                        QuicConnCloseLocally(
                            Connection,
                            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                            (uint64_t)QUIC_STATUS_ABORTED,
                            NULL);
                        return FALSE;
                    }
                }
            }

            if (QuicTraceLogVerboseEnabled()) {
                QuicPacketLogHeader(
                    Connection,
                    TRUE,
                    Connection->State.ShareBinding ? MsQuicLib.CidTotalLength : 0,
                    Packet->PacketNumber,
                    Packet->HeaderLength,
                    Packet->AvailBuffer,
                    Connection->Stats.QuicVersion);
            }
            Connection->Stats.Recv.DecryptionFailures++;
            QuicPacketLogDrop(Connection, Packet, "Decryption failure");
            QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL);
            if (Connection->Stats.Recv.DecryptionFailures >= CXPLAT_AEAD_INTEGRITY_LIMIT) {
                QuicConnTransportError(Connection, QUIC_ERROR_AEAD_LIMIT_REACHED);
            }

            return FALSE;
        }
    }

    Connection->Stats.Recv.ValidPackets++;

    //
    // Validate the header's reserved bits now that the packet has been
    // decrypted.
    //
    if (Packet->IsShortHeader) {
        if (Packet->SH->Reserved != 0) {
            QuicPacketLogDrop(Connection, Packet, "Invalid SH Reserved bits values");
            QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
            return FALSE;
        }
    } else {
        if (Packet->LH->Reserved != 0) {
            QuicPacketLogDrop(Connection, Packet, "Invalid LH Reserved bits values");
            QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
            return FALSE;
        }
    }

    //
    // Account for updated payload length after decryption.
    //
    if (Packet->Encrypted) {
        Packet->PayloadLength -= CXPLAT_ENCRYPTION_OVERHEAD;
    }

    //
    // At this point the packet has been completely decrypted and authenticated.
    // Now all header processing that can only be done on an authenticated
    // packet may continue.
    //

    //
    // Drop any duplicate packet numbers now that we know the packet number is
    // valid.
    //
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    if (QuicAckTrackerAddPacketNumber(
            &Connection->Packets[EncryptLevel]->AckTracker,
            Packet->PacketNumber)) {

        if (QuicTraceLogVerboseEnabled()) {
            QuicPacketLogHeader(
                Connection,
                TRUE,
                Connection->State.ShareBinding ? MsQuicLib.CidTotalLength : 0,
                Packet->PacketNumber,
                Packet->AvailBufferLength,
                Packet->AvailBuffer,
                Connection->Stats.QuicVersion);
        }
        QuicPacketLogDrop(Connection, Packet, "Duplicate packet number");
        Connection->Stats.Recv.DuplicatePackets++;
        return FALSE;
    }

    //
    // Log the received packet header and payload now that it's decrypted.
    //

    if (QuicTraceLogVerboseEnabled()) {
        QuicPacketLogHeader(
            Connection,
            TRUE,
            Connection->State.ShareBinding ? MsQuicLib.CidTotalLength : 0,
            Packet->PacketNumber,
            Packet->HeaderLength + Packet->PayloadLength,
            Packet->AvailBuffer,
            Connection->Stats.QuicVersion);
        QuicFrameLogAll(
            Connection,
            TRUE,
            Packet->PacketNumber,
            Packet->HeaderLength + Packet->PayloadLength,
            Packet->AvailBuffer,
            Packet->HeaderLength);
    }

    QuicTraceEvent(
        ConnPacketRecv,
        "[conn][%p][RX][%llu] %c (%hu bytes)",
        Connection,
        Packet->PacketNumber,
        Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1),
        Packet->HeaderLength + Packet->PayloadLength);

    //
    // Process any connection ID updates as necessary.
    //

    if (!Packet->IsShortHeader) {
        BOOLEAN IsVersion2 = (Connection->Stats.QuicVersion == QUIC_VERSION_2);
        if ((!IsVersion2 && Packet->LH->Type == QUIC_INITIAL_V1) ||
            (IsVersion2 && Packet->LH->Type == QUIC_INITIAL_V2)) {
            if (!Connection->State.Connected &&
                QuicConnIsClient(Connection) &&
                !QuicConnUpdateDestCid(Connection, Packet)) {
                //
                // Client side needs to respond to the server's new source
                // connection ID that is received in the first Initial packet.
                //
                return FALSE;
            }
        } else if ((!IsVersion2 && Packet->LH->Type == QUIC_0_RTT_PROTECTED_V1) ||
            (IsVersion2 && Packet->LH->Type == QUIC_0_RTT_PROTECTED_V2)) {

            CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
            Packet->EncryptedWith0Rtt = TRUE;
        }
    }

    //
    // Update key state if the keys have been updated.
    //

    if (Packet->IsShortHeader) {
        QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
        if (Packet->KeyType == QUIC_PACKET_KEY_1_RTT_NEW) {

            QuicCryptoUpdateKeyPhase(Connection, FALSE);
            PacketSpace->ReadKeyPhaseStartPacketNumber = Packet->PacketNumber;

            QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);

        } else if (Packet->KeyType == QUIC_PACKET_KEY_1_RTT &&
            Packet->SH->KeyPhase == PacketSpace->CurrentKeyPhase &&
            Packet->PacketNumber < PacketSpace->ReadKeyPhaseStartPacketNumber) {
            //
            // This packet is in the current key phase and before the current phase
            // start, so update the packet space start point.
            //
            PacketSpace->ReadKeyPhaseStartPacketNumber = Packet->PacketNumber;
            QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);
        }
    }

    if (Packet->KeyType == QUIC_PACKET_KEY_HANDSHAKE &&
        QuicConnIsServer(Connection)) {
        //
        // Per spec, server MUST discard Initial keys when it starts
        // decrypting packets using handshake keys.
        //
        QuicCryptoDiscardKeys(&Connection->Crypto, QUIC_PACKET_KEY_INITIAL);
        QuicPathSetValid(Connection, Path, QUIC_PATH_VALID_HANDSHAKE_PACKET);
    }

    return TRUE;
}

//
// Reads the frames in a packet, and if everything is successful marks the
// packet for acknowledgement and returns TRUE.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvFrames(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ CXPLAT_ECN_TYPE ECN
    )
{
    BOOLEAN AckEliciting = FALSE;
    BOOLEAN AckImmediately = FALSE;
    BOOLEAN UpdatedFlowControl = FALSE;
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    BOOLEAN Closed = Connection->State.ClosedLocally || Connection->State.ClosedRemotely;
    const uint8_t* Payload = Packet->AvailBuffer + Packet->HeaderLength;
    uint16_t PayloadLength = Packet->PayloadLength;
    uint64_t RecvTime = CxPlatTimeUs64();

    //
    // In closing state, respond to any packet with a new close frame (rate-limited).
    //
    if (Closed && !Connection->State.ShutdownComplete) {
        if (RecvTime - Connection->LastCloseResponseTimeUs >= QUIC_CLOSING_RESPONSE_MIN_INTERVAL) {
            QuicSendSetSendFlag(
                &Connection->Send,
                Connection->State.AppClosed ?
                    QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE :
                    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }
    }

    if (QuicConnIsClient(Connection) &&
        !Connection->State.GotFirstServerResponse) {
        Connection->State.GotFirstServerResponse = TRUE;
    }

    uint16_t Offset = 0;
    while (Offset < PayloadLength) {

        //
        // Read the frame type.
        //
        QUIC_VAR_INT FrameType INIT_NO_SAL(0);
        if (!QuicVarIntDecode(PayloadLength, Payload, &Offset, &FrameType)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Frame type decode failure");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        if (!QUIC_FRAME_IS_KNOWN(FrameType)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unknown frame type");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        //
        // Validate allowable frames based on the packet type.
        //
        if (EncryptLevel != QUIC_ENCRYPT_LEVEL_1_RTT) {
            switch (FrameType) {
            //
            // The following frames are allowed pre-1-RTT encryption level:
            //
            case QUIC_FRAME_PADDING:
            case QUIC_FRAME_PING:
            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_1:
            case QUIC_FRAME_CRYPTO:
            case QUIC_FRAME_CONNECTION_CLOSE:
                break;
            //
            // All other frame types are disallowed.
            //
            default:
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    (uint32_t)FrameType,
                    "Disallowed frame type");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

        } else if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT) {
            switch (FrameType) {
            //
            // The following frames are are disallowed in 0-RTT.
            //
            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_1:
            case QUIC_FRAME_HANDSHAKE_DONE:
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    (uint32_t)FrameType,
                    "Disallowed frame type");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            //
            // All other frame types are allowed.
            //
            default:
                break;
            }
        }

        //
        // Process the frame based on the frame type.
        //
        switch (FrameType) {

        case QUIC_FRAME_PADDING: {
            while (Offset < PayloadLength &&
                Payload[Offset] == QUIC_FRAME_PADDING) {
                Offset += sizeof(uint8_t);
            }
            break;
        }

        case QUIC_FRAME_PING: {
            //
            // No other payload. Just need to acknowledge the packet this was
            // contained in.
            //
            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_1: {
            BOOLEAN InvalidAckFrame;
            if (!QuicLossDetectionProcessAckFrame(
                    &Connection->LossDetection,
                    Path,
                    Packet,
                    EncryptLevel,
                    FrameType,
                    PayloadLength,
                    Payload,
                    &Offset,
                    &InvalidAckFrame)) {
                if (InvalidAckFrame) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid ACK frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                }
                return FALSE;
            }

            Connection->Stats.Recv.ValidAckFrames++;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_CRYPTO: {
            QUIC_CRYPTO_EX Frame;
            if (!QuicCryptoFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CRYPTO frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            QUIC_STATUS Status =
                QuicCryptoProcessFrame(
                    &Connection->Crypto,
                    Packet->KeyType,
                    &Frame);
            if (QUIC_SUCCEEDED(Status)) {
                AckEliciting = TRUE;
            } else if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                QuicPacketLogDrop(Connection, Packet, "Crypto frame process OOM");
                return FALSE;
            } else {
                if (Status == QUIC_STATUS_VER_NEG_ERROR) {
                    if (QuicBindingQueueStatelessOperation(
                            Connection->Paths[0].Binding,
                            QUIC_OPER_TYPE_VERSION_NEGOTIATION,
                            Packet)) {
                        Packet->ReleaseDeferred = TRUE;
                    }
                    QuicConnCloseLocally(
                        Connection,
                        QUIC_CLOSE_INTERNAL_SILENT,
                        QUIC_ERROR_VERSION_NEGOTIATION_ERROR,
                        NULL);
                } else if (Status != QUIC_STATUS_INVALID_STATE) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid CRYPTO frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                }
                return FALSE;
            }

            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_NEW_TOKEN: {
            QUIC_NEW_TOKEN_EX Frame;
            if (!QuicNewTokenFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding NEW_TOKEN frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            //
            // TODO - Save the token for future use.
            //

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_RESET_STREAM:
        case QUIC_FRAME_STOP_SENDING:
        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
        case QUIC_FRAME_MAX_STREAM_DATA:
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
        case QUIC_FRAME_RELIABLE_RESET_STREAM: {
            if (Closed) {
                if (!QuicStreamFrameSkip(
                        FrameType, PayloadLength, Payload, &Offset)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping closed stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }
                break; // Ignore frame if we are closed.
            }

            uint64_t StreamId;
            if (!QuicStreamFramePeekID(
                    PayloadLength, Payload, Offset, &StreamId)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding stream ID from frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            AckEliciting = TRUE;

            BOOLEAN PeerOriginatedStream =
                QuicConnIsServer(Connection) ?
                    STREAM_ID_IS_CLIENT(StreamId) :
                    STREAM_ID_IS_SERVER(StreamId);

            if (STREAM_ID_IS_UNI_DIR(StreamId)) {
                BOOLEAN IsReceiverSideFrame =
                    FrameType == QUIC_FRAME_MAX_STREAM_DATA ||
                    FrameType == QUIC_FRAME_STOP_SENDING;
                if (PeerOriginatedStream == IsReceiverSideFrame) {
                    //
                    // For locally initiated unidirectional streams, the peer
                    // should only send receiver frame types, and vice versa
                    // for peer initiated unidirectional streams.
                    //
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid frame on unidirectional stream");
                    QuicConnTransportError(Connection, QUIC_ERROR_STREAM_STATE_ERROR);
                    break;
                }
            }

            BOOLEAN FatalError;
            QUIC_STREAM* Stream =
                QuicStreamSetGetStreamForPeer(
                    &Connection->Streams,
                    StreamId,
                    Packet->EncryptedWith0Rtt,
                    PeerOriginatedStream,
                    &FatalError);

            if (Stream) {
                QUIC_STATUS Status =
                    QuicStreamRecv(
                        Stream,
                        Packet,
                        FrameType,
                        PayloadLength,
                        Payload,
                        &Offset,
                        &UpdatedFlowControl);
                QuicStreamRelease(Stream, QUIC_STREAM_REF_LOOKUP);
                if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                    QuicPacketLogDrop(Connection, Packet, "Stream frame process OOM");
                    return FALSE;
                }

                if (QUIC_FAILED(Status)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }

            } else if (FatalError) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Getting stream from ID");
                return FALSE;
            } else {
                //
                // Didn't find a matching Stream. Skip the frame as the Stream
                // might have been closed already.
                //
                QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
                if (!QuicStreamFrameSkip(
                        FrameType, PayloadLength, Payload, &Offset)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping ignored stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }
            }

            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_MAX_DATA: {
            QUIC_MAX_DATA_EX Frame;
            if (!QuicMaxDataFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_DATA frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Connection->Send.PeerMaxData < Frame.MaximumData) {
                Connection->Send.PeerMaxData = Frame.MaximumData;
                //
                // The peer has given us more allowance. Send packets from
                // any previously blocked streams.
                //
                UpdatedFlowControl = TRUE;
                QuicConnRemoveOutFlowBlockedReason(
                    Connection, QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL);
                QuicSendQueueFlush(
                    &Connection->Send, REASON_CONNECTION_FLOW_CONTROL);
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_MAX_STREAMS:
        case QUIC_FRAME_MAX_STREAMS_1: {
            QUIC_MAX_STREAMS_EX Frame;
            if (!QuicMaxStreamsFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_STREAMS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Frame.MaximumStreams > QUIC_TP_MAX_STREAMS_MAX) {
                QuicConnTransportError(Connection, QUIC_ERROR_STREAM_LIMIT_ERROR);
                break;
            }

            QuicStreamSetUpdateMaxStreams(
                &Connection->Streams,
                Frame.BidirectionalStreams,
                Frame.MaximumStreams);

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_DATA_BLOCKED: {
            QUIC_DATA_BLOCKED_EX Frame;
            if (!QuicDataBlockedFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            //
            // TODO - Should we do anything else with this?
            //
            QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_MAX_DATA);

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_STREAMS_BLOCKED:
        case QUIC_FRAME_STREAMS_BLOCKED_1: {
            QUIC_STREAMS_BLOCKED_EX Frame;
            if (!QuicStreamsBlockedFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding STREAMS_BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
            AckEliciting = TRUE;

            uint8_t Type =
                (QuicConnIsServer(Connection) ? // Peer's role, so flip
                STREAM_ID_FLAG_IS_CLIENT : STREAM_ID_FLAG_IS_SERVER)
                |
                (Frame.BidirectionalStreams ?
                 STREAM_ID_FLAG_IS_BI_DIR : STREAM_ID_FLAG_IS_UNI_DIR);

            const QUIC_STREAM_TYPE_INFO* Info = &Connection->Streams.Types[Type];

            if (Info->MaxTotalStreamCount > Frame.StreamLimit) {
                break;
            }

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
            Event.PEER_NEEDS_STREAMS.Bidirectional = Frame.BidirectionalStreams;
            QuicTraceLogConnVerbose(
                IndicatePeerNeedStreamsV2,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s",
                Frame.BidirectionalStreams ? "Bidi" : "Unidi"
                );
            (void)QuicConnIndicateEvent(Connection, &Event);

            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_NEW_CONNECTION_ID: {
            QUIC_NEW_CONNECTION_ID_EX Frame;
            if (!QuicNewConnectionIDFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding NEW_CONNECTION_ID frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            BOOLEAN ReplaceRetiredCids = FALSE;
            if (Connection->RetirePriorTo < Frame.RetirePriorTo) {
                Connection->RetirePriorTo = Frame.RetirePriorTo;
                ReplaceRetiredCids = QuicConnOnRetirePriorToUpdated(Connection);
            }

            if (QuicConnGetDestCidFromSeq(Connection, Frame.Sequence, FALSE) == NULL) {
                //
                // Create the new destination connection ID.
                //
                QUIC_CID_LIST_ENTRY* DestCid =
                    QuicCidNewDestination(Frame.Length, Frame.Buffer);
                if (DestCid == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "new DestCid",
                        sizeof(QUIC_CID_LIST_ENTRY) + Frame.Length);
                    if (ReplaceRetiredCids) {
                        QuicConnSilentlyAbort(Connection);
                    } else {
                        QuicConnFatalError(Connection, QUIC_STATUS_OUT_OF_MEMORY, NULL);
                    }
                    return FALSE;
                }

                DestCid->CID.HasResetToken = TRUE;
                DestCid->CID.SequenceNumber = Frame.Sequence;
                CxPlatCopyMemory(
                    DestCid->ResetToken,
                    Frame.Buffer + Frame.Length,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH);
                QuicTraceEvent(
                    ConnDestCidAdded,
                    "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                    Connection,
                    DestCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
                CxPlatListInsertTail(&Connection->DestCids, &DestCid->Link);
                Connection->DestCidCount++;

                if (DestCid->CID.SequenceNumber < Connection->RetirePriorTo) {
                    QuicConnRetireCid(Connection, DestCid);
                }

                if (Connection->DestCidCount > QUIC_ACTIVE_CONNECTION_ID_LIMIT) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Peer exceeded CID limit");
                    if (ReplaceRetiredCids) {
                        QuicConnSilentlyAbort(Connection);
                    } else {
                        QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                    }
                    return FALSE;
                }
            }

            if (ReplaceRetiredCids && !QuicConnReplaceRetiredCids(Connection)) {
                return FALSE;
            }

            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_RETIRE_CONNECTION_ID: {
            QUIC_RETIRE_CONNECTION_ID_EX Frame;
            if (!QuicRetireConnectionIDFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding RETIRE_CONNECTION_ID frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            BOOLEAN IsLastCid;
            QUIC_CID_HASH_ENTRY* SourceCid =
                QuicConnGetSourceCidFromSeq(
                    Connection,
                    Frame.Sequence,
                    TRUE,
                    &IsLastCid);
            if (SourceCid != NULL) {
                BOOLEAN CidAlreadyRetired = SourceCid->CID.Retired;
                CXPLAT_FREE(SourceCid, QUIC_POOL_CIDHASH);
                if (IsLastCid) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Last Source CID Retired!");
                    QuicConnCloseLocally(
                        Connection,
                        QUIC_CLOSE_INTERNAL_SILENT,
                        QUIC_ERROR_PROTOCOL_VIOLATION,
                        NULL);
                } else if (!CidAlreadyRetired) {
                    //
                    // Replace the CID if we weren't the one to request it to be
                    // retired in the first place.
                    //
                    if (!QuicConnGenerateNewSourceCid(Connection, FALSE)) {
                        break;
                    }
                }
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_PATH_CHALLENGE: {
            QUIC_PATH_CHALLENGE_EX Frame;
            if (!QuicPathChallengeFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_CHALLENGE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            Path->SendResponse = TRUE;
            CxPlatCopyMemory(Path->Response, Frame.Data, sizeof(Frame.Data));
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_RESPONSE);

            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_PATH_RESPONSE: {
            QUIC_PATH_RESPONSE_EX Frame;
            if (!QuicPathChallengeFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_RESPONSE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
            for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
                QUIC_PATH* TempPath = &Connection->Paths[i];
                if (!TempPath->IsPeerValidated &&
                    !memcmp(Frame.Data, TempPath->Challenge, sizeof(Frame.Data))) {
                    QuicPerfCounterIncrement(
                        Connection->Partition, QUIC_PERF_COUNTER_PATH_VALIDATED);
                    QuicPathSetValid(Connection, TempPath, QUIC_PATH_VALID_PATH_RESPONSE);
                    break;
                }
            }

            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_1: {
            QUIC_CONNECTION_CLOSE_EX Frame;
            if (!QuicConnCloseFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CONNECTION_CLOSE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            uint32_t Flags = QUIC_CLOSE_REMOTE | QUIC_CLOSE_SEND_NOTIFICATION;
            if (Frame.ApplicationClosed) {
                Flags |= QUIC_CLOSE_APPLICATION;
            }

            if (!Frame.ApplicationClosed && Frame.ErrorCode == QUIC_ERROR_APPLICATION_ERROR) {
                //
                // The APPLICATION_ERROR transport error should be sent only
                // when closing the connection before the handshake is
                // confirmed. In such case, we can also expect peer to send the
                // application CONNECTION_CLOSE frame in a 1-RTT packet
                // (presumably also in the same UDP datagram).
                //
                // We want to prioritize reporting the application-layer error
                // code to the application, so we postpone the call to
                // QuicConnTryClose and check again after processing incoming
                // datagrams in case it does not arrive.
                //
                QuicTraceEvent(
                    ConnDelayCloseApplicationError,
                    "[conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.",
                    Connection);
                Connection->State.DelayedApplicationError = TRUE;
            } else {
                QuicConnTryClose(
                    Connection,
                    Flags,
                    Frame.ErrorCode,
                    Frame.ReasonPhrase,
                    (uint16_t)Frame.ReasonPhraseLength);
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;

            if (Connection->State.HandleClosed) {
                //
                // If we are now closed, we should exit immediately. No need to
                // parse anything else.
                //
                goto Done;
            }
            break;
        }

        case QUIC_FRAME_HANDSHAKE_DONE: {
            if (QuicConnIsServer(Connection)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Client sent HANDSHAKE_DONE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            if (!Connection->State.HandshakeConfirmed) {
                QuicTraceLogConnInfo(
                    HandshakeConfirmedFrame,
                    Connection,
                    "Handshake confirmed (frame)");
                QuicCryptoHandshakeConfirmed(&Connection->Crypto, TRUE);
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1: {
            if (!Connection->Settings.DatagramReceiveEnabled) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received DATAGRAM frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            if (!QuicDatagramProcessFrame(
                    &Connection->Datagram,
                    Packet,
                    FrameType,
                    PayloadLength,
                    Payload,
                    &Offset)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding DATAGRAM frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }
            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_ACK_FREQUENCY: { // Always accept the frame, because we always enable support.
            QUIC_ACK_FREQUENCY_EX Frame;
            if (!QuicAckFrequencyFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding ACK_FREQUENCY frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Frame.RequestedMaxAckDelay < MS_TO_US(MsQuicLib.TimerResolutionMs)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "RequestedMaxAckDelay is less than TimerResolution");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            AckEliciting = TRUE;
            if (Frame.SequenceNumber < Connection->NextRecvAckFreqSeqNum) {
                //
                // This sequence number (or a higher one) has already been
                // received. Ignore this one.
                //
                break;
            }

            Connection->NextRecvAckFreqSeqNum = Frame.SequenceNumber + 1;
            if (Frame.RequestedMaxAckDelay == 0) {
                Connection->Settings.MaxAckDelayMs = 0;
            } else if (Frame.RequestedMaxAckDelay < 1000) {
                Connection->Settings.MaxAckDelayMs = 1;
            } else {
                CXPLAT_DBG_ASSERT(US_TO_MS(Frame.RequestedMaxAckDelay) <= UINT32_MAX);
                Connection->Settings.MaxAckDelayMs = (uint32_t)US_TO_MS(Frame.RequestedMaxAckDelay);
            }
            if (Frame.AckElicitingThreshold < UINT8_MAX) {
                Connection->PacketTolerance = (uint8_t)Frame.AckElicitingThreshold;
            } else {
                Connection->PacketTolerance = UINT8_MAX; // Cap to 0xFF for space savings.
            }
            if (Frame.ReorderingThreshold < UINT8_MAX) {
                Connection->ReorderingThreshold = (uint8_t)Frame.ReorderingThreshold;
            } else {
                Connection->ReorderingThreshold = UINT8_MAX; // Cap to 0xFF for space savings.
            }
            QuicTraceLogConnInfo(
                UpdatePacketTolerance,
                Connection,
                "Updating packet tolerance to %hhu",
                Connection->PacketTolerance);
            break;
        }

        case QUIC_FRAME_IMMEDIATE_ACK: // Always accept the frame, because we always enable support.
            AckImmediately = TRUE;
            break;

        case QUIC_FRAME_TIMESTAMP: { // Always accept the frame, because we always enable support.
            if (!Connection->State.TimestampRecvNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received TIMESTAMP frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;

            }
            QUIC_TIMESTAMP_EX Frame;
            if (!QuicTimestampFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding TIMESTAMP frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            Packet->HasNonProbingFrame = TRUE;
            Packet->SendTimestamp = Frame.Timestamp;
            break;
        }

        default:
            //
            // No default case necessary, as we have already validated the frame
            // type initially, but included for clang the compiler.
            //
            break;
        }
    }

Done:

    if (UpdatedFlowControl) {
        QuicConnLogOutFlowStats(Connection);
    }

    if (Connection->State.ShutdownComplete || Connection->State.HandleClosed) {
        QuicTraceLogVerbose(
            PacketRxNotAcked,
            "[%c][RX][%llu] not acked (connection is closed)",
            PtkConnPre(Connection),
            Packet->PacketNumber);

    } else if (Connection->Packets[EncryptLevel] != NULL) {

        if (Connection->Packets[EncryptLevel]->NextRecvPacketNumber <= Packet->PacketNumber) {
            Connection->Packets[EncryptLevel]->NextRecvPacketNumber = Packet->PacketNumber + 1;
            Packet->NewLargestPacketNumber = TRUE;
        }

        QUIC_ACK_TYPE AckType;
        if (AckImmediately) {
            AckType = QUIC_ACK_TYPE_ACK_IMMEDIATE;
        } else if (AckEliciting) {
            AckType = QUIC_ACK_TYPE_ACK_ELICITING;
        } else {
            AckType = QUIC_ACK_TYPE_NON_ACK_ELICITING;
        }

        QuicAckTrackerAckPacket(
            &Connection->Packets[EncryptLevel]->AckTracker,
            Packet->PacketNumber,
            RecvTime,
            ECN,
            AckType);
    }

    Packet->CompletelyValid = TRUE;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvPostProcessing(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH** Path,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    BOOLEAN PeerUpdatedCid = FALSE;
    if (Packet->DestCidLen != 0) {
        QUIC_CID_HASH_ENTRY* SourceCid =
            QuicConnGetSourceCidFromBuf(
                Connection,
                Packet->DestCidLen,
                Packet->DestCid);
        if (SourceCid != NULL && !SourceCid->CID.UsedByPeer) {
            QuicTraceLogConnInfo(
                FirstCidUsage,
                Connection,
                "First usage of SrcCid: %s",
                QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer);
            SourceCid->CID.UsedByPeer = TRUE;
            if (!SourceCid->CID.IsInitial) {
                PeerUpdatedCid = TRUE;
            }
        }
    }

    if (!(*Path)->GotValidPacket) {
        (*Path)->GotValidPacket = TRUE;

        if (!(*Path)->IsActive) {

            //
            // This is the first valid packet received on this non-active path.
            // Set the state accordingly and queue up a path challenge to be
            // sent back out.
            //

            if ((*Path)->DestCid == NULL ||
                (PeerUpdatedCid && (*Path)->DestCid->CID.Length != 0)) {
                //
                // TODO - What if the peer (client) only sends a single CID and
                // rebinding happens? Should we support using the same CID over?
                //
                QUIC_CID_LIST_ENTRY* NewDestCid = QuicConnGetUnusedDestCid(Connection);
                if (NewDestCid == NULL) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "No unused CID for new path");
                    (*Path)->GotValidPacket = FALSE; // Don't have a new CID to use!!!
                    (*Path)->DestCid = NULL;
                    return;
                }
                CXPLAT_DBG_ASSERT(NewDestCid != (*Path)->DestCid);
                (*Path)->DestCid = NewDestCid;
                QUIC_CID_SET_PATH(Connection, (*Path)->DestCid, (*Path));
                (*Path)->DestCid->CID.UsedLocally = TRUE;
            }

            CXPLAT_DBG_ASSERT((*Path)->DestCid != NULL);
            QuicPathValidate((*Path));
            (*Path)->SendChallenge = TRUE;
            (*Path)->PathValidationStartTime = CxPlatTimeUs64();

            //
            // NB: The path challenge payload is initialized here and reused
            // for any retransmits, but the spec requires a new payload in each
            // path challenge.
            //
            CxPlatRandom(sizeof((*Path)->Challenge), (*Path)->Challenge);

            //
            // We need to also send a challenge on the active path to make sure
            // it is still good.
            //
            CXPLAT_DBG_ASSERT(Connection->Paths[0].IsActive);
            if (Connection->Paths[0].IsPeerValidated) { // Not already doing peer validation.
                Connection->Paths[0].IsPeerValidated = FALSE;
                Connection->Paths[0].SendChallenge = TRUE;
                Connection->Paths[0].PathValidationStartTime = CxPlatTimeUs64();
                CxPlatRandom(sizeof(Connection->Paths[0].Challenge), Connection->Paths[0].Challenge);
            }

            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
        }

    } else if (PeerUpdatedCid) {
        //
        // If we didn't initiate the CID change locally, we need to
        // respond to this change with a change of our own.
        //
        if (!(*Path)->InitiatedCidUpdate) {
            QuicConnRetireCurrentDestCid(Connection, *Path);
        } else {
            (*Path)->InitiatedCidUpdate = FALSE;
        }
    }

    if (Packet->HasNonProbingFrame &&
        Packet->NewLargestPacketNumber &&
        !(*Path)->IsActive) {
        //
        // The peer has sent a non-probing frame on a path other than the active
        // one. This signals their intent to switch active paths.
        //
        QuicPathSetActive(Connection, *Path);
        *Path = &Connection->Paths[0];

        QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.RemoteAddress), &Connection->Paths[0].Route.RemoteAddress)); // TODO - Addr removed event?

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
        Event.PEER_ADDRESS_CHANGED.Address = &(*Path)->Route.RemoteAddress;
        QuicTraceLogConnVerbose(
            IndicatePeerAddrChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
        (void)QuicConnIndicateEvent(Connection, &Event);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvDatagramBatch(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint8_t BatchCount,
    _In_reads_(BatchCount) QUIC_RX_PACKET** Packets,
    _In_reads_(BatchCount * CXPLAT_HP_SAMPLE_LENGTH)
        const uint8_t* Cipher,
    _Inout_ QUIC_RECEIVE_PROCESSING_STATE* RecvState
    )
{
    uint8_t HpMask[CXPLAT_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];

    CXPLAT_DBG_ASSERT(BatchCount > 0 && BatchCount <= QUIC_MAX_CRYPTO_BATCH_COUNT);
    QUIC_RX_PACKET* Packet = Packets[0];

    QuicTraceLogConnVerbose(
        UdpRecvBatch,
        Connection,
        "Batch Recv %u UDP datagrams",
        BatchCount);

    if (Connection->Crypto.TlsState.ReadKeys[Packet->KeyType] == NULL) {
        QuicPacketLogDrop(Connection, Packet, "Key no longer accepted (batch)");
        return;
    }

    if (Packet->Encrypted &&
        Connection->State.HeaderProtectionEnabled) {
        if (QUIC_FAILED(
            CxPlatHpComputeMask(
                Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->HeaderKey,
                BatchCount,
                Cipher,
                HpMask))) {
            QuicPacketLogDrop(Connection, Packet, "Failed to compute HP mask");
            return;
        }
    } else {
        CxPlatZeroMemory(HpMask, BatchCount * CXPLAT_HP_SAMPLE_LENGTH);
    }

    for (uint8_t i = 0; i < BatchCount; ++i) {
        CXPLAT_DBG_ASSERT(Packets[i]->Allocated);
        CXPLAT_ECN_TYPE ECN = CXPLAT_ECN_FROM_TOS(Packets[i]->TypeOfService);
        Packet = Packets[i];
        CXPLAT_DBG_ASSERT(Packet->PacketId != 0);
        if (!QuicConnRecvPrepareDecrypt(
                Connection, Packet, HpMask + i * CXPLAT_HP_SAMPLE_LENGTH) ||
            !QuicConnRecvDecryptAndAuthenticate(Connection, Path, Packet)) {
            if (Connection->State.CompatibleVerNegotiationAttempted &&
                !Connection->State.CompatibleVerNegotiationCompleted) {
                //
                // The packet which initiated compatible version negotation failed
                // decryption, so undo the version change.
                //
                Connection->Stats.QuicVersion = Connection->OriginalQuicVersion;
                Connection->State.CompatibleVerNegotiationAttempted = FALSE;
            }
        } else if (QuicConnRecvFrames(Connection, Path, Packet, ECN)) {

            QuicConnRecvPostProcessing(Connection, &Path, Packet);
            RecvState->ResetIdleTimeout |= Packet->CompletelyValid;

            if (Connection->Registration != NULL && !Connection->Registration->NoPartitioning &&
                Path->IsActive && !Path->PartitionUpdated && Packet->CompletelyValid &&
                (Packets[i]->PartitionIndex % MsQuicLib.PartitionCount) != RecvState->PartitionIndex) {
                RecvState->PartitionIndex = Packets[i]->PartitionIndex % MsQuicLib.PartitionCount;
                RecvState->UpdatePartitionId = TRUE;
                Path->PartitionUpdated = TRUE;
            }

            if (Packet->IsShortHeader && Packet->NewLargestPacketNumber) {

                if (QuicConnIsServer(Connection)) {
                    Path->SpinBit = Packet->SH->SpinBit;
                } else {
                    Path->SpinBit = !Packet->SH->SpinBit;
                }
            }
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvDatagrams(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packets,
    _In_ uint32_t PacketChainCount,
    _In_ uint32_t PacketChainByteCount,
    _In_ BOOLEAN IsDeferred
    )
{
    QUIC_RX_PACKET* ReleaseChain = NULL;
    QUIC_RX_PACKET** ReleaseChainTail = &ReleaseChain;
    uint32_t ReleaseChainCount = 0;
    QUIC_RECEIVE_PROCESSING_STATE RecvState = { FALSE, FALSE, 0 };
    RecvState.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);

    UNREFERENCED_PARAMETER(PacketChainCount);
    UNREFERENCED_PARAMETER(PacketChainByteCount);

    CXPLAT_PASSIVE_CODE();

    if (IsDeferred) {
        QuicTraceLogConnVerbose(
            UdpRecvDeferred,
            Connection,
            "Recv %u deferred UDP datagrams",
            PacketChainCount);
    } else {
        QuicTraceEvent(
            ConnRecvUdpDatagrams,
            "[conn][%p] Recv %u UDP datagrams, %u bytes",
            Connection,
            PacketChainCount,
            PacketChainByteCount);
    }

    //
    // Iterate through each QUIC packet in the chain of UDP datagrams until an
    // error is encountered or we run out of buffer.
    //

    uint8_t BatchCount = 0;
    QUIC_RX_PACKET* Batch[QUIC_MAX_CRYPTO_BATCH_COUNT];
    uint8_t Cipher[CXPLAT_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];
    QUIC_PATH* CurrentPath = NULL;
    QUIC_PACKET_KEY_TYPE PrevPackKeyType = QUIC_PACKET_KEY_COUNT;

    QUIC_RX_PACKET* Packet;
    while ((Packet = Packets) != NULL) {
        CXPLAT_DBG_ASSERT(Packet->Allocated);
        CXPLAT_DBG_ASSERT(Packet->QueuedOnConnection);
        Packets = (QUIC_RX_PACKET*)Packet->Next;
        Packet->Next = NULL;

        CXPLAT_DBG_ASSERT(Packet != NULL);
        CXPLAT_DBG_ASSERT(Packet->PacketId != 0);

        CXPLAT_DBG_ASSERT(Packet->ReleaseDeferred == IsDeferred);
        Packet->ReleaseDeferred = FALSE;

        QUIC_PATH* DatagramPath = QuicConnGetPathForPacket(Connection, Packet);
        if (DatagramPath == NULL) {
            QuicPacketLogDrop(Connection, Packet, "Max paths already tracked");
            goto Drop;
        }

        CxPlatUpdateRoute(&DatagramPath->Route, Packet->Route);

        if (DatagramPath != CurrentPath) {
            if (BatchCount != 0) {
                //
                // This datagram is from a different path than the current
                // batch. Flush the current batch before continuing.
                //
                CXPLAT_DBG_ASSERT(CurrentPath != NULL);
                QuicConnRecvDatagramBatch(
                    Connection,
                    CurrentPath,
                    BatchCount,
                    Batch,
                    Cipher,
                    &RecvState);
                BatchCount = 0;
            }
            CurrentPath = DatagramPath;
        }

        if (!IsDeferred) {
            Connection->Stats.Recv.TotalBytes += Packet->BufferLength;
            if (Connection->Stats.Handshake.HandshakeHopLimitTTL == 0) {
                Connection->Stats.Handshake.HandshakeHopLimitTTL = Packet->HopLimitTTL;
            }
            QuicConnLogInFlowStats(Connection);

            if (!CurrentPath->IsPeerValidated) {
                QuicPathIncrementAllowance(
                    Connection,
                    CurrentPath,
                    QUIC_AMPLIFICATION_RATIO * Packet->BufferLength);
            }
        }

        do {
            CXPLAT_DBG_ASSERT(BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT);
            CXPLAT_DBG_ASSERT(Packet->Allocated);
            Connection->Stats.Recv.TotalPackets++;

            if (!Packet->ValidatedHeaderInv) {
                //
                // Only calculate the buffer length from the available UDP
                // payload length if the long header hasn't already been
                // validated (which indicates the actual length);
                //
                Packet->AvailBufferLength =
                    Packet->BufferLength - (uint16_t)(Packet->AvailBuffer - Packet->Buffer);
            }

            if (!QuicConnRecvHeader(
                    Connection,
                    Packet,
                    Cipher + BatchCount * CXPLAT_HP_SAMPLE_LENGTH)) {
                if (Packet->ReleaseDeferred) {
                    Connection->Stats.Recv.TotalPackets--; // Don't count the packet right now.
                } else if (!Packet->IsShortHeader && Packet->ValidatedHeaderVer) {
                    goto NextPacket;
                }
                break;
            }

            if ((BatchCount != 0) &&
                (!Packet->IsShortHeader ||
                (PrevPackKeyType != QUIC_PACKET_KEY_COUNT && PrevPackKeyType != Packet->KeyType))) {
                //
                // We already had some batched short header packets and then
                // encountered a long header packet OR the current packet
                // has different key type. Finish off the batch first and
                // then continue with the current packet.
                //
                QuicConnRecvDatagramBatch(
                    Connection,
                    CurrentPath,
                    BatchCount,
                    Batch,
                    Cipher,
                    &RecvState);
                CxPlatMoveMemory(
                    Cipher + BatchCount * CXPLAT_HP_SAMPLE_LENGTH,
                    Cipher,
                    CXPLAT_HP_SAMPLE_LENGTH);
                BatchCount = 0;
            }

            Batch[BatchCount++] = Packet;
            PrevPackKeyType = Packet->KeyType;
            if (Packet->IsShortHeader && BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT) {
                break;
            }

            QuicConnRecvDatagramBatch(
                Connection,
                CurrentPath,
                BatchCount,
                Batch,
                Cipher,
                &RecvState);
            BatchCount = 0;

            if (Packet->IsShortHeader) {
                break; // Short header packets aren't followed by additional packets.
            }

            //
            // Move to the next QUIC packet (if available) and reset the packet
            // state.
            //

        NextPacket:

            Packet->AvailBuffer += Packet->AvailBufferLength;

            Packet->ValidatedHeaderInv = FALSE;
            Packet->ValidatedHeaderVer = FALSE;
            Packet->ValidToken = FALSE;
            Packet->PacketNumberSet = FALSE;
            Packet->EncryptedWith0Rtt = FALSE;
            Packet->ReleaseDeferred = FALSE;
            Packet->CompletelyValid = FALSE;
            Packet->NewLargestPacketNumber = FALSE;
            Packet->HasNonProbingFrame = FALSE;

        } while (Packet->AvailBuffer - Packet->Buffer < Packet->BufferLength);

    Drop:

        if (!Packet->ReleaseDeferred) {
            *ReleaseChainTail = Packet;
            ReleaseChainTail = (QUIC_RX_PACKET**)&Packet->Next;
            Packet->QueuedOnConnection = FALSE;
            if (++ReleaseChainCount == QUIC_MAX_RECEIVE_BATCH_COUNT) {
                if (BatchCount != 0) {
                    QuicConnRecvDatagramBatch(
                        Connection,
                        CurrentPath,
                        BatchCount,
                        Batch,
                        Cipher,
                        &RecvState);
                    BatchCount = 0;
                }
                CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)ReleaseChain);
                ReleaseChain = NULL;
                ReleaseChainTail = &ReleaseChain;
                ReleaseChainCount = 0;
            }
        }
    }

    if (BatchCount != 0) {
        QuicConnRecvDatagramBatch(
            Connection,
            CurrentPath,
            BatchCount,
            Batch,
            Cipher,
            &RecvState);
        BatchCount = 0; // cppcheck-suppress unreadVariable; NOLINT
    }

    if (Connection->State.DelayedApplicationError && Connection->CloseStatus == 0) {
        //
        // We received transport APPLICATION_ERROR, but didn't receive the expected
        // CONNECTION_ERROR frame, so close the connection with originally postponed
        // APPLICATION_ERROR.
        //
        QuicConnTryClose(
            Connection,
            QUIC_CLOSE_REMOTE | QUIC_CLOSE_SEND_NOTIFICATION,
            QUIC_ERROR_APPLICATION_ERROR,
            NULL,
            (uint16_t)0);
    }

    if (RecvState.ResetIdleTimeout) {
        QuicConnResetIdleTimeout(Connection);
    }

    if (ReleaseChain != NULL) {
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)ReleaseChain);
    }

    if (QuicConnIsServer(Connection) &&
        Connection->Stats.Recv.ValidPackets == 0 &&
        !Connection->State.ClosedLocally) {
        //
        // The packet(s) that created this connection weren't valid. We should
        // immediately throw away the connection.
        //
        QuicTraceLogConnWarning(
            InvalidInitialPackets,
            Connection,
            "Aborting connection with invalid initial packets");
        QuicConnSilentlyAbort(Connection);
    }

    //
    // Any new paths created here were created before packet validation. Now
    // remove any non-active paths that didn't get any valid packets.
    // NB: Traversing the array backwards is simpler and more efficient here due
    // to the array shifting that happens in QuicPathRemove.
    //
    for (uint8_t i = Connection->PathsCount - 1; i > 0; --i) {
        if (!Connection->Paths[i].GotValidPacket) {
            QuicTraceLogConnInfo(
                PathDiscarded,
                Connection,
                "Removing invalid path[%hhu]",
                Connection->Paths[i].ID);
            QuicPathRemove(Connection, i);
        }
    }

    if (!Connection->State.UpdateWorker && Connection->State.Connected &&
        !Connection->State.ShutdownComplete && RecvState.UpdatePartitionId) {
        CXPLAT_DBG_ASSERT(Connection->Registration);
        CXPLAT_DBG_ASSERT(!Connection->Registration->NoPartitioning);
        CXPLAT_DBG_ASSERT(RecvState.PartitionIndex != QuicPartitionIdGetIndex(Connection->PartitionID));
        Connection->PartitionID = QuicPartitionIdCreate(RecvState.PartitionIndex);
        QuicConnGenerateNewSourceCids(Connection, TRUE);
        Connection->State.UpdateWorker = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnFlushRecv(
    _In_ QUIC_CONNECTION* Connection
    )
{
    BOOLEAN FlushedAll;
    uint32_t ReceiveQueueCount, ReceiveQueueByteCount;
    QUIC_RX_PACKET* ReceiveQueue;

    CxPlatDispatchLockAcquire(&Connection->ReceiveQueueLock);
    ReceiveQueue = Connection->ReceiveQueue;
    if (Connection->ReceiveQueueCount > QUIC_MAX_RECEIVE_FLUSH_COUNT) {
        FlushedAll = FALSE;
        Connection->ReceiveQueueCount -= QUIC_MAX_RECEIVE_FLUSH_COUNT;
        QUIC_RX_PACKET* Tail = Connection->ReceiveQueue;
        ReceiveQueueCount = 0;
        ReceiveQueueByteCount = 0;
        while (++ReceiveQueueCount < QUIC_MAX_RECEIVE_FLUSH_COUNT) {
            ReceiveQueueByteCount += Tail->BufferLength;
            Tail = Connection->ReceiveQueue;
        }
        Connection->ReceiveQueueByteCount -= ReceiveQueueByteCount;
        Connection->ReceiveQueue = (QUIC_RX_PACKET*)Tail->Next;
        Tail->Next = NULL;
    } else {
        FlushedAll = TRUE;
        ReceiveQueueCount = Connection->ReceiveQueueCount;
        ReceiveQueueByteCount = Connection->ReceiveQueueByteCount;
        Connection->ReceiveQueueCount = 0;
        Connection->ReceiveQueueByteCount = 0;
        Connection->ReceiveQueue = NULL;
        Connection->ReceiveQueueTail = &Connection->ReceiveQueue;
    }
    CxPlatDispatchLockRelease(&Connection->ReceiveQueueLock);

    QuicConnRecvDatagrams(
        Connection, ReceiveQueue, ReceiveQueueCount, ReceiveQueueByteCount, FALSE);

    return FlushedAll;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnDiscardDeferred0Rtt(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_RX_PACKET* ReleaseChain = NULL;
    QUIC_RX_PACKET** ReleaseChainTail = &ReleaseChain;
    QUIC_PACKET_SPACE* Packets = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    CXPLAT_DBG_ASSERT(Packets != NULL);

    QUIC_RX_PACKET* DeferredPackets = Packets->DeferredPackets;
    QUIC_RX_PACKET** DeferredPacketsTail = &Packets->DeferredPackets;
    Packets->DeferredPackets = NULL;

    while (DeferredPackets != NULL) {
        QUIC_RX_PACKET* Packet = DeferredPackets;
        DeferredPackets = (QUIC_RX_PACKET*)DeferredPackets->Next;

        if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT) {
            QuicPacketLogDrop(Connection, Packet, "0-RTT rejected");
            Packets->DeferredPacketsCount--;
            *ReleaseChainTail = Packet;
            ReleaseChainTail = (QUIC_RX_PACKET**)&Packet->Next;
        } else {
            *DeferredPacketsTail = Packet;
            DeferredPacketsTail = (QUIC_RX_PACKET**)&Packet->Next;
        }
    }

    if (ReleaseChain != NULL) {
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)ReleaseChain);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnFlushDeferred(
    _In_ QUIC_CONNECTION* Connection
    )
{
    for (uint8_t i = 1; i <= (uint8_t)Connection->Crypto.TlsState.ReadKey; ++i) {

        if (Connection->Crypto.TlsState.ReadKeys[i] == NULL) {
            continue;
        }

        QUIC_ENCRYPT_LEVEL EncryptLevel =
            QuicKeyTypeToEncryptLevel((QUIC_PACKET_KEY_TYPE)i);
        QUIC_PACKET_SPACE* Packets = Connection->Packets[EncryptLevel];

        if (Packets->DeferredPackets != NULL) {
            QUIC_RX_PACKET* DeferredPackets = Packets->DeferredPackets;
            uint8_t DeferredPacketsCount = Packets->DeferredPacketsCount;

            Packets->DeferredPacketsCount = 0;
            Packets->DeferredPackets = NULL;

            QuicConnRecvDatagrams(
                Connection,
                DeferredPackets,
                DeferredPacketsCount,
                0, // Unused for deferred datagrams
                TRUE);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessUdpUnreachable(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (Connection->Crypto.TlsState.ReadKey > QUIC_PACKET_KEY_INITIAL) {
        //
        // Only accept unreachable events at the beginning of the handshake.
        // Otherwise, it opens up an attack surface.
        //
        QuicTraceLogConnWarning(
            UnreachableIgnore,
            Connection,
            "Ignoring received unreachable event");

    } else if (QuicAddrCompare(&Connection->Paths[0].Route.RemoteAddress, RemoteAddress)) {
        QuicTraceLogConnInfo(
            Unreachable,
            Connection,
            "Received unreachable event");
        //
        // Close the connection since the peer is unreachable.
        //
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_UNREACHABLE,
            NULL);

    } else {
        QuicTraceLogConnWarning(
            UnreachableInvalid,
            Connection,
            "Received invalid unreachable event");
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessRouteCompletion(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    )
{
    uint8_t PathIndex;
    QUIC_PATH* Path = QuicConnGetPathByID(Connection, PathId, &PathIndex);
    if (Path != NULL) {
        if (Succeeded) {
            CxPlatResolveRouteComplete(Connection, &Path->Route, PhysicalAddress, PathId);
            if (!QuicSendFlush(&Connection->Send)) {
                QuicSendQueueFlush(&Connection->Send, REASON_ROUTE_COMPLETION);
            }
        } else {
            //
            // Kill the path that failed route resolution and make the next path active if possible.
            //
            if (Path->IsActive && Connection->PathsCount > 1) {
                QuicTraceLogConnInfo(
                    FailedRouteResolution,
                    Connection,
                    "Route resolution failed on Path[%hhu]. Switching paths...",
                    PathId);
                QuicPathSetActive(Connection, &Connection->Paths[1]);
                QuicPathRemove(Connection, 1);
                if (!QuicSendFlush(&Connection->Send)) {
                    QuicSendQueueFlush(&Connection->Send, REASON_ROUTE_COMPLETION);
                }
            } else {
                QuicPathRemove(Connection, PathIndex);
            }
        }
    }

    if (Connection->PathsCount == 0) {
        //
        // Close the connection since the peer is unreachable.
        //
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_UNREACHABLE,
            NULL);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnResetIdleTimeout(
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint64_t IdleTimeoutMs;
    QUIC_PATH* Path = &Connection->Paths[0];
    if (Connection->State.Connected) {
        //
        // Use the (non-zero) min value between local and peer's configuration.
        //
        IdleTimeoutMs = Connection->PeerTransportParams.IdleTimeout;
        if (IdleTimeoutMs == 0 ||
            (Connection->Settings.IdleTimeoutMs != 0 &&
             Connection->Settings.IdleTimeoutMs < IdleTimeoutMs)) {
            IdleTimeoutMs = Connection->Settings.IdleTimeoutMs;
        }
    } else {
        IdleTimeoutMs = Connection->Settings.HandshakeIdleTimeoutMs;
    }

    if (IdleTimeoutMs != 0) {
        if (Connection->State.Connected) {
            //
            // Idle timeout must be no less than the PTOs for closing.
            //
            uint64_t MinIdleTimeoutMs =
                US_TO_MS(QuicLossDetectionComputeProbeTimeout(
                    &Connection->LossDetection,
                    Path,
                    QUIC_CLOSE_PTO_COUNT));
            if (IdleTimeoutMs < MinIdleTimeoutMs) {
                IdleTimeoutMs = MinIdleTimeoutMs;
            }
        }

        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_IDLE,
            MS_TO_US(IdleTimeoutMs));

    } else {
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_IDLE);
    }

    if (Connection->Settings.KeepAliveIntervalMs != 0) {
        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_KEEP_ALIVE,
            MS_TO_US(Connection->Settings.KeepAliveIntervalMs));
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessIdleTimerOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Close the connection, as the agreed-upon idle time period has elapsed.
    //
    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)QUIC_STATUS_CONNECTION_IDLE,
        NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessKeepAliveOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Send a PING frame to keep the connection alive.
    //
    Connection->Send.TailLossProbeNeeded = TRUE;
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);

    //
    // Restart the keep alive timer.
    //
    QuicConnTimerSet(
        Connection,
        QUIC_CONN_TIMER_KEEP_ALIVE,
        MS_TO_US(Connection->Settings.KeepAliveIntervalMs));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdatePeerPacketTolerance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t NewPacketTolerance
    )
{
    if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MIN_ACK_DELAY &&
        Connection->PeerPacketTolerance != NewPacketTolerance) {
        QuicTraceLogConnInfo(
            UpdatePeerPacketTolerance,
            Connection,
            "Updating peer packet tolerance to %hhu",
            NewPacketTolerance);
        Connection->SendAckFreqSeqNum++;
        Connection->PeerPacketTolerance = NewPacketTolerance;
        QuicSendSetSendFlag(
            &Connection->Send,
            QUIC_CONN_SEND_FLAG_ACK_FREQUENCY);
    }
}

#define QUIC_CONN_BAD_START_STATE(CONN) (CONN->State.Started || CONN->State.ClosedLocally)

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnParamSet(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_SETTINGS_INTERNAL InternalSettings = {0};

    switch (Param) {

    case QUIC_PARAM_CONN_LOCAL_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADDR)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.ClosedLocally || QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (Connection->State.Started &&
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        const QUIC_ADDR* LocalAddress = (const QUIC_ADDR*)Buffer;

        if (!QuicAddrIsValid(LocalAddress)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.LocalAddressSet = TRUE;
        CxPlatCopyMemory(&Connection->Paths[0].Route.LocalAddress, Buffer, sizeof(QUIC_ADDR));
        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));

        if (Connection->State.Started) {

            CXPLAT_DBG_ASSERT(Connection->Paths[0].Binding);
            CXPLAT_DBG_ASSERT(Connection->State.RemoteAddressSet);
            CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);

            QUIC_BINDING* OldBinding = Connection->Paths[0].Binding;

            CXPLAT_UDP_CONFIG UdpConfig = {0};
            UdpConfig.LocalAddress = LocalAddress;
            UdpConfig.RemoteAddress = &Connection->Paths[0].Route.RemoteAddress;
            UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
            UdpConfig.InterfaceIndex = 0;
#ifdef QUIC_COMPARTMENT_ID
            UdpConfig.CompartmentId = Connection->Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
            UdpConfig.OwningProcess = Connection->Configuration->OwningProcess;
#endif
            if (Connection->State.ShareBinding) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
            }
            if (Connection->Settings.XdpEnabled) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
            }
            if (Connection->Settings.QTIPEnabled) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
            }
            if (Connection->Settings.RioEnabled) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_RIO;
            }
            Status =
                QuicLibraryGetBinding(
                    &UdpConfig,
                    &Connection->Paths[0].Binding);
            if (QUIC_FAILED(Status)) {
                Connection->Paths[0].Binding = OldBinding;
                break;
            }
            Connection->Paths[0].Route.State = RouteUnresolved;
            Connection->Paths[0].Route.Queue = NULL;

            //
            // TODO - Need to free any queued recv packets from old binding.
            //

            QuicBindingMoveSourceConnectionIDs(
                OldBinding, Connection->Paths[0].Binding, Connection);
            QuicLibraryReleaseBinding(OldBinding);

            QuicTraceEvent(
                ConnLocalAddrRemoved,
                "[conn][%p] Removed Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));

            QuicBindingGetLocalAddress(
                Connection->Paths[0].Binding,
                &Connection->Paths[0].Route.LocalAddress);

            QuicTraceEvent(
                ConnLocalAddrAdded,
                "[conn][%p] New Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));

            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);
        }

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_REMOTE_ADDRESS:

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (BufferLength != sizeof(QUIC_ADDR) ||
            QuicAddrIsWildCard((QUIC_ADDR*)Buffer) ||
            QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.RemoteAddressSet = TRUE;
        CxPlatCopyMemory(&Connection->Paths[0].Route.RemoteAddress, Buffer, sizeof(QUIC_ADDR));
        //
        // Don't log new Remote address added here because it is logged when
        // the connection is started.
        //

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status =
            QuicSettingsSettingsToInternal(
                BufferLength,
                (QUIC_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicConnApplyNewSettings(
                Connection,
                TRUE,
                &InternalSettings)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        break;

    case QUIC_PARAM_CONN_VERSION_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status =
            QuicSettingsVersionSettingsToInternal(
                BufferLength,
                (QUIC_VERSION_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicConnApplyNewSettings(
                Connection,
                TRUE,
                &InternalSettings)) {
            QuicSettingsCleanup(&InternalSettings);
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        QuicSettingsCleanup(&InternalSettings);

        break;

    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection) ||
            QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.ShareBinding = *(uint8_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateShareBinding,
            Connection,
            "Updated ShareBinding = %hhu",
            Connection->State.ShareBinding);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:

        if (BufferLength > QUIC_MAX_CONN_CLOSE_REASON_LENGTH) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Require the reason to be null terminated.
        //
        if (Buffer && ((char*)Buffer)[BufferLength - 1] != 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Free any old data.
        //
        if (Connection->CloseReasonPhrase != NULL) {
            CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
        }

        //
        // Allocate new space.
        //
        Connection->CloseReasonPhrase =
            CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_CLOSE_REASON);

        if (Buffer && Connection->CloseReasonPhrase != NULL) {
            CxPlatCopyMemory(
                Connection->CloseReasonPhrase,
                Buffer,
                BufferLength);
            Status = QUIC_STATUS_SUCCESS;
        } else {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
        }

        break;

    case QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME: {

        if (BufferLength != sizeof(QUIC_STREAM_SCHEDULING_SCHEME)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_STREAM_SCHEDULING_SCHEME Scheme =
            *(QUIC_STREAM_SCHEDULING_SCHEME*)Buffer;

        if (Scheme >= QUIC_STREAM_SCHEDULING_SCHEME_COUNT) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.UseRoundRobinStreamScheduling =
            Scheme == QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN;

        QuicTraceLogConnInfo(
            UpdateStreamSchedulingScheme,
            Connection,
            "Updated Stream Scheduling Scheme = %u",
            (uint32_t)Scheme);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:

        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->Settings.DatagramReceiveEnabled = *(BOOLEAN*)Buffer;
        Connection->Settings.IsSet.DatagramReceiveEnabled = TRUE;
        Status = QUIC_STATUS_SUCCESS;

        QuicTraceLogConnVerbose(
            DatagramReceiveEnableUpdated,
            Connection,
            "Updated datagram receive enabled to %hhu",
            Connection->Settings.DatagramReceiveEnabled);

        break;

    case QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION:

        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (Connection->State.PeerTransportParameterValid &&
            (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION))) {
            //
            // The peer did't negotiate the feature.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.Disable1RttEncrytion = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;

        QuicTraceLogConnVerbose(
            Disable1RttEncrytionUpdated,
            Connection,
            "Updated disable 1-RTT encrytption to %hhu",
            Connection->State.Disable1RttEncrytion);

        break;

    case QUIC_PARAM_CONN_RESUMPTION_TICKET: {
        if (BufferLength == 0 || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Must be set before the client connection is started.
        //

        if (QuicConnIsServer(Connection) ||
            QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Status =
            QuicCryptoDecodeClientTicket(
                Connection,
                (uint16_t)BufferLength,
                Buffer,
                &Connection->PeerTransportParams,
                &Connection->Crypto.ResumptionTicket,
                &Connection->Crypto.ResumptionTicketLength,
                &Connection->Stats.QuicVersion);
        if (QUIC_FAILED(Status)) {
            break;
        }

        QuicConnOnQuicVersionSet(Connection);
        Status = QuicConnProcessPeerTransportParameters(Connection, TRUE);
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));

        break;
    }

    case QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID:
        if (BufferLength != sizeof(BOOLEAN) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicCryptoCustomCertValidationComplete(
            &Connection->Crypto,
            *(BOOLEAN*)Buffer,
            QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE);
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_LOCAL_INTERFACE:

        if (BufferLength != sizeof(uint32_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QuicConnIsServer(Connection) ||
            QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.LocalInterfaceSet = TRUE;
        Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id = *(uint32_t*)Buffer;

        QuicTraceLogConnInfo(
            LocalInterfaceSet,
            Connection,
            "Local interface set to %u",
            Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_TLS_SECRETS:

        if (BufferLength != sizeof(QUIC_TLS_SECRETS) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->TlsSecrets = (QUIC_TLS_SECRETS*)Buffer;
        CxPlatZeroMemory(Connection->TlsSecrets, sizeof(*Connection->TlsSecrets));
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_CIBIR_ID: {

        if (QuicConnIsServer(Connection) ||
            QUIC_CONN_BAD_START_STATE(Connection)) {
            return QUIC_STATUS_INVALID_STATE;
        }
        if (!Connection->State.ShareBinding) {
            //
            // We aren't sharing the binding, and therefore we don't use source
            // connection IDs, so CIBIR is not supported.
            //
            return QUIC_STATUS_INVALID_STATE;
        }

        if (BufferLength > QUIC_MAX_CIBIR_LENGTH + 1) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (BufferLength == 0) {
            CxPlatZeroMemory(Connection->CibirId, sizeof(Connection->CibirId));
            return QUIC_STATUS_SUCCESS;
        }
        if (BufferLength < 2) { // Must have at least the offset and 1 byte of payload.
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (((uint8_t*)Buffer)[0] != 0) {
            return QUIC_STATUS_NOT_SUPPORTED; // Not yet supproted.
        }

        Connection->CibirId[0] = (uint8_t)BufferLength - 1;
        memcpy(Connection->CibirId + 1, Buffer, BufferLength);

        QuicTraceLogConnInfo(
            CibirIdSet,
            Connection,
            "CIBIR ID set (len %hhu, offset %hhu)",
            Connection->CibirId[0],
            Connection->CibirId[1]);

        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_PARAM_CONN_SEND_DSCP: {
        if (BufferLength != sizeof(uint8_t) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        uint8_t DSCP = *(uint8_t*)Buffer;

        if (DSCP > CXPLAT_MAX_DSCP) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->DSCP = DSCP;

        QuicTraceLogConnInfo(
            ConnDscpSet,
            Connection,
            "Connection DSCP set to %hhu",
            Connection->DSCP);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    //
    // Private
    //

    case QUIC_PARAM_CONN_FORCE_KEY_UPDATE:

        if (!Connection->State.Connected ||
            Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT] == NULL ||
            Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->AwaitingKeyPhaseConfirmation ||
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QuicTraceLogConnVerbose(
            ForceKeyUpdate,
            Connection,
            "Forcing key update");

        Status = QuicCryptoGenerateNewKeys(Connection);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "Forced key update");
            break;
        }

        QuicCryptoUpdateKeyPhase(Connection, TRUE);
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_FORCE_CID_UPDATE:

        if (!Connection->State.Connected ||
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QuicTraceLogConnVerbose(
            ForceCidUpdate,
            Connection,
            "Forcing destination CID update");

        if (!QuicConnRetireCurrentDestCid(Connection, &Connection->Paths[0])) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->Paths[0].InitiatedCidUpdate = TRUE;
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER:

        if (BufferLength != sizeof(QUIC_PRIVATE_TRANSPORT_PARAMETER)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        CxPlatCopyMemory(
            &Connection->TestTransportParameter, Buffer, BufferLength);
        Connection->State.TestTransportParameterSet = TRUE;

        QuicTraceLogConnVerbose(
            TestTPSet,
            Connection,
            "Setting Test Transport Parameter (type %x, %hu bytes)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_KEEP_ALIVE_PADDING:

        if (BufferLength != sizeof(Connection->KeepAlivePadding)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->KeepAlivePadding = *(uint16_t*)Buffer;
        Status = QUIC_STATUS_SUCCESS;
        break;

#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
    case QUIC_PARAM_CONN_DISABLE_VNE_TP_GENERATION:

        if (BufferLength != sizeof(BOOLEAN) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.DisableVneTp = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

#define STATISTICS_HAS_FIELD(Size, Field) \
    (Size >= QUIC_STRUCT_SIZE_THRU_FIELD(QUIC_STATISTICS_V2, Field))

_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnGetV2Statistics(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsPlat,
    _Inout_ uint32_t* StatsLength,
    _Out_writes_bytes_opt_(*StatsLength)
        QUIC_STATISTICS_V2* Stats
    )
{
    const uint32_t MinimumStatsSize = QUIC_STATISTICS_V2_SIZE_1;

    if (*StatsLength == 0) {
        *StatsLength = sizeof(QUIC_STATISTICS_V2);
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (*StatsLength < MinimumStatsSize) {
        *StatsLength = MinimumStatsSize;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Stats == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const QUIC_PATH* Path = &Connection->Paths[0];

    Stats->CorrelationId = Connection->Stats.CorrelationId;
    Stats->VersionNegotiation = Connection->Stats.VersionNegotiation;
    Stats->StatelessRetry = Connection->Stats.StatelessRetry;
    Stats->ResumptionAttempted = Connection->Stats.ResumptionAttempted;
    Stats->ResumptionSucceeded = Connection->Stats.ResumptionSucceeded;
    Stats->GreaseBitNegotiated = Connection->Stats.GreaseBitNegotiated;
    Stats->EncryptionOffloaded = Connection->Stats.EncryptionOffloaded;
    Stats->EcnCapable = Path->EcnValidationState == ECN_VALIDATION_CAPABLE;
    Stats->Rtt = (uint32_t)Path->SmoothedRtt;
    Stats->MinRtt = (uint32_t)Path->MinRtt;
    Stats->MaxRtt = (uint32_t)Path->MaxRtt;
    Stats->TimingStart = Connection->Stats.Timing.Start;
    Stats->TimingInitialFlightEnd = Connection->Stats.Timing.InitialFlightEnd;
    Stats->TimingHandshakeFlightEnd = Connection->Stats.Timing.HandshakeFlightEnd;
    Stats->HandshakeClientFlight1Bytes = Connection->Stats.Handshake.ClientFlight1Bytes;
    Stats->HandshakeServerFlight1Bytes = Connection->Stats.Handshake.ServerFlight1Bytes;
    Stats->HandshakeClientFlight2Bytes = Connection->Stats.Handshake.ClientFlight2Bytes;
    Stats->SendPathMtu = Path->Mtu;
    Stats->SendTotalPackets = Connection->Stats.Send.TotalPackets;
    Stats->SendRetransmittablePackets = Connection->Stats.Send.RetransmittablePackets;
    Stats->SendSuspectedLostPackets = Connection->Stats.Send.SuspectedLostPackets;
    Stats->SendSpuriousLostPackets = Connection->Stats.Send.SpuriousLostPackets;
    Stats->SendTotalBytes = Connection->Stats.Send.TotalBytes;
    Stats->SendTotalStreamBytes = Connection->Stats.Send.TotalStreamBytes;
    Stats->SendCongestionCount = Connection->Stats.Send.CongestionCount;
    Stats->SendPersistentCongestionCount = Connection->Stats.Send.PersistentCongestionCount;
    Stats->RecvTotalPackets = Connection->Stats.Recv.TotalPackets;
    Stats->RecvReorderedPackets = Connection->Stats.Recv.ReorderedPackets;
    Stats->RecvDroppedPackets = Connection->Stats.Recv.DroppedPackets;
    Stats->RecvDuplicatePackets = Connection->Stats.Recv.DuplicatePackets;
    Stats->RecvTotalBytes = Connection->Stats.Recv.TotalBytes;
    Stats->RecvTotalStreamBytes = Connection->Stats.Recv.TotalStreamBytes;
    Stats->RecvDecryptionFailures = Connection->Stats.Recv.DecryptionFailures;
    Stats->RecvValidAckFrames = Connection->Stats.Recv.ValidAckFrames;
    Stats->KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;

    if (IsPlat) {
        Stats->TimingStart = CxPlatTimeUs64ToPlat(Stats->TimingStart); // cppcheck-suppress selfAssignment
        Stats->TimingInitialFlightEnd = CxPlatTimeUs64ToPlat(Stats->TimingInitialFlightEnd); // cppcheck-suppress selfAssignment
        Stats->TimingHandshakeFlightEnd = CxPlatTimeUs64ToPlat(Stats->TimingHandshakeFlightEnd); // cppcheck-suppress selfAssignment
    }

    //
    // N.B. Anything after this needs to be size checked
    //

    //
    // The below is how to add a new field while checking size.
    //
    // if (STATISTICS_HAS_FIELD(*StatsLength, KeyUpdateCount)) {
    //     Stats->KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;
    // }

    if (STATISTICS_HAS_FIELD(*StatsLength, SendCongestionWindow)) {
        Stats->SendCongestionWindow = QuicCongestionControlGetCongestionWindow(&Connection->CongestionControl);
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, DestCidUpdateCount)) {
        Stats->DestCidUpdateCount = Connection->Stats.Misc.DestCidUpdateCount;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, SendEcnCongestionCount)) {
        Stats->SendEcnCongestionCount = Connection->Stats.Send.EcnCongestionCount;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, HandshakeHopLimitTTL)) {
        Stats->HandshakeHopLimitTTL = Connection->Stats.Handshake.HandshakeHopLimitTTL;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, RttVariance)) {
        Stats->RttVariance = (uint32_t)Path->RttVariance;
    }

    *StatsLength = CXPLAT_MIN(*StatsLength, sizeof(QUIC_STATISTICS_V2));

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnParamGet(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;
    uint32_t Length;
    uint8_t Type;

    switch (Param) {

    case QUIC_PARAM_CONN_QUIC_VERSION:

        if (*BufferLength < sizeof(Connection->Stats.QuicVersion)) {
            *BufferLength = sizeof(Connection->Stats.QuicVersion);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Connection->Stats.QuicVersion);
        *(uint32_t*)Buffer = CxPlatByteSwapUint32(Connection->Stats.QuicVersion);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_LOCAL_ADDRESS:

        if (*BufferLength < sizeof(QUIC_ADDR)) {
            *BufferLength = sizeof(QUIC_ADDR);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Connection->State.LocalAddressSet) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(QUIC_ADDR);
        CxPlatCopyMemory(
            Buffer,
            &Connection->Paths[0].Route.LocalAddress,
            sizeof(QUIC_ADDR));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_REMOTE_ADDRESS:

        if (*BufferLength < sizeof(QUIC_ADDR)) {
            *BufferLength = sizeof(QUIC_ADDR);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Connection->State.RemoteAddressSet) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(QUIC_ADDR);
        CxPlatCopyMemory(
            Buffer,
            &Connection->Paths[0].Route.RemoteAddress,
            sizeof(QUIC_ADDR));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_IDEAL_PROCESSOR:

        if (*BufferLength < sizeof(uint16_t)) {
            *BufferLength = sizeof(uint16_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t);
        *(uint16_t*)Buffer = Connection->Partition->Processor;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SETTINGS:

        Status = QuicSettingsGetSettings(&Connection->Settings, BufferLength, (QUIC_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_CONN_VERSION_SETTINGS:

        Status = QuicSettingsGetVersionSettings(&Connection->Settings, BufferLength, (QUIC_VERSION_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_CONN_STATISTICS:
    case QUIC_PARAM_CONN_STATISTICS_PLAT: {

        if (*BufferLength < sizeof(QUIC_STATISTICS)) {
            *BufferLength = sizeof(QUIC_STATISTICS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_STATISTICS* Stats = (QUIC_STATISTICS*)Buffer;
        const QUIC_PATH* Path = &Connection->Paths[0];

        Stats->CorrelationId = Connection->Stats.CorrelationId;
        Stats->VersionNegotiation = Connection->Stats.VersionNegotiation;
        Stats->StatelessRetry = Connection->Stats.StatelessRetry;
        Stats->ResumptionAttempted = Connection->Stats.ResumptionAttempted;
        Stats->ResumptionSucceeded = Connection->Stats.ResumptionSucceeded;
        Stats->Rtt = (uint32_t)Path->SmoothedRtt;
        Stats->MinRtt = (uint32_t)Path->MinRtt;
        Stats->MaxRtt = (uint32_t)Path->MaxRtt;
        Stats->Timing.Start = Connection->Stats.Timing.Start;
        Stats->Timing.InitialFlightEnd = Connection->Stats.Timing.InitialFlightEnd;
        Stats->Timing.HandshakeFlightEnd = Connection->Stats.Timing.HandshakeFlightEnd;
        Stats->Handshake.ClientFlight1Bytes = Connection->Stats.Handshake.ClientFlight1Bytes;
        Stats->Handshake.ServerFlight1Bytes = Connection->Stats.Handshake.ServerFlight1Bytes;
        Stats->Handshake.ClientFlight2Bytes = Connection->Stats.Handshake.ClientFlight2Bytes;
        Stats->Send.PathMtu = Path->Mtu;
        Stats->Send.TotalPackets = Connection->Stats.Send.TotalPackets;
        Stats->Send.RetransmittablePackets = Connection->Stats.Send.RetransmittablePackets;
        Stats->Send.SuspectedLostPackets = Connection->Stats.Send.SuspectedLostPackets;
        Stats->Send.SpuriousLostPackets = Connection->Stats.Send.SpuriousLostPackets;
        Stats->Send.TotalBytes = Connection->Stats.Send.TotalBytes;
        Stats->Send.TotalStreamBytes = Connection->Stats.Send.TotalStreamBytes;
        Stats->Send.CongestionCount = Connection->Stats.Send.CongestionCount;
        Stats->Send.PersistentCongestionCount = Connection->Stats.Send.PersistentCongestionCount;
        Stats->Recv.TotalPackets = Connection->Stats.Recv.TotalPackets;
        Stats->Recv.ReorderedPackets = Connection->Stats.Recv.ReorderedPackets;
        Stats->Recv.DroppedPackets = Connection->Stats.Recv.DroppedPackets;
        Stats->Recv.DuplicatePackets = Connection->Stats.Recv.DuplicatePackets;
        Stats->Recv.TotalBytes = Connection->Stats.Recv.TotalBytes;
        Stats->Recv.TotalStreamBytes = Connection->Stats.Recv.TotalStreamBytes;
        Stats->Recv.DecryptionFailures = Connection->Stats.Recv.DecryptionFailures;
        Stats->Recv.ValidAckFrames = Connection->Stats.Recv.ValidAckFrames;
        Stats->Misc.KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;

        if (Param == QUIC_PARAM_CONN_STATISTICS_PLAT) {
            Stats->Timing.Start = CxPlatTimeUs64ToPlat(Stats->Timing.Start); // cppcheck-suppress selfAssignment
            Stats->Timing.InitialFlightEnd = CxPlatTimeUs64ToPlat(Stats->Timing.InitialFlightEnd); // cppcheck-suppress selfAssignment
            Stats->Timing.HandshakeFlightEnd = CxPlatTimeUs64ToPlat(Stats->Timing.HandshakeFlightEnd); // cppcheck-suppress selfAssignment
        }

        *BufferLength = sizeof(QUIC_STATISTICS);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:

        if (*BufferLength < sizeof(uint8_t)) {
            *BufferLength = sizeof(uint8_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint8_t);
        *(uint8_t*)Buffer = Connection->State.ShareBinding;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT:
        Type =
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR :
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR;
        goto Get_Stream_Count;

    case QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT:
        Type =
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR :
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR;
        goto Get_Stream_Count;

    Get_Stream_Count:
        if (*BufferLength < sizeof(uint16_t)) {
            *BufferLength = sizeof(uint16_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t);
        *(uint16_t*)Buffer =
            QuicStreamSetGetCountAvailable(&Connection->Streams, Type);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_MAX_STREAM_IDS:

        if (*BufferLength < sizeof(uint64_t) * NUMBER_OF_STREAM_TYPES) {
            *BufferLength = sizeof(uint64_t) * NUMBER_OF_STREAM_TYPES;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint64_t) * NUMBER_OF_STREAM_TYPES;
        QuicStreamSetGetMaxStreamIDs(&Connection->Streams, (uint64_t*)Buffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:

        if (Connection->CloseReasonPhrase == NULL) {
            Status = QUIC_STATUS_NOT_FOUND;
            break;
        }

        Length = (uint32_t)strlen(Connection->CloseReasonPhrase) + 1;
        if (*BufferLength < Length) {
            *BufferLength = Length;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = Length;
        CxPlatCopyMemory(Buffer, Connection->CloseReasonPhrase, Length);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME:

        if (*BufferLength < sizeof(QUIC_STREAM_SCHEDULING_SCHEME)) {
            *BufferLength = sizeof(QUIC_STREAM_SCHEDULING_SCHEME);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_STREAM_SCHEDULING_SCHEME);
        *(QUIC_STREAM_SCHEDULING_SCHEME*)Buffer =
            Connection->State.UseRoundRobinStreamScheduling ?
                QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN : QUIC_STREAM_SCHEDULING_SCHEME_FIFO;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->Settings.DatagramReceiveEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->Datagram.SendEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->State.Disable1RttEncrytion;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_STATISTICS_V2:
    case QUIC_PARAM_CONN_STATISTICS_V2_PLAT: {

        Status =
            QuicConnGetV2Statistics(
                Connection,
                Param == QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
                BufferLength,
                (QUIC_STATISTICS_V2*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_ORIG_DEST_CID:

        if (Connection->OrigDestCID == NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (*BufferLength < Connection->OrigDestCID->Length) {
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            *BufferLength = Connection->OrigDestCID->Length;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        CxPlatCopyMemory(
            Buffer,
            Connection->OrigDestCID->Data,
            Connection->OrigDestCID->Length);

        //
        // Tell app how much buffer we copied.
        //
        *BufferLength = Connection->OrigDestCID->Length;

        Status = QUIC_STATUS_SUCCESS;
        break;

     case QUIC_PARAM_CONN_SEND_DSCP:

        if (*BufferLength < sizeof(uint8_t)) {
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            *BufferLength = sizeof(uint8_t);
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        CxPlatCopyMemory(
            Buffer,
            &Connection->DSCP,
            sizeof(Connection->DSCP));

        *BufferLength = sizeof(Connection->DSCP);
        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnApplyNewSettings(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OverWrite,
    _In_ const QUIC_SETTINGS_INTERNAL* NewSettings
    )
{
    QuicTraceLogConnInfo(
        ApplySettings,
        Connection,
        "Applying new settings");

    if (!QuicSettingApply(
            &Connection->Settings,
            OverWrite,
            !Connection->State.Started,
            NewSettings)) {
        return FALSE;
    }

    if (!Connection->State.Started) {

        Connection->Paths[0].SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
        Connection->Paths[0].RttVariance = Connection->Paths[0].SmoothedRtt / 2;
        Connection->Paths[0].Mtu = Connection->Settings.MinimumMtu;

        if (Connection->Settings.ServerResumptionLevel > QUIC_SERVER_NO_RESUME &&
            Connection->HandshakeTP == NULL) {
            CXPLAT_DBG_ASSERT(!Connection->State.Started);
            Connection->HandshakeTP =
                CxPlatPoolAlloc(&Connection->Partition->TransportParamPool);
            if (Connection->HandshakeTP == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "handshake TP",
                    sizeof(*Connection->HandshakeTP));
            } else {
                CxPlatZeroMemory(Connection->HandshakeTP, sizeof(*Connection->HandshakeTP));
                Connection->State.ResumptionEnabled = TRUE;
            }
        }

        QuicSendApplyNewSettings(&Connection->Send, &Connection->Settings);
        QuicCongestionControlInitialize(&Connection->CongestionControl, &Connection->Settings);

        if (QuicConnIsClient(Connection) && Connection->Settings.IsSet.VersionSettings) {
            Connection->Stats.QuicVersion = Connection->Settings.VersionSettings->FullyDeployedVersions[0];
            QuicConnOnQuicVersionSet(Connection);
            //
            // The version has changed AFTER the crypto layer has been initialized,
            // so reinitialize the crypto layer here so it uses the right keys.
            // If the reinitialization fails, fail the connection.
            //
            if (QUIC_FAILED(QuicCryptoOnVersionChange(&Connection->Crypto))) {
                return FALSE;
            }
        }

        if (QuicConnIsServer(Connection) &&
            Connection->Settings.GreaseQuicBitEnabled &&
            (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT) > 0) {
            //
            // Endpoints that receive the grease_quic_bit transport parameter from
            // a peer SHOULD set the QUIC Bit to an unpredictable value extension
            // assigns specific meaning to the value of the bit.
            //
            uint8_t RandomValue;
            (void)CxPlatRandom(sizeof(RandomValue), &RandomValue);
            Connection->State.FixedBit = (RandomValue % 2);
            Connection->Stats.GreaseBitNegotiated = TRUE;
        }

        if (QuicConnIsServer(Connection) && Connection->Settings.ReliableResetEnabled) {
            Connection->State.ReliableResetStreamNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED;
            Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated = Connection->State.ReliableResetStreamNegotiated;

            QuicTraceLogConnVerbose(
                IndicateReliableResetNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED [IsNegotiated=%hhu]",
                Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (QuicConnIsServer(Connection) && Connection->Settings.OneWayDelayEnabled) {
            Connection->State.TimestampSendNegotiated = // Peer wants to recv, so we can send
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
            Connection->State.TimestampRecvNegotiated = // Peer wants to send, so we can recv
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED;
            Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated = Connection->State.TimestampSendNegotiated;
            Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated = Connection->State.TimestampRecvNegotiated;

            QuicTraceLogConnVerbose(
                IndicateOneWayDelayNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED [Send=%hhu,Recv=%hhu]",
                Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated,
                Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (Connection->Settings.EcnEnabled) {
            QUIC_PATH* Path = &Connection->Paths[0];
            Path->EcnValidationState = ECN_VALIDATION_TESTING;
        }
    }

    if (Connection->State.Started &&
        (Connection->Settings.EncryptionOffloadAllowed ^ Connection->Paths[0].EncryptionOffloading)) {
        // TODO: enable/disable after start
        CXPLAT_FRE_ASSERT(FALSE);
    }

    uint8_t PeerStreamType =
        QuicConnIsServer(Connection) ?
            STREAM_ID_FLAG_IS_CLIENT : STREAM_ID_FLAG_IS_SERVER;

    if (NewSettings->IsSet.PeerBidiStreamCount) {
        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            PeerStreamType | STREAM_ID_FLAG_IS_BI_DIR,
            Connection->Settings.PeerBidiStreamCount);
    }
    if (NewSettings->IsSet.PeerUnidiStreamCount) {
        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            PeerStreamType | STREAM_ID_FLAG_IS_UNI_DIR,
            Connection->Settings.PeerUnidiStreamCount);
    }

    if (NewSettings->IsSet.KeepAliveIntervalMs && Connection->State.Started) {
        if (Connection->Settings.KeepAliveIntervalMs != 0) {
            QuicConnProcessKeepAliveOperation(Connection);
        } else {
            QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_KEEP_ALIVE);
        }
    }

    if (OverWrite) {
        QuicSettingsDumpNew(NewSettings);
    } else {
        QuicSettingsDump(&Connection->Settings); // TODO - Really necessary?
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessApiOperation(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_API_CONTEXT* ApiCtx
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_STATUS* ApiStatus = ApiCtx->Status;
    CXPLAT_EVENT* ApiCompleted = ApiCtx->Completed;

    switch (ApiCtx->Type) {

    case QUIC_API_TYPE_CONN_CLOSE:
        QuicConnCloseHandle(Connection);
        break;

    case QUIC_API_TYPE_CONN_SHUTDOWN:
        QuicConnShutdown(
            Connection,
            ApiCtx->CONN_SHUTDOWN.Flags,
            ApiCtx->CONN_SHUTDOWN.ErrorCode,
            ApiCtx->CONN_SHUTDOWN.RegistrationShutdown,
            ApiCtx->CONN_SHUTDOWN.TransportShutdown);
        break;

    case QUIC_API_TYPE_CONN_START:
        Status =
            QuicConnStart(
                Connection,
                ApiCtx->CONN_START.Configuration,
                ApiCtx->CONN_START.Family,
                ApiCtx->CONN_START.ServerName,
                ApiCtx->CONN_START.ServerPort,
                QUIC_CONN_START_FLAG_NONE);
        ApiCtx->CONN_START.ServerName = NULL;
        break;

    case QUIC_API_TYPE_CONN_SET_CONFIGURATION:
        Status =
            QuicConnSetConfiguration(
                Connection,
                ApiCtx->CONN_SET_CONFIGURATION.Configuration);
        break;

    case QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET:
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        Status =
            QuicConnSendResumptionTicket(
                Connection,
                ApiCtx->CONN_SEND_RESUMPTION_TICKET.AppDataLength,
                ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData);
        ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData = NULL;
        if (ApiCtx->CONN_SEND_RESUMPTION_TICKET.Flags & QUIC_SEND_RESUMPTION_FLAG_FINAL) {
            Connection->State.ResumptionEnabled = FALSE;
        }
        break;

    case QUIC_API_TYPE_CONN_COMPLETE_RESUMPTION_TICKET_VALIDATION:
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        QuicCryptoCustomTicketValidationComplete(
            &Connection->Crypto,
            ApiCtx->CONN_COMPLETE_RESUMPTION_TICKET_VALIDATION.Result);
        break;

    case QUIC_API_TYPE_CONN_COMPLETE_CERTIFICATE_VALIDATION:
        QuicCryptoCustomCertValidationComplete(
            &Connection->Crypto,
            ApiCtx->CONN_COMPLETE_CERTIFICATE_VALIDATION.Result,
            ApiCtx->CONN_COMPLETE_CERTIFICATE_VALIDATION.TlsAlert);
        break;

    case QUIC_API_TYPE_STRM_CLOSE:
        QuicStreamClose(ApiCtx->STRM_CLOSE.Stream);
        break;

    case QUIC_API_TYPE_STRM_SHUTDOWN:
        QuicStreamShutdown(
            ApiCtx->STRM_SHUTDOWN.Stream,
            ApiCtx->STRM_SHUTDOWN.Flags,
            ApiCtx->STRM_SHUTDOWN.ErrorCode);
        break;

    case QUIC_API_TYPE_STRM_START:
        Status =
            QuicStreamStart(
                ApiCtx->STRM_START.Stream,
                ApiCtx->STRM_START.Flags,
                FALSE);
        break;

    case QUIC_API_TYPE_STRM_SEND:
        QuicStreamSendFlush(
            ApiCtx->STRM_SEND.Stream);
        break;

    case QUIC_API_TYPE_STRM_RECV_COMPLETE:
        QuicStreamReceiveCompletePending(
            ApiCtx->STRM_RECV_COMPLETE.Stream);
        break;

    case QUIC_API_TYPE_STRM_RECV_SET_ENABLED:
        Status =
            QuicStreamRecvSetEnabledState(
                ApiCtx->STRM_RECV_SET_ENABLED.Stream,
                ApiCtx->STRM_RECV_SET_ENABLED.IsEnabled);
        break;

    case QUIC_API_TYPE_STRM_PROVIDE_RECV_BUFFERS:
        Status =
            QuicStreamProvideRecvBuffers(
                ApiCtx->STRM_PROVIDE_RECV_BUFFERS.Stream,
                &ApiCtx->STRM_PROVIDE_RECV_BUFFERS.Chunks);

        if (Status != QUIC_STATUS_SUCCESS) {
            //
            // If we cannot accept the app provided buffers at this point, we need to abort
            // the connection: otherwise, we break the contract with the app about writting
            // data to the provided buffers in order.
            //
            QuicConnFatalError(
                ApiCtx->STRM_PROVIDE_RECV_BUFFERS.Stream->Connection,
                Status,
                "Failed to accept app provided receive buffers");
        }
        break;

    case QUIC_API_TYPE_SET_PARAM:
        Status =
            QuicLibrarySetParam(
                ApiCtx->SET_PARAM.Handle,
                ApiCtx->SET_PARAM.Param,
                ApiCtx->SET_PARAM.BufferLength,
                ApiCtx->SET_PARAM.Buffer);
        break;

    case QUIC_API_TYPE_GET_PARAM:
        Status =
            QuicLibraryGetParam(
                ApiCtx->GET_PARAM.Handle,
                ApiCtx->GET_PARAM.Param,
                ApiCtx->GET_PARAM.BufferLength,
                ApiCtx->GET_PARAM.Buffer);
        break;

    case QUIC_API_TYPE_DATAGRAM_SEND:
        QuicDatagramSendFlush(&Connection->Datagram);
        break;

    default:
        CXPLAT_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    if (ApiStatus) {
        *ApiStatus = Status;
    }
    if (ApiCompleted) {
        CxPlatEventSet(*ApiCompleted);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessExpiredTimer(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type
    )
{
    switch (Type) {
    case QUIC_CONN_TIMER_IDLE:
        QuicConnProcessIdleTimerOperation(Connection);
        break;
    case QUIC_CONN_TIMER_LOSS_DETECTION:
        QuicLossDetectionProcessTimerOperation(&Connection->LossDetection);
        break;
    case QUIC_CONN_TIMER_KEEP_ALIVE:
        QuicConnProcessKeepAliveOperation(Connection);
        break;
    case QUIC_CONN_TIMER_SHUTDOWN:
        QuicConnProcessShutdownTimerOperation(Connection);
        break;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnDrainOperations(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ BOOLEAN* StillHasPriorityWork
    )
{
    QUIC_OPERATION* Oper;
    const uint32_t MaxOperationCount =
        Connection->Settings.MaxOperationsPerDrain;
    uint32_t OperationCount = 0;
    BOOLEAN HasMoreWorkToDo = TRUE;

    CXPLAT_PASSIVE_CODE();

    if (!Connection->State.Initialized && !Connection->State.ShutdownComplete) {
        //
        // TODO - Try to move this only after the connection is accepted by the
        // listener. But that's going to be pretty complicated.
        //
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_STATUS Status;
        if (QUIC_FAILED(Status = QuicCryptoInitialize(&Connection->Crypto))) {
            QuicConnFatalError(Connection, Status, "Lazily initialize failure");
        } else {
            Connection->State.Initialized = TRUE;
            QuicTraceEvent(
                ConnInitializeComplete,
                "[conn][%p] Initialize complete",
                Connection);
            if (Connection->Settings.KeepAliveIntervalMs != 0) {
                QuicConnTimerSet(
                    Connection,
                    QUIC_CONN_TIMER_KEEP_ALIVE,
                    MS_TO_US(Connection->Settings.KeepAliveIntervalMs));
            }
        }
    }

    while (!Connection->State.UpdateWorker &&
           OperationCount++ < MaxOperationCount) {

        Oper = QuicOperationDequeue(&Connection->OperQ, Connection->Partition);
        if (Oper == NULL) {
            HasMoreWorkToDo = FALSE;
            break;
        }

        QuicOperLog(Connection, Oper);

        BOOLEAN FreeOper = Oper->FreeAfterProcess;

        switch (Oper->Type) {

        case QUIC_OPER_TYPE_API_CALL:
            CXPLAT_DBG_ASSERT(Oper->API_CALL.Context != NULL);
            QuicConnProcessApiOperation(
                Connection,
                Oper->API_CALL.Context);
            break;

        case QUIC_OPER_TYPE_FLUSH_RECV:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            if (!QuicConnFlushRecv(Connection)) {
                //
                // Still have more data to recv. Put the operation back on the
                // queue.
                //
                FreeOper = FALSE;
                (void)QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper);
            }
            break;

        case QUIC_OPER_TYPE_UNREACHABLE:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnProcessUdpUnreachable(
                Connection,
                &Oper->UNREACHABLE.RemoteAddress);
            break;

        case QUIC_OPER_TYPE_FLUSH_STREAM_RECV:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicStreamRecvFlush(Oper->FLUSH_STREAM_RECEIVE.Stream);
            break;

        case QUIC_OPER_TYPE_FLUSH_SEND:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            if (QuicSendFlush(&Connection->Send)) {
                //
                // We have no more data to send out so clear the pending flag.
                //
                Connection->Send.FlushOperationPending = FALSE;
            } else {
                //
                // Still have more data to send. Put the operation back on the
                // queue.
                //
                FreeOper = FALSE;
                (void)QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper);
            }
            break;

        case QUIC_OPER_TYPE_TIMER_EXPIRED:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnProcessExpiredTimer(Connection, Oper->TIMER_EXPIRED.Type);
            break;

        case QUIC_OPER_TYPE_TRACE_RUNDOWN:
            QuicConnTraceRundownOper(Connection);
            break;

        case QUIC_OPER_TYPE_ROUTE_COMPLETION:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnProcessRouteCompletion(
                Connection, Oper->ROUTE.PhysicalAddress, Oper->ROUTE.PathId, Oper->ROUTE.Succeeded);
            break;

        default:
            CXPLAT_FRE_ASSERT(FALSE);
            break;
        }

        QuicConnValidate(Connection);

        if (FreeOper) {
            QuicOperationFree(Oper);
        }

        Connection->Stats.Schedule.OperationCount++;
        QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_OPER_COMPLETED);
    }

    if (Connection->State.ProcessShutdownComplete) {
        QuicConnOnShutdownComplete(Connection);
    }

    if (!Connection->State.ShutdownComplete) {
        if (OperationCount >= MaxOperationCount &&
            (Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK)) {
            //
            // We can't process any more operations but still need to send an
            // immediate ACK. So as to not introduce additional queuing delay do
            // one immediate flush now.
            //
            (void)QuicSendFlush(&Connection->Send);
        }
    }

    QuicStreamSetDrainClosedStreams(&Connection->Streams);

    QuicConnValidate(Connection);

    if (HasMoreWorkToDo) {
        *StillHasPriorityWork = QuicOperationHasPriority(&Connection->OperQ);
        return TRUE;
    }

    return FALSE;
}
