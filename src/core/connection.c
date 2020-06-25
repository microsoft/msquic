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
    on multiple threads. The function will drain up to QUIC_SETTINGS's
    MaxOperationsPerDrain operations per call, so as to not starve any other
    work.

    While most of the connection specific work is managed by other interfaces,
    the following things are managed in this file:

    Connection Lifetime - Initialization, handshake and state changes, shutdown,
    closure and cleanup are located here.

    Receive Path - The per-connection packet receive path is here. This is the
    logic that happens after the global receive callback has processed the
    packet initially and done the necessary processing to pass the packet to
    the correct connection.

--*/

#include "precomp.h"

typedef struct QUIC_RECEIVE_PROCESSING_STATE {
    BOOLEAN ResetIdleTimeout;
    BOOLEAN UpdatePartitionId;
    uint8_t PartitionIndex;
} QUIC_RECEIVE_PROCESSING_STATE;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnInitializeCrypto(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
QUIC_CONNECTION*
QuicConnAlloc(
    _In_ QUIC_SESSION* Session,
    _In_opt_ const QUIC_RECV_DATAGRAM* const Datagram
    )
{
    BOOLEAN IsServer = Datagram != NULL;
    uint8_t CurProcIndex = QuicLibraryGetCurrentPartition();

    //
    // For client, the datapath partitioning info is not known yet, so just use
    // the current processor for now. Once the connection receives a packet the
    // partition can be updated accordingly.
    //
    uint8_t BasePartitionId =
        IsServer ?
            (Datagram->PartitionIndex % MsQuicLib.PartitionCount) :
            CurProcIndex;
    uint8_t PartitionId = QuicPartitionIdCreate(BasePartitionId);
    QUIC_DBG_ASSERT(BasePartitionId == QuicPartitionIdGetIndex(PartitionId));

    QUIC_CONNECTION* Connection =
        QuicPoolAlloc(&MsQuicLib.PerProc[CurProcIndex].ConnectionPool);
    if (Connection == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
        goto Error;
    }
    QuicZeroMemory(Connection, sizeof(QUIC_CONNECTION));

#if DEBUG
    InterlockedIncrement(&MsQuicLib.ConnectionCount);
#endif

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
    Connection->State.UseSendBuffer = QUIC_DEFAULT_SEND_BUFFERING_ENABLE;
    Connection->State.EncryptionEnabled = !MsQuicLib.EncryptionDisabled;
    Connection->State.ShareBinding = IsServer;
    Connection->Stats.Timing.Start = QuicTimeUs64();
    Connection->SourceCidLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
    Connection->AckDelayExponent = QUIC_ACK_DELAY_EXPONENT;
    Connection->PeerTransportParams.AckDelayExponent = QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT;
    Connection->ReceiveQueueTail = &Connection->ReceiveQueue;
    QuicDispatchLockInitialize(&Connection->ReceiveQueueLock);
    QuicListInitializeHead(&Connection->DestCids);
    QuicStreamSetInitialize(&Connection->Streams);
    QuicSendBufferInitialize(&Connection->SendBuffer);
    QuicOperationQueueInitialize(&Connection->OperQ);
    QuicSendInitialize(&Connection->Send);
    QuicLossDetectionInitialize(&Connection->LossDetection);
    QuicDatagramInitialize(&Connection->Datagram);

    QUIC_PATH* Path = &Connection->Paths[0];
    QuicPathInitialize(Connection, Path);
    Path->IsActive = TRUE;
    Connection->PathsCount = 1;

    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Timers); i++) {
        Connection->Timers[i].Type = (QUIC_CONN_TIMER_TYPE)i;
        Connection->Timers[i].ExpirationTime = UINT64_MAX;
    }

    if (IsServer) {

        //
        // Use global settings until the connection is assigned to a session.
        // Then the connection will use the session's settings.
        //
        QuicConnApplySettings(Connection, &MsQuicLib.Settings);

        const QUIC_RECV_PACKET* Packet =
            QuicDataPathRecvDatagramToRecvPacket(Datagram);

        Connection->Type = QUIC_HANDLE_TYPE_CHILD;
        if (MsQuicLib.Settings.LoadBalancingMode == QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            QuicRandom(1, Connection->ServerID); // Randomize the first byte.
            if (QuicAddrGetFamily(&Datagram->Tuple->LocalAddress) == AF_INET) {
                QuicCopyMemory(
                    Connection->ServerID + 1,
                    &Datagram->Tuple->LocalAddress.Ipv4.sin_addr,
                    4);
            } else {
                QuicCopyMemory(
                    Connection->ServerID + 1,
                    ((uint8_t*)&Datagram->Tuple->LocalAddress.Ipv6.sin6_addr) + 12,
                    4);
            }
        }

        Connection->Stats.QuicVersion = Packet->Invariant->LONG_HDR.Version;
        QuicConnOnQuicVersionSet(Connection);

        Path->LocalAddress = Datagram->Tuple->LocalAddress;
        Connection->State.LocalAddressSet = TRUE;
        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!SOCKADDR!",
            Connection,
            LOG_ADDR_LEN(Path->LocalAddress),
            (const uint8_t*)&Path->LocalAddress);

        Path->RemoteAddress = Datagram->Tuple->RemoteAddress;
        Connection->State.RemoteAddressSet = TRUE;
        QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!SOCKADDR!",
            Connection,
            LOG_ADDR_LEN(Path->RemoteAddress),
            (const uint8_t*)&Path->RemoteAddress);

        Path->DestCid =
            QuicCidNewDestination(Packet->SourceCidLen, Packet->SourceCid);
        if (Path->DestCid == NULL) {
            goto Error;
        }
        Path->DestCid->CID.UsedLocally = TRUE;
        QuicListInsertTail(&Connection->DestCids, &Path->DestCid->Link);
        QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            Path->DestCid->CID.Length,
            Path->DestCid->CID.Data);

        QUIC_CID_HASH_ENTRY* SourceCid =
            QuicCidNewSource(Connection, Packet->DestCidLen, Packet->DestCid);
        if (SourceCid == NULL) {
            goto Error;
        }
        SourceCid->CID.IsInitial = TRUE;
        SourceCid->CID.UsedByPeer = TRUE;
        QuicListPushEntry(&Connection->SourceCids, &SourceCid->Link);
        QuicTraceEvent(
            ConnSourceCidAdded,
            "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
            Connection,
            SourceCid->CID.SequenceNumber,
            SourceCid->CID.Length,
            SourceCid->CID.Data);

    } else {
        Connection->Type = QUIC_HANDLE_TYPE_CLIENT;
        Connection->State.ExternalOwner = TRUE;
        Path->IsPeerValidated = TRUE;
        Path->Allowance = UINT32_MAX;

        Path->DestCid = QuicCidNewRandomDestination();
        if (Path->DestCid == NULL) {
            goto Error;
        }
        Path->DestCid->CID.UsedLocally = TRUE;
        Connection->DestCidCount++;
        QuicListInsertTail(&Connection->DestCids, &Path->DestCid->Link);
        QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            Path->DestCid->CID.Length,
            Path->DestCid->CID.Data);
    }

    QuicSessionRegisterConnection(Session, Connection);

    return Connection;

Error:

    if (Connection != NULL) {
        QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);
    }

    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicConnInitialize(
    _In_ QUIC_SESSION* Session,
    _In_opt_ const QUIC_RECV_DATAGRAM* const Datagram, // NULL for client side
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem))
        QUIC_CONNECTION** NewConnection
    )
{
    QUIC_STATUS Status;
    uint32_t InitStep = 0;

    QUIC_CONNECTION* Connection = QuicConnAlloc(Session, Datagram);
    if (Connection == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    InitStep++; // Step 1

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

    //
    // N.B. Initializing packet space can fail part-way through, so it must be
    //      cleaned up even if it doesn't complete. Do not separate it from
    //      allocation.
    //
    Status =
        QuicRangeInitialize(
            QUIC_MAX_RANGE_DECODE_ACKS,
            &Connection->DecodedAckRanges);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    InitStep++; // Step 2

    if (Datagram == NULL) {
        Connection->State.Initialized = TRUE;
        QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
    } else {
        //
        // Server lazily finishes initialzation in response to first operation.
        //
    }

    *NewConnection = Connection;

    return QUIC_STATUS_SUCCESS;

Error:

    switch (InitStep) {
    case 2:
        QuicRangeUninitialize(&Connection->DecodedAckRanges);
        __fallthrough;
    case 1:
        for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); i++) {
            if (Connection->Packets[i] != NULL) {
                QuicPacketSpaceUninitialize(Connection->Packets[i]);
            }
        }

        Connection->State.HandleClosed = TRUE;
        Connection->State.Uninitialized = TRUE;
        if (Datagram != NULL) {
            QUIC_FREE(
                QUIC_CONTAINING_RECORD(
                    Connection->SourceCids.Next,
                    QUIC_CID_HASH_ENTRY,
                    Link));
            Connection->SourceCids.Next = NULL;
        }
        QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);
        break;
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnFree(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection
    )
{
    QUIC_FRE_ASSERT(!Connection->State.Freed);
    QUIC_TEL_ASSERT(Connection->RefCount == 0);
    if (Connection->State.ExternalOwner) {
        QUIC_TEL_ASSERT(Connection->State.HandleClosed);
        QUIC_TEL_ASSERT(Connection->State.Uninitialized);
    }
    QUIC_TEL_ASSERT(Connection->SourceCids.Next == NULL);
    QUIC_TEL_ASSERT(QuicListIsEmpty(&Connection->Streams.ClosedStreams));
    QuicLossDetectionUninitialize(&Connection->LossDetection);
    QuicSendUninitialize(&Connection->Send);
    while (!QuicListIsEmpty(&Connection->DestCids)) {
        QUIC_CID_QUIC_LIST_ENTRY *CID =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&Connection->DestCids),
                QUIC_CID_QUIC_LIST_ENTRY,
                Link);
        QUIC_FREE(CID);
    }
    if (Connection->Worker != NULL) {
        QuicOperationQueueClear(Connection->Worker, &Connection->OperQ);
    }
    if (Connection->ReceiveQueue != NULL) {
        QUIC_RECV_DATAGRAM* Datagram = Connection->ReceiveQueue;
        do {
            Datagram->QueuedOnConnection = FALSE;
        } while ((Datagram = Datagram->Next) != NULL);
        QuicDataPathBindingReturnRecvDatagrams(Connection->ReceiveQueue);
        Connection->ReceiveQueue = NULL;
    }
    QUIC_PATH* Path = &Connection->Paths[0];
    if (Path->Binding != NULL) {
        QuicLibraryReleaseBinding(Path->Binding);
        Path->Binding = NULL;
    }
    QuicDispatchLockUninitialize(&Connection->ReceiveQueueLock);
    QuicOperationQueueUninitialize(&Connection->OperQ);
    QuicStreamSetUninitialize(&Connection->Streams);
    QuicSendBufferUninitialize(&Connection->SendBuffer);
    QuicDatagramUninitialize(&Connection->Datagram);
    QuicSessionUnregisterConnection(Connection);
    if (Connection->Registration != NULL) {
        QuicRundownRelease(&Connection->Registration->ConnectionRundown);
    }
    Connection->State.Freed = TRUE;
    if (Connection->RemoteServerName != NULL) {
        QUIC_FREE(Connection->RemoteServerName);
    }
    if (Connection->OrigDestCID != NULL) {
        QUIC_FREE(Connection->OrigDestCID);
    }
    if (Connection->HandshakeTP != NULL) {
        QuicPoolFree(
            &MsQuicLib.PerProc[QuicLibraryGetCurrentPartition()].TransportParamPool,
            Connection->HandshakeTP);
        Connection->HandshakeTP = NULL;
    }
    QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
    QuicPoolFree(
        &MsQuicLib.PerProc[QuicLibraryGetCurrentPartition()].ConnectionPool,
        Connection);

#if DEBUG
    InterlockedDecrement(&MsQuicLib.ConnectionCount);
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnApplySettings(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_SETTINGS* Settings
    )
{
    Connection->State.UsePacing = Settings->PacingDefault;
    Connection->MaxAckDelayMs = Settings->MaxAckDelayMs;
    Connection->Paths[0].SmoothedRtt = MS_TO_US(Settings->InitialRttMs);
    Connection->DisconnectTimeoutUs = MS_TO_US(Settings->DisconnectTimeoutMs);
    Connection->IdleTimeoutMs = Settings->IdleTimeoutMs;
    Connection->HandshakeIdleTimeoutMs = Settings->HandshakeIdleTimeoutMs;
    Connection->KeepAliveIntervalMs = Settings->KeepAliveIntervalMs;
    Connection->Datagram.ReceiveEnabled = Settings->DatagramReceiveEnabled;

    uint8_t PeerStreamType =
        QuicConnIsServer(Connection) ?
            STREAM_ID_FLAG_IS_CLIENT : STREAM_ID_FLAG_IS_SERVER;
    if (Settings->BidiStreamCount != 0) {
        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            PeerStreamType | STREAM_ID_FLAG_IS_BI_DIR,
            Settings->BidiStreamCount);
    }
    if (Settings->UnidiStreamCount != 0) {
        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            PeerStreamType | STREAM_ID_FLAG_IS_UNI_DIR,
            Settings->UnidiStreamCount);
    }

    if (Settings->ServerResumptionLevel > QUIC_SERVER_NO_RESUME) {
        QUIC_DBG_ASSERT(!Connection->State.Started);
        //
        // TODO: Replace with pool allocator for performance.
        //
        Connection->HandshakeTP =
            QuicPoolAlloc(&MsQuicLib.PerProc[QuicLibraryGetCurrentPartition()].TransportParamPool);
        if (Connection->HandshakeTP == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "handshake TP",
                sizeof(*Connection->HandshakeTP));
        } else {
            QuicZeroMemory(Connection->HandshakeTP, sizeof(*Connection->HandshakeTP));
            Connection->State.ResumptionEnabled = TRUE;
        }
    }

    QuicSendApplySettings(&Connection->Send, Settings);
    QuicCongestionControlInitialize(&Connection->CongestionControl, Settings);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnShutdown(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    uint32_t CloseFlags = QUIC_CLOSE_APPLICATION;
    if (Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT ||
        (!Connection->State.Started && !QuicConnIsServer(Connection))) {
        CloseFlags |= QUIC_CLOSE_SILENT;
    }

    QuicConnCloseLocally(Connection, CloseFlags, ErrorCode, NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUninitialize(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_TEL_ASSERT(Connection->State.HandleClosed);
    QUIC_TEL_ASSERT(!Connection->State.Uninitialized);

    Connection->State.Uninitialized = TRUE;
    Connection->State.UpdateWorker = FALSE;

    //
    // Ensure we are shut down.
    //
    QuicConnShutdown(
        Connection,
        QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
        QUIC_ERROR_NO_ERROR);

    //
    // Remove all entries in the binding's lookup tables so we don't get any
    // more packets queued.
    //
    if (Connection->Paths[0].Binding != NULL) {
        QuicBindingRemoveConnection(Connection->Paths[0].Binding, Connection);
    }

    //
    // Clean up the packet space first, to return any deferred received
    // packets back to the binding.
    //
    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); i++) {
        if (Connection->Packets[i] != NULL) {
            QuicPacketSpaceUninitialize(Connection->Packets[i]);
            Connection->Packets[i] = NULL;
        }
    }

    //
    // Clean up the rest of the internal state.
    //
    QuicRangeUninitialize(&Connection->DecodedAckRanges);
    QuicCryptoUninitialize(&Connection->Crypto);
    QuicTimerWheelRemoveConnection(&Connection->Worker->TimerWheel, Connection);
    QuicOperationQueueClear(Connection->Worker, &Connection->OperQ);

    if (Connection->CloseReasonPhrase != NULL) {
        QUIC_FREE(Connection->CloseReasonPhrase);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnCloseHandle(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_TEL_ASSERT(!Connection->State.HandleClosed);

    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_SILENT | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)QUIC_STATUS_ABORTED,
        NULL);

    if (Connection->State.SendShutdownCompleteNotif) {
        QuicConnOnShutdownComplete(Connection);
    }

    Connection->State.HandleClosed = TRUE;
    Connection->ClientCallbackHandler = NULL;

    QuicSessionUnregisterConnection(Connection);

    QuicTraceEvent(
        ConnHandleClosed,
        "[conn][%p] Handle closed",
        Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueTraceRundown(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_OPERATION* Oper;
    if ((Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_TRACE_RUNDOWN)) != NULL) {
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
    if (Connection->Session != NULL) {
        QuicTraceEvent(
            ConnRegisterSession,
            "[conn][%p] Registered with session: %p",
            Connection,
            Connection->Session);
    }
    if (Connection->State.Started) {
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (Connection->State.LocalAddressSet || i != 0) {
                QuicTraceEvent(
                    ConnLocalAddrAdded,
                     "[conn][%p] New Local IP: %!SOCKADDR!",
                    Connection,
                    LOG_ADDR_LEN(Connection->Paths[i].LocalAddress),
                    (const uint8_t*)&Connection->Paths[i].LocalAddress);
            }
            if (Connection->State.RemoteAddressSet || i != 0) {
                QuicTraceEvent(
                    ConnRemoteAddrAdded,
                    "[conn][%p] New Remote IP: %!SOCKADDR!",
                    Connection,
                    LOG_ADDR_LEN(Connection->Paths[i].RemoteAddress),
                    (const uint8_t*)&Connection->Paths[i].RemoteAddress);
            }
        }
        for (QUIC_SINGLE_LIST_ENTRY* Entry = Connection->SourceCids.Next;
                Entry != NULL;
                Entry = Entry->Next) {
            const QUIC_CID_HASH_ENTRY* SourceCid =
                QUIC_CONTAINING_RECORD(
                    Entry,
                    QUIC_CID_HASH_ENTRY,
                    Link);
            UNREFERENCED_PARAMETER(SourceCid);
            QuicTraceEvent(
                ConnSourceCidAdded,
                "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
                Connection,
                SourceCid->CID.SequenceNumber,
                SourceCid->CID.Length,
                SourceCid->CID.Data);
        }
        for (QUIC_LIST_ENTRY* Entry = Connection->DestCids.Flink;
                Entry != &Connection->DestCids;
                Entry = Entry->Flink) {
            const QUIC_CID_QUIC_LIST_ENTRY* DestCid =
                QUIC_CONTAINING_RECORD(
                    Entry,
                    QUIC_CID_QUIC_LIST_ENTRY,
                    Link);
            UNREFERENCED_PARAMETER(DestCid);
            QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                Connection,
                DestCid->CID.SequenceNumber,
                DestCid->CID.Length,
                DestCid->CID.Data);
        }
    }
    if (Connection->State.Connected) {
        QuicConnOnQuicVersionSet(Connection);
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
    QUIC_STATUS Status;
    if (!Connection->State.HandleClosed) {
        QUIC_CONN_VERIFY(Connection, Connection->State.HandleShutdown || Connection->ClientCallbackHandler != NULL);
        if (Connection->ClientCallbackHandler == NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
            QuicTraceLogConnWarning(
                ApiEventNoHandler,
                Connection,
                "Event silently discarded (no handler).");
        } else {
            uint64_t StartTime = QuicTimeUs64();
            Status =
                Connection->ClientCallbackHandler(
                    (HQUIC)Connection,
                    Connection->ClientContext,
                    Event);
            uint64_t EndTime = QuicTimeUs64();
            if (EndTime - StartTime > QUIC_MAX_CALLBACK_TIME_WARNING) {
                QuicTraceLogConnWarning(
                    ApiEventTooLong,
                    Connection,
                    "App took excessive time (%llu us) in callback.",
                    (EndTime - StartTime));
                QUIC_TEL_ASSERTMSG_ARGS(
                    EndTime - StartTime < QUIC_MAX_CALLBACK_TIME_ERROR,
                    "App extremely long time in connection callback",
                    Connection->Registration == NULL ?
                        NULL : Connection->Registration->AppName,
                    Event->Type, 0);
            }
        }
    } else {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogConnWarning(
            ApiEventAlreadyClosed,
            Connection,
            "Event silently discarded.");
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
    if (QuicOperationEnqueue(&Connection->OperQ, Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueueConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueHighestPriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
    if (QuicOperationEnqueueFront(&Connection->OperQ, Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueueConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnUpdateRtt(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t LatestRtt
    )
{
    BOOLEAN RttUpdated;
    UNREFERENCED_PARAMETER(Connection);

    if (LatestRtt == 0) {
        //
        // RTT cannot be zero or several loss recovery algorithms break down.
        //
        LatestRtt = 1;
    }

    Path->LatestRttSample = LatestRtt;
    if (LatestRtt < Path->MinRtt) {
        Path->MinRtt = LatestRtt;
    }
    if (LatestRtt > Path->MaxRtt) {
        Path->MaxRtt = LatestRtt;
    }

    if (!Path->GotFirstRttSample) {
        Path->GotFirstRttSample = TRUE;

        Path->SmoothedRtt = LatestRtt;
        Path->RttVariance = LatestRtt / 2;
        RttUpdated = TRUE;

    } else {
        uint32_t PrevRtt = Path->SmoothedRtt;
        if (Path->SmoothedRtt > LatestRtt) {
            Path->RttVariance = (3 * Path->RttVariance + Path->SmoothedRtt - LatestRtt) / 4;
        } else {
            Path->RttVariance = (3 * Path->RttVariance + LatestRtt - Path->SmoothedRtt) / 4;
        }
        Path->SmoothedRtt = (7 * Path->SmoothedRtt + LatestRtt) / 8;
        RttUpdated = PrevRtt != Path->SmoothedRtt;
    }

    if (RttUpdated) {
        QUIC_DBG_ASSERT(Path->SmoothedRtt != 0);
        QuicTraceLogConnVerbose(
            RttUpdated,
            Connection,
            "Updated Rtt=%u.%03u ms, Var=%u.%03u",
            Path->SmoothedRtt / 1000, Path->SmoothedRtt % 1000,
            Path->RttVariance / 1000, Path->RttVariance % 1000);
    }

    return RttUpdated;
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
                Connection->Registration->CidPrefixLength,
                Connection->Registration->CidPrefix);
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
            QUIC_FREE(SourceCid);
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
        SourceCid->CID.Length,
        SourceCid->CID.Data);

    SourceCid->CID.SequenceNumber = Connection->NextSourceCidSequenceNumber++;
    if (SourceCid->CID.SequenceNumber > 0) {
        SourceCid->CID.NeedsToSend = TRUE;
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID);
    }

    if (IsInitial) {
        SourceCid->CID.IsInitial = TRUE;
        QuicListPushEntry(&Connection->SourceCids, &SourceCid->Link);
    } else {
        QUIC_SINGLE_LIST_ENTRY** Tail = &Connection->SourceCids.Next;
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
    const QUIC_SINGLE_LIST_ENTRY* Entry = Connection->SourceCids.Next;
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
        QUIC_SINGLE_LIST_ENTRY* Entry = Connection->SourceCids.Next;
        while (Entry != NULL) {
            QUIC_CID_HASH_ENTRY* SourceCid =
                QUIC_CONTAINING_RECORD(Entry, QUIC_CID_HASH_ENTRY, Link);
            SourceCid->CID.Retired = TRUE;
            Entry = Entry->Next;
        }
    } else {
        uint8_t CurrentCidCount = QuicConnSourceCidsCount(Connection);
        QUIC_DBG_ASSERT(CurrentCidCount <= Connection->SourceCidLimit);
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
QUIC_CID_QUIC_LIST_ENTRY*
QuicConnGetUnusedDestCid(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    for (QUIC_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_QUIC_LIST_ENTRY* DestCid =
            QUIC_CONTAINING_RECORD(
                Entry,
                QUIC_CID_QUIC_LIST_ENTRY,
                Link);
        if (!DestCid->CID.UsedLocally) {
            return DestCid;
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRetireCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CID_QUIC_LIST_ENTRY* DestCid
    )
{
    QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
        Connection,
        DestCid->CID.SequenceNumber,
        DestCid->CID.Length,
        DestCid->CID.Data);
    Connection->DestCidCount--;
    DestCid->CID.Retired = TRUE;
    DestCid->CID.NeedsToSend = TRUE;
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID);
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

    QUIC_CID_QUIC_LIST_ENTRY* NewDestCid = QuicConnGetUnusedDestCid(Connection);
    if (NewDestCid == NULL) {
        QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            Connection,
            "Can't retire current CID because we don't have a replacement");
        return FALSE;
    }

    QuicConnRetireCid(Connection, Path->DestCid);
    Path->DestCid = NewDestCid;
    Path->DestCid->CID.UsedLocally = TRUE;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnOnRetirePriorToUpdated(
    _In_ QUIC_CONNECTION* Connection
    )
{
    BOOLEAN ReplaceRetiredCids = FALSE;

    for (QUIC_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_QUIC_LIST_ENTRY* DestCid =
            QUIC_CONTAINING_RECORD(
                Entry,
                QUIC_CID_QUIC_LIST_ENTRY,
                Link);
        if (DestCid->CID.SequenceNumber >= Connection->RetirePriorTo ||
            DestCid->CID.Retired) {
            continue;
        }

        if (DestCid->CID.UsedLocally) {
            ReplaceRetiredCids = TRUE;
        }

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
    QUIC_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (!Path->DestCid->CID.Retired) {
            continue;
        }

        QUIC_CID_QUIC_LIST_ENTRY* NewDestCid = QuicConnGetUnusedDestCid(Connection);
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
            QUIC_DBG_ASSERT(i != 0);
            QuicPathRemove(Connection, i--);
            continue;
        }

        Path->DestCid = NewDestCid;
        Path->DestCid->CID.UsedLocally = TRUE;
        Path->InitiatedCidUpdate = TRUE;
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerSet(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type,
    _In_ uint64_t Delay
    )
{
    uint64_t NewExpirationTime = QuicTimeUs64() + MS_TO_US(Delay);

    //
    // Find the current and new index in the timer array for this timer.
    //

    uint32_t NewIndex = ARRAYSIZE(Connection->Timers);
    uint32_t CurIndex = 0;
    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Timers); ++i) {
        if (Connection->Timers[i].Type == Type) {
            CurIndex = i;
        }
        if (i < NewIndex &&
            NewExpirationTime < Connection->Timers[i].ExpirationTime) {
            NewIndex = i;
        }
    }

    if (NewIndex < CurIndex) {
        //
        // Need to move the timer forward in the array.
        //
        QuicMoveMemory(
            Connection->Timers + NewIndex + 1,
            Connection->Timers + NewIndex,
            sizeof(QUIC_CONN_TIMER_ENTRY) * (CurIndex - NewIndex));
        Connection->Timers[NewIndex].Type = Type;
        Connection->Timers[NewIndex].ExpirationTime = NewExpirationTime;

    } else if (NewIndex > CurIndex + 1) {
        //
        // Need to move the timer back in the array. Ignore changes that
        // wouldn't actually move it at all.
        //
        QuicMoveMemory(
            Connection->Timers + CurIndex,
            Connection->Timers + CurIndex + 1,
            sizeof(QUIC_CONN_TIMER_ENTRY) * (NewIndex - CurIndex - 1));
        Connection->Timers[NewIndex - 1].Type = Type;
        Connection->Timers[NewIndex - 1].ExpirationTime = NewExpirationTime;
    } else {
        //
        // Didn't move, so just update the expiration time.
        //
        Connection->Timers[CurIndex].ExpirationTime = NewExpirationTime;
        NewIndex = CurIndex;
    }

    if (NewIndex == 0) {
        //
        // The first timer was updated, so make sure the timer wheel is updated.
        //
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
    for (uint32_t i = 0;
        i < ARRAYSIZE(Connection->Timers) &&
            Connection->Timers[i].ExpirationTime != UINT64_MAX;
        ++i) {

        //
        // Find the correct timer (by type), invalidate it, and move it past all
        // the other valid timers.
        //

        if (Connection->Timers[i].Type == Type) {

            if (Connection->Timers[i].ExpirationTime != UINT64_MAX) {

                //
                // Find the end of the valid timers (if any more).
                //

                uint32_t j = i + 1;
                while (j < ARRAYSIZE(Connection->Timers) &&
                    Connection->Timers[j].ExpirationTime != UINT64_MAX) {
                    ++j;
                }

                if (j == i + 1) {
                    //
                    // No more valid timers, just invalidate this one and leave it
                    // where it is.
                    //
                    Connection->Timers[i].ExpirationTime = UINT64_MAX;
                } else {

                    //
                    // Move the valid timers forward and then put this timer after
                    // them.
                    //
                    QuicMoveMemory(
                        Connection->Timers + i,
                        Connection->Timers + i + 1,
                        sizeof(QUIC_CONN_TIMER_ENTRY) * (j - i - 1));
                    Connection->Timers[j - 1].Type = Type;
                    Connection->Timers[j - 1].ExpirationTime = UINT64_MAX;
                }

                if (i == 0) {
                    //
                    // The first timer was removed, so make sure the timer wheel is updated.
                    //
                    QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);
                }
            }

            break;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerExpired(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ uint64_t TimeNow
    )
{
    uint32_t i = 0;
    QUIC_CONN_TIMER_ENTRY Temp[QUIC_CONN_TIMER_COUNT];
    BOOLEAN FlushSendImmediate = FALSE;

    while (i < ARRAYSIZE(Connection->Timers) &&
           Connection->Timers[i].ExpirationTime <= TimeNow) {
        Connection->Timers[i].ExpirationTime = UINT64_MAX;
        ++i;
    }

    QUIC_DBG_ASSERT(i != 0);

    QuicCopyMemory(
        Temp,
        Connection->Timers,
        i * sizeof(QUIC_CONN_TIMER_ENTRY));
    if (i < ARRAYSIZE(Connection->Timers)) {
        QuicMoveMemory(
            Connection->Timers,
            Connection->Timers + i,
            (QUIC_CONN_TIMER_COUNT - i) * sizeof(QUIC_CONN_TIMER_ENTRY));
        QuicCopyMemory(
            Connection->Timers + (QUIC_CONN_TIMER_COUNT - i),
            Temp,
            i * sizeof(QUIC_CONN_TIMER_ENTRY));
    }

    for (uint32_t j = 0; j < i; ++j) {
        const char* TimerNames[] = {
            "PACING",
            "ACK_DELAY",
            "LOSS_DETECTION",
            "KEEP_ALIVE",
            "IDLE",
            "SHUTDOWN",
            "INVALID"
        };
        QuicTraceLogConnVerbose(
            TimerExpired,
            Connection,
            "%s timer expired",
            TimerNames[Temp[j].Type]);
        if (Temp[j].Type == QUIC_CONN_TIMER_ACK_DELAY) {
            QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                QUIC_CONN_TIMER_ACK_DELAY);
            QuicSendProcessDelayedAckTimer(&Connection->Send);
            FlushSendImmediate = TRUE;
        } else if (Temp[j].Type == QUIC_CONN_TIMER_PACING) {
            QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                QUIC_CONN_TIMER_PACING);
            FlushSendImmediate = TRUE;
        } else {
            QUIC_OPERATION* Oper;
            if ((Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_TIMER_EXPIRED)) != NULL) {
                Oper->TIMER_EXPIRED.Type = Temp[j].Type;
                QuicConnQueueOper(Connection, Oper);
            } else {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "expired timer operation",
                    0);
            }
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
    Connection->State.SendShutdownCompleteNotif = FALSE;
    if (Connection->State.HandleShutdown) {
        return;
    }
    Connection->State.HandleShutdown = TRUE;

    QuicTraceEvent(
        ConnShutdownComplete,
        "[conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.",
        Connection,
        Connection->State.ShutdownCompleteTimedOut);

    if (Connection->State.ExternalOwner == FALSE) {

        //
        // If the connection was never indicated to the application, then it
        // needs to be cleaned up now.
        //

        QuicConnCloseHandle(Connection);
        QuicConnUninitialize(Connection);
        QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);

    } else {

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        Event.SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown =
            !Connection->State.ShutdownCompleteTimedOut;

        QuicTraceLogConnVerbose(
            IndicateConnectionShutdownComplete,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
        (void)QuicConnIndicateEvent(Connection, &Event);

        Connection->ClientCallbackHandler = NULL;
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
    case QUIC_ERROR_CRYPTO_USER_CANCELED:           return QUIC_STATUS_USER_CANCELED;
    case QUIC_ERROR_CRYPTO_HANDSHAKE_FAILURE:       return QUIC_STATUS_HANDSHAKE_FAILURE;
    case QUIC_ERROR_CRYPTO_NO_APPLICATION_PROTOCOL: return QUIC_STATUS_ALPN_NEG_FAILURE;
    default:                                        return QUIC_STATUS_INTERNAL_ERROR;
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
            Connection->State.SendShutdownCompleteNotif = TRUE;
        }
        return;
    }

    if (!ClosedRemotely) {

        if ((Flags & QUIC_CLOSE_APPLICATION) &&
            Connection->Crypto.TlsState.WriteKey < QUIC_PACKET_KEY_1_RTT) {
            //
            // Application close can only happen if we are using 1-RTT keys.
            // Otherwise we have to send "user_canceled" TLS error code as a
            // connection close. Overwrite all application provided parameters.
            //
            Flags &= ~QUIC_CLOSE_APPLICATION;
            ErrorCode = QUIC_ERROR_CRYPTO_USER_CANCELED;
            RemoteReasonPhrase = NULL;
            RemoteReasonPhraseLength = 0;
        }
    }

    BOOLEAN ResultQuicStatus = !!(Flags & QUIC_CLOSE_QUIC_STATUS);

    BOOLEAN IsFirstCloseForConnection = TRUE;

    if (ClosedRemotely && !Connection->State.ClosedLocally) {

        //
        // Peer closed first.
        //

        if (!Connection->State.Connected && !QuicConnIsServer(Connection)) {
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
                max(15, US_TO_MS(Connection->Paths[0].SmoothedRtt * 2)));

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
            uint32_t Pto =
                US_TO_MS(QuicLossDetectionComputeProbeTimeout(
                    &Connection->LossDetection,
                    &Connection->Paths[0],
                    QUIC_CLOSE_PTO_COUNT));
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

        if (!QuicConnIsServer(Connection)) {
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
                max(15, US_TO_MS(Connection->Paths[0].SmoothedRtt * 2)));
        }

        IsFirstCloseForConnection = FALSE;
    }

    if (ClosedRemotely) {
        Connection->State.ClosedRemotely = TRUE;
    } else {
        Connection->State.ClosedLocally = TRUE;
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
            Connection->CloseErrorCode = ErrorCode;
        }

        if (Flags & QUIC_CLOSE_APPLICATION) {
            Connection->State.AppClosed = TRUE;
        }

        if (Flags & QUIC_CLOSE_SEND_NOTIFICATION &&
            Connection->State.ExternalOwner) {
            QuicConnIndicateShutdownBegin(Connection);
        }

        if (Connection->CloseReasonPhrase != NULL) {
            QUIC_FREE(Connection->CloseReasonPhrase);
            Connection->CloseReasonPhrase = NULL;
        }

        if (RemoteReasonPhraseLength != 0) {
            Connection->CloseReasonPhrase =
                QUIC_ALLOC_NONPAGED(RemoteReasonPhraseLength + 1);
            if (Connection->CloseReasonPhrase != NULL) {
                QuicCopyMemory(
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

    if (SilentClose ||
        (Connection->State.ClosedRemotely && Connection->State.ClosedLocally)) {
        Connection->State.ShutdownCompleteTimedOut = FALSE;
        Connection->State.SendShutdownCompleteNotif = TRUE;
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
    Connection->State.SendShutdownCompleteNotif = TRUE;
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
    QUIC_DBG_ASSERT(ErrorMsg == NULL || strlen(ErrorMsg) < UINT16_MAX);
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
        "[conn][%p] Version = %u",
        Connection,
        Connection->Stats.QuicVersion);

    switch (Connection->Stats.QuicVersion) {
    case QUIC_VERSION_DRAFT_27:
    case QUIC_VERSION_DRAFT_28:
    case QUIC_VERSION_DRAFT_29:
    case QUIC_VERSION_MS_1:
    default:
        Connection->State.HeaderProtectionEnabled = TRUE;
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnStart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_opt_z_ const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    )
{
    QUIC_STATUS Status;
    QUIC_PATH* Path = &Connection->Paths[0];
    QUIC_DBG_ASSERT(!QuicConnIsServer(Connection));

    if (Connection->State.ClosedLocally || Connection->State.Started) {
        if (ServerName != NULL) {
            QUIC_FREE(ServerName);
        }
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_TEL_ASSERT(Path->Binding == NULL);

    if (!Connection->State.RemoteAddressSet) {

        QUIC_DBG_ASSERT(ServerName != NULL);
        QuicAddrSetFamily(&Path->RemoteAddress, Family);

#ifdef QUIC_COMPARTMENT_ID
        BOOLEAN RevertCompartmentId = FALSE;
        QUIC_COMPARTMENT_ID PrevCompartmentId = QuicCompartmentIdGetCurrent();
        if (PrevCompartmentId != Connection->Session->CompartmentId) {
            Status = QuicCompartmentIdSetCurrent(Connection->Session->CompartmentId);
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
            QuicDataPathResolveAddress(
                MsQuicLib.Datapath,
                ServerName,
                &Path->RemoteAddress);

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

    QuicAddrSetPort(&Path->RemoteAddress, ServerPort);
    QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!SOCKADDR!",
        Connection,
        LOG_ADDR_LEN(Path->RemoteAddress),
        (const uint8_t*)&Path->RemoteAddress);

    //
    // Get the binding for the current local & remote addresses.
    //
    Status =
        QuicLibraryGetBinding(
            Connection->Session,
            Connection->State.ShareBinding,
            FALSE,
            Connection->State.LocalAddressSet ? &Path->LocalAddress : NULL,
            &Path->RemoteAddress,
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
                Connection->Registration->CidPrefixLength,
                Connection->Registration->CidPrefix);
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
        SourceCid->CID.Length,
        SourceCid->CID.Data);
    QuicListPushEntry(&Connection->SourceCids, &SourceCid->Link);

    if (!QuicBindingAddSourceConnectionID(Path->Binding, SourceCid)) {
        QuicLibraryReleaseBinding(Path->Binding);
        Path->Binding = NULL;
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Connection->State.LocalAddressSet = TRUE;
    QuicDataPathBindingGetLocalAddress(
        Path->Binding->DatapathBinding,
        &Path->LocalAddress);
    QuicTraceEvent(
        ConnLocalAddrAdded,
        "[conn][%p] New Local IP: %!SOCKADDR!",
        Connection,
        LOG_ADDR_LEN(Path->LocalAddress),
        (const uint8_t*)&Path->LocalAddress);

    //
    // Save the server name.
    //
    Connection->RemoteServerName = ServerName;
    ServerName = NULL;

    //
    // Start the handshake.
    //
    Status = QuicConnInitializeCrypto(Connection);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

Exit:

    if (ServerName != NULL) {
        QUIC_FREE(ServerName);
    }

    if (QUIC_FAILED(Status)) {
        QuicConnCloseLocally(
            Connection,
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
    QUIC_TEL_ASSERT(Connection->State.Started);

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
        Path->RttVariance = 0;
        Path->SmoothedRtt = MS_TO_US(Connection->Session->Settings.InitialRttMs);
    }

    for (uint32_t i = 0; i < ARRAYSIZE(Connection->Packets); ++i) {
        QUIC_DBG_ASSERT(Connection->Packets[i] != NULL);
        QuicPacketSpaceReset(Connection->Packets[i]);
    }

    QuicCongestionControlReset(&Connection->CongestionControl);
    QuicSendReset(&Connection->Send);
    QuicLossDetectionReset(&Connection->LossDetection);
    QuicCryptoReset(&Connection->Crypto, CompleteReset);
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
    uint32_t EncodedTransportParametersLength = 0;
    uint8_t* TicketBuffer = NULL;
    uint16_t AlpnLength = *(Connection->Crypto.TlsState.NegotiatedAlpn);
    const uint8_t* EncodedHSTP = NULL;

    if (Connection->HandshakeTP == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QUIC_TRANSPORT_PARAMETERS HSTPCopy = *Connection->HandshakeTP;
    HSTPCopy.Flags = HSTPCopy.Flags & (
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI);

    EncodedHSTP =
        QuicCryptoTlsEncodeTransportParameters(
            Connection,
            &HSTPCopy,
            &EncodedTransportParametersLength);
    if (EncodedHSTP == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    uint32_t TotalTicketLength =
        (uint32_t)(QuicVarIntSize(QUIC_TLS_RESUMPTION_TICKET_VERSION) +
        QuicVarIntSize(AlpnLength) +
        QuicVarIntSize(EncodedTransportParametersLength) +
        QuicVarIntSize(AppDataLength) +
        sizeof(QUIC_VERSION_LATEST) +
        AlpnLength +
        EncodedTransportParametersLength +
        AppDataLength);

    TicketBuffer = QUIC_ALLOC_NONPAGED(TotalTicketLength);
    if (TicketBuffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Server resumption ticket",
            TotalTicketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Encoded ticket format is as follows:
    //   Ticket Version (QUIC_VAR_INT) [1..4]
    //   Quic Version [4]
    //   Negotiated ALPN length (QUIC_VAR_INT) [1..2]
    //   Negotiated ALPN [...]
    //   Transport Parameters length (QUIC_VAR_INT) [1..2]
    //   Transport Parameters [...]
    //   App Ticket length (QUIC_VAR_INT) [1..2]
    //   App Ticket (omitted if length is zero) [...]
    //

    _Analysis_assume_(sizeof(*TicketBuffer) >= 8);
    uint8_t* TicketCursor = QuicVarIntEncode(QUIC_TLS_RESUMPTION_TICKET_VERSION, TicketBuffer);
    *(uint32_t*)TicketCursor = QuicByteSwapUint32(QUIC_VERSION_LATEST);
    TicketCursor += sizeof(QUIC_VERSION_LATEST);
    TicketCursor = QuicVarIntEncode(AlpnLength, TicketCursor);
    QuicCopyMemory(TicketCursor, Connection->Crypto.TlsState.NegotiatedAlpn + 1, AlpnLength);
    TicketCursor += AlpnLength;
    TicketCursor = QuicVarIntEncode(EncodedTransportParametersLength, TicketCursor);
    QuicCopyMemory(TicketCursor, EncodedHSTP, EncodedTransportParametersLength);
    TicketCursor += EncodedTransportParametersLength;
    TicketCursor = QuicVarIntEncode(AppDataLength, TicketCursor);
    if (AppDataLength > 0) {
        QuicCopyMemory(TicketCursor, AppResumptionData, AppDataLength);
        TicketCursor += AppDataLength;
    }
    QUIC_DBG_ASSERT(TicketCursor == TicketBuffer + TotalTicketLength);

    Status = QuicCryptoProcessAppData(&Connection->Crypto, TotalTicketLength, TicketBuffer);

Error:
    if (TicketBuffer != NULL) {
        QUIC_FREE(TicketBuffer);
    }

    if (EncodedHSTP != NULL) {
        QUIC_FREE(EncodedHSTP);
    }

    if (AppResumptionData != NULL) {
        QUIC_FREE(AppResumptionData);
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
    QUIC_TRANSPORT_PARAMETERS ResumedTP;
    if (QuicConnIsServer(Connection)) {
        uint16_t Offset = 0;
        QUIC_VAR_INT TicketVersion = 0, AlpnLength = 0, TPLength = 0, AppTicketLength = 0;
        if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &TicketVersion)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket version failed to decode");
            goto Error;
        }
        if (TicketVersion != QUIC_TLS_RESUMPTION_TICKET_VERSION) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket version unsupported");
            goto Error;
        }

        uint32_t QuicVersionHost = QuicByteSwapUint32(*(uint32_t*)(Ticket + Offset));
        if (!QuicIsVersionSupported(QuicVersionHost)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket for unsupported QUIC version");
            goto Error;
        }
        Offset += sizeof(QuicVersionHost);

        if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &AlpnLength)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket ALPN length failed to decode");
            goto Error;
        }
        if (QuicTlsAlpnFindInList(
                Connection->Session->AlpnListLength, Connection->Session->AlpnList,
                (uint8_t)AlpnLength, Ticket + Offset) == NULL) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket ALPN not present in ALPN list");
            goto Error;
        }
        Offset += (uint16_t)AlpnLength;

        if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &TPLength)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket TP length failed to decode");
            goto Error;
        }
        if (!QuicCryptoTlsDecodeTransportParameters(
                Connection,
                Ticket + Offset,
                (uint16_t)TPLength,
                &ResumedTP)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket TParams failed to decode");
            goto Error;
        }
        Offset += (uint16_t)TPLength;

        //
        // Validate resumed TP are <= current settings
        //
        if (ResumedTP.ActiveConnectionIdLimit > QUIC_ACTIVE_CONNECTION_ID_LIMIT ||
            ResumedTP.InitialMaxData > Connection->Send.MaxData ||
            ResumedTP.InitialMaxStreamDataBidiLocal > Connection->Session->Settings.StreamRecvWindowDefault ||
            ResumedTP.InitialMaxStreamDataBidiRemote > Connection->Session->Settings.StreamRecvWindowDefault ||
            ResumedTP.InitialMaxStreamDataUni > Connection->Session->Settings.StreamRecvWindowDefault ||
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

        if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &AppTicketLength)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket app data length failed to decode");
            goto Error;
        }

        QUIC_CONNECTION_EVENT Event = { 0, };
        Event.Type = QUIC_CONNECTION_EVENT_RESUMED;
        Event.RESUMED.ResumptionStateLength = (uint16_t)AppTicketLength;
        Event.RESUMED.ResumptionState = (AppTicketLength > 0) ? Ticket + Offset : NULL;
        ResumptionAccepted =
            QUIC_SUCCEEDED(QuicConnIndicateEvent(Connection, &Event));


        if (ResumptionAccepted) {
            QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app accepted resumption ticket",
                Connection);
        } else {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket rejected by server app");
        }

        QUIC_DBG_ASSERT(Offset + AppTicketLength == TicketLength);
    } else {
        //
        // TODO Client-side processing.
        // Until then, this shouldn't ever get called.
        //
        QUIC_FRE_ASSERT(FALSE);
    }

Error:

    return ResumptionAccepted;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCleanupServerResumptionState(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
    if (!Connection->State.ResumptionEnabled) {
        if (Connection->HandshakeTP != NULL) {
            QuicPoolFree(
                &MsQuicLib.PerProc[QuicLibraryGetCurrentPartition()].TransportParamPool,
                Connection->HandshakeTP);
            Connection->HandshakeTP = NULL;
        }

        QUIC_CRYPTO* Crypto = &Connection->Crypto;

        QuicTraceLogConnInfo(
            CryptoStateDiscard,
            Connection,
            "TLS state no longer needed");
        if (Crypto->TLS != NULL) {
            QuicTlsUninitialize(Crypto->TLS);
            Crypto->TLS = NULL;
        }
        if (Crypto->Initialized) {
            QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
            QuicRangeUninitialize(&Crypto->SparseAckRanges);
            QUIC_FREE(Crypto->TlsState.Buffer);
            Crypto->TlsState.Buffer = NULL;
            Crypto->Initialized = FALSE;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnInitializeCrypto(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_STATUS Status;
    BOOLEAN CryptoInitialized = FALSE;

    Status = QuicCryptoInitialize(&Connection->Crypto);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    CryptoInitialized = TRUE;

    if (!QuicConnIsServer(Connection)) {
        Status = QuicConnHandshakeConfigure(Connection, NULL);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (Connection->KeepAliveIntervalMs != 0) {
        //
        // Now that we are starting the connection, start the keep alive timer
        // if enabled.
        //
        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_KEEP_ALIVE,
            Connection->KeepAliveIntervalMs);
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (CryptoInitialized) {
            QuicCryptoUninitialize(&Connection->Crypto);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnHandshakeConfigure(
    _In_ QUIC_CONNECTION* Connection,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
{
    QUIC_STATUS Status;
    QUIC_TRANSPORT_PARAMETERS LocalTP = { 0 };

    QUIC_TEL_ASSERT(Connection->Session != NULL);

    QUIC_DBG_ASSERT(Connection->SourceCids.Next != NULL);
    const QUIC_CID_HASH_ENTRY* SourceCid =
        QUIC_CONTAINING_RECORD(
            Connection->SourceCids.Next,
            QUIC_CID_HASH_ENTRY,
            Link);

    QUIC_DBG_ASSERT(!QuicListIsEmpty(&Connection->DestCids));
    const QUIC_CID_QUIC_LIST_ENTRY* DestCid =
        QUIC_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_QUIC_LIST_ENTRY,
            Link);

    if (QuicConnIsServer(Connection)) {

        QUIC_TEL_ASSERT(SecConfig != NULL);

        LocalTP.InitialMaxStreamDataBidiLocal = Connection->Session->Settings.StreamRecvWindowDefault;
        LocalTP.InitialMaxStreamDataBidiRemote = Connection->Session->Settings.StreamRecvWindowDefault;
        LocalTP.InitialMaxStreamDataUni = Connection->Session->Settings.StreamRecvWindowDefault;
        LocalTP.InitialMaxData = Connection->Send.MaxData;
        LocalTP.MaxUdpPayloadSize =
            MaxUdpPayloadSizeFromMTU(
                QuicDataPathBindingGetLocalMtu(
                    Connection->Paths[0].Binding->DatapathBinding));
        LocalTP.ActiveConnectionIdLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
        LocalTP.Flags =
            QUIC_TP_FLAG_INITIAL_MAX_DATA |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
            QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE |
            QUIC_TP_FLAG_MAX_ACK_DELAY |
            QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;

        if (Connection->IdleTimeoutMs != 0) {
            LocalTP.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
            LocalTP.IdleTimeout = Connection->IdleTimeoutMs;
        }

        if (!Connection->Session->Settings.MigrationEnabled) {
            LocalTP.Flags |= QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION;
        }

        LocalTP.MaxAckDelay =
            Connection->MaxAckDelayMs + (uint32_t)MsQuicLib.TimerResolutionMs;

        LocalTP.Flags |= QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
        Status =
            QuicBindingGenerateStatelessResetToken(
                Connection->Paths[0].Binding,
                SourceCid->CID.Data,
                LocalTP.StatelessResetToken);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "QuicBindingGenerateStatelessResetToken");
            goto Error;
        }

        if (Connection->AckDelayExponent != QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT) {
            LocalTP.Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
            LocalTP.AckDelayExponent = Connection->AckDelayExponent;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            LocalTP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LocalTP.InitialMaxBidiStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount) {
            LocalTP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LocalTP.InitialMaxUniStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;
        }

        if (Connection->OrigDestCID != NULL) {
            QUIC_DBG_ASSERT(Connection->OrigDestCID->Length <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
            LocalTP.Flags |= QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID;
            LocalTP.OriginalDestinationConnectionIDLength = Connection->OrigDestCID->Length;
            QuicCopyMemory(
                LocalTP.OriginalDestinationConnectionID,
                Connection->OrigDestCID->Data,
                Connection->OrigDestCID->Length);
            QUIC_FREE(Connection->OrigDestCID);
            Connection->OrigDestCID = NULL;

            if (Connection->State.HandshakeUsedRetryPacket &&
                Connection->Stats.QuicVersion != QUIC_VERSION_DRAFT_27) {
                QUIC_DBG_ASSERT(SourceCid->Link.Next != NULL);
                const QUIC_CID_HASH_ENTRY* PrevSourceCid =
                    QUIC_CONTAINING_RECORD(
                        SourceCid->Link.Next,
                        QUIC_CID_HASH_ENTRY,
                        Link);

                LocalTP.Flags |= QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID;
                LocalTP.RetrySourceConnectionIDLength = PrevSourceCid->CID.Length;
                QuicCopyMemory(
                    LocalTP.RetrySourceConnectionID,
                    PrevSourceCid->CID.Data,
                    PrevSourceCid->CID.Length);
            }
        }

        if (Connection->Stats.QuicVersion != QUIC_VERSION_DRAFT_27) {
            LocalTP.Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
            LocalTP.InitialSourceConnectionIDLength = SourceCid->CID.Length;
            QuicCopyMemory(
                LocalTP.InitialSourceConnectionID,
                SourceCid->CID.Data,
                SourceCid->CID.Length);
        }

        if (Connection->Datagram.ReceiveEnabled) {
            LocalTP.Flags |= QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
            LocalTP.MaxDatagramFrameSize = QUIC_DEFAULT_MAX_DATAGRAM_LENGTH;
        }

        //
        // Persist the transport parameters used during handshake for resumption.
        // (if resumption is enabled)
        //
        if (Connection->HandshakeTP != NULL) {
            QUIC_DBG_ASSERT(Connection->State.ResumptionEnabled);
            *Connection->HandshakeTP = LocalTP;
        }

    } else {

        uint32_t InitialQuicVersion = QUIC_VERSION_LATEST;
        if (Connection->RemoteServerName != NULL &&
            QuicSessionServerCacheGetState(
                Connection->Session,
                Connection->RemoteServerName,
                &InitialQuicVersion,
                &Connection->PeerTransportParams,
                &SecConfig)) {

            QuicTraceLogConnVerbose(
                FoundCachedServerState,
                Connection,
                "Found server cached state");
            QuicConnProcessPeerTransportParameters(Connection, TRUE);
        }

        if (Connection->Stats.QuicVersion == 0) {
            //
            // Only initialize the version if not already done (by the
            // application layer).
            //
            Connection->Stats.QuicVersion = InitialQuicVersion;
        }
        QuicConnOnQuicVersionSet(Connection);

        if (SecConfig == NULL) {
            Status =
                QuicTlsClientSecConfigCreate(
                    Connection->ServerCertValidationFlags,
                    &SecConfig);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "QuicTlsClientSecConfigCreate");
                goto Error;
            }
        }

        LocalTP.InitialMaxStreamDataBidiLocal = Connection->Session->Settings.StreamRecvWindowDefault;
        LocalTP.InitialMaxStreamDataBidiRemote = Connection->Session->Settings.StreamRecvWindowDefault;
        LocalTP.InitialMaxStreamDataUni = Connection->Session->Settings.StreamRecvWindowDefault;
        LocalTP.InitialMaxData = Connection->Send.MaxData;
        LocalTP.MaxUdpPayloadSize =
            MaxUdpPayloadSizeFromMTU(
                QuicDataPathBindingGetLocalMtu(
                    Connection->Paths[0].Binding->DatapathBinding));
        LocalTP.ActiveConnectionIdLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
        LocalTP.Flags =
            QUIC_TP_FLAG_INITIAL_MAX_DATA |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
            QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE |
            QUIC_TP_FLAG_MAX_ACK_DELAY |
            QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;

        if (Connection->IdleTimeoutMs != 0) {
            LocalTP.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
            LocalTP.IdleTimeout = Connection->IdleTimeoutMs;
        }

        LocalTP.MaxAckDelay =
            Connection->MaxAckDelayMs + MsQuicLib.TimerResolutionMs;

        if (Connection->AckDelayExponent != QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT) {
            LocalTP.Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
            LocalTP.AckDelayExponent = Connection->AckDelayExponent;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            LocalTP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LocalTP.InitialMaxBidiStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount) {
            LocalTP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LocalTP.InitialMaxUniStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Datagram.ReceiveEnabled) {
            LocalTP.Flags |= QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
            LocalTP.MaxDatagramFrameSize = QUIC_DEFAULT_MAX_DATAGRAM_LENGTH;
        }

        if (Connection->Stats.QuicVersion != QUIC_VERSION_DRAFT_27) {
            LocalTP.Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
            LocalTP.InitialSourceConnectionIDLength = SourceCid->CID.Length;
            QuicCopyMemory(
                LocalTP.InitialSourceConnectionID,
                SourceCid->CID.Data,
                SourceCid->CID.Length);
        }

        //
        // Save the original CID for later validation in the TP.
        //
        Connection->OrigDestCID =
            QUIC_ALLOC_NONPAGED(
                sizeof(QUIC_CID) +
                DestCid->CID.Length);
        if (Connection->OrigDestCID == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "OrigDestCID",
                sizeof(QUIC_CID) + DestCid->CID.Length);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        Connection->OrigDestCID->Length = DestCid->CID.Length;
        QuicCopyMemory(
            Connection->OrigDestCID->Data,
            DestCid->CID.Data,
            DestCid->CID.Length);
    }

    Connection->State.Started = TRUE;
    Connection->Stats.Timing.Start = QuicTimeUs64();
    QuicTraceEvent(
        ConnHandshakeStart,
        "[conn][%p] Handshake start",
        Connection);

    Status =
        QuicCryptoInitializeTls(
            &Connection->Crypto,
            SecConfig,
            &LocalTP);
    QuicTlsSecConfigRelease(SecConfig); // No longer need local ref.

Error:

    return Status;
}

BOOLEAN
QuicConnValidateTransportParameterDraft27CIDs(
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->State.HandshakeUsedRetryPacket) {
        QUIC_DBG_ASSERT(!QuicConnIsServer(Connection));
        QUIC_DBG_ASSERT(Connection->OrigDestCID != NULL);
        //
        // If we received a Retry packet during the handshake, we (the client)
        // must validate that the server knew the original connection ID we sent,
        // so that we can be sure that no middle box injected the Retry packet.
        //
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer didn't provide the original destination CID in TP");
            return FALSE;
        } else if (Connection->PeerTransportParams.OriginalDestinationConnectionIDLength != Connection->OrigDestCID->Length) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer provided incorrect length of original destination CID in TP");
            return FALSE;
        } else if (
            memcmp(
                Connection->PeerTransportParams.OriginalDestinationConnectionID,
                Connection->OrigDestCID->Data,
                Connection->OrigDestCID->Length) != 0) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer provided incorrect original destination CID in TP");
            return FALSE;
        } else {
            QUIC_FREE(Connection->OrigDestCID);
            Connection->OrigDestCID = NULL;
        }

    } else if (!QuicConnIsServer(Connection)) {
        //
        // Per spec, the client must validate no original destination CID TP
        // was sent if no Retry occurred. No need to validate cached values, as
        // they don't apply to the current connection attempt.
        //
        if (!!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer provided the original destination CID in TP when no Retry occurred");
            return FALSE;
        }
    }

    return TRUE;
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

    const QUIC_CID_QUIC_LIST_ENTRY* DestCid =
        QUIC_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_QUIC_LIST_ENTRY,
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

    if (!QuicConnIsServer(Connection)) {
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Server didn't provide the original destination CID in TP");
            return FALSE;
        }
        QUIC_DBG_ASSERT(Connection->OrigDestCID);
        if (Connection->OrigDestCID->Length != Connection->PeerTransportParams.OriginalDestinationConnectionIDLength ||
            memcmp(Connection->OrigDestCID->Data, Connection->PeerTransportParams.OriginalDestinationConnectionID, Connection->OrigDestCID->Length) != 0) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Original destination CID from TP doesn't match");
            return FALSE;
        }
        QUIC_FREE(Connection->OrigDestCID);
        Connection->OrigDestCID = NULL;
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessPeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN FromCache
    )
{
    QuicTraceLogConnInfo(
        PeerTPSet,
        Connection,
        "Peer Transport Parameters Set");
    Connection->State.PeerTransportParameterValid = TRUE;

    if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        QUIC_DBG_ASSERT(Connection->PeerTransportParams.ActiveConnectionIdLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
        if (Connection->SourceCidLimit > Connection->PeerTransportParams.ActiveConnectionIdLimit) {
            Connection->SourceCidLimit = (uint8_t) Connection->PeerTransportParams.ActiveConnectionIdLimit;
        }
    } else {
        Connection->SourceCidLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT;
    }

    if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        QUIC_DBG_ASSERT(!QuicListIsEmpty(&Connection->DestCids));
        QUIC_DBG_ASSERT(!QuicConnIsServer(Connection));
        QUIC_CID_QUIC_LIST_ENTRY* DestCid =
            QUIC_CONTAINING_RECORD(
                Connection->DestCids.Flink,
                QUIC_CID_QUIC_LIST_ENTRY,
                Link);
        QuicCopyMemory(
            DestCid->ResetToken,
            Connection->PeerTransportParams.StatelessResetToken,
            QUIC_STATELESS_RESET_TOKEN_LENGTH);
        DestCid->CID.HasResetToken = TRUE;
    }

    if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        /* TODO - Platform independent logging
        if (QuicAddrGetFamily(&Connection->PeerTransportParams.PreferredAddress) == AF_INET) {
            QuicTraceLogConnInfo(
                PeerPreferredAddressV4,
                Connection,
                "Peer configured preferred address %!IPV4ADDR!:%d",
                &Connection->PeerTransportParams.PreferredAddress.Ipv4.sin_addr,
                QuicByteSwapUint16(Connection->PeerTransportParams.PreferredAddress.Ipv4.sin_port));
        } else {
            QuicTraceLogConnInfo(
                PeerPreferredAddressV6,
                Connection,
                "Peer configured preferred address [%!IPV6ADDR!]:%d",
                &Connection->PeerTransportParams.PreferredAddress.Ipv6.sin6_addr,
                QuicByteSwapUint16(Connection->PeerTransportParams.PreferredAddress.Ipv6.sin6_port));
        }*/

        //
        // TODO - Implement preferred address feature.
        //
    }

    if (!FromCache) {
        //
        // Version draft-28 and later fully validate all exchanged connection IDs.
        // Version draft-27 only validates in the Retry scenario.
        //
        if (Connection->Stats.QuicVersion == QUIC_VERSION_DRAFT_27) {
            if (!QuicConnValidateTransportParameterDraft27CIDs(Connection)) {
                goto Error;
            }
        } else {
            if (!QuicConnValidateTransportParameterCIDs(Connection)) {
                goto Error;
            }
        }
    }

    Connection->Send.PeerMaxData =
        Connection->PeerTransportParams.InitialMaxData;

    QuicStreamSetInitializeTransportParameters(
        &Connection->Streams,
        Connection->PeerTransportParams.InitialMaxBidiStreams,
        Connection->PeerTransportParams.InitialMaxUniStreams,
        !FromCache);

    QuicDatagramOnSendStateChanged(&Connection->Datagram);

    return;

Error:

    QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueRecvDatagrams(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RECV_DATAGRAM* DatagramChain,
    _In_ uint32_t DatagramChainLength
    )
{
    QUIC_RECV_DATAGRAM** DatagramChainTail = &DatagramChain->Next;
    DatagramChain->QueuedOnConnection = TRUE;
    QuicDataPathRecvDatagramToRecvPacket(DatagramChain)->AssignedToConnection = TRUE;
    while (*DatagramChainTail != NULL) {
        (*DatagramChainTail)->QueuedOnConnection = TRUE;
        QuicDataPathRecvDatagramToRecvPacket(*DatagramChainTail)->AssignedToConnection = TRUE;
        DatagramChainTail = &((*DatagramChainTail)->Next);
    }

    QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u UDP datagrams",
        DatagramChainLength);

    BOOLEAN QueueOperation;
    QuicDispatchLockAcquire(&Connection->ReceiveQueueLock);
    if (Connection->ReceiveQueueCount >= QUIC_MAX_RECEIVE_QUEUE_COUNT) {
        QueueOperation = FALSE;
    } else {
        *Connection->ReceiveQueueTail = DatagramChain;
        Connection->ReceiveQueueTail = DatagramChainTail;
        DatagramChain = NULL;
        QueueOperation = (Connection->ReceiveQueueCount == 0);
        Connection->ReceiveQueueCount += DatagramChainLength;
    }
    QuicDispatchLockRelease(&Connection->ReceiveQueueLock);

    if (DatagramChain != NULL) {
        QUIC_RECV_DATAGRAM* Datagram = DatagramChain;
        do {
            Datagram->QueuedOnConnection = FALSE;
            QuicPacketLogDrop(Connection, QuicDataPathRecvDatagramToRecvPacket(Datagram), "Max queue limit reached");
        } while ((Datagram = Datagram->Next) != NULL);
        QuicDataPathBindingReturnRecvDatagrams(DatagramChain);
        return;
    }

    if (QueueOperation) {
        QUIC_OPERATION* ConnOper =
            QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_FLUSH_RECV);
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
        QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_UNREACHABLE);
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

//
// Updates the current destination CID to the received packet's source CID, if
// not already equal. Only used during the handshake, on the client side.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnUpdateDestCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RECV_PACKET* const Packet
    )
{
    QUIC_DBG_ASSERT(!QuicConnIsServer(Connection));
    QUIC_DBG_ASSERT(!Connection->State.Connected);

    QUIC_DBG_ASSERT(!QuicListIsEmpty(&Connection->DestCids));
    QUIC_CID_QUIC_LIST_ENTRY* DestCid =
        QUIC_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_QUIC_LIST_ENTRY,
            Link);
    QUIC_DBG_ASSERT(Connection->Paths[0].DestCid == DestCid);

    if (Packet->SourceCidLen != DestCid->CID.Length ||
        memcmp(Packet->SourceCid, DestCid->CID.Data, DestCid->CID.Length) != 0) {

        // TODO - Only update for the first packet of each type (Initial and Retry).

        QuicTraceEvent(
            ConnDestCidRemoved,
            "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
            Connection,
            DestCid->CID.SequenceNumber,
            DestCid->CID.Length,
            DestCid->CID.Data);

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
            QuicCopyMemory(DestCid->CID.Data, Packet->SourceCid, DestCid->CID.Length);
        } else {
            //
            // There isn't enough room in the existing structure,
            // so we must allocate a new one and free the old one.
            //
            QuicListEntryRemove(&DestCid->Link);
            QUIC_FREE(DestCid);
            DestCid =
                QuicCidNewDestination(
                    Packet->SourceCidLen,
                    Packet->SourceCid);
            if (DestCid == NULL) {
                Connection->DestCidCount--;
                QuicConnFatalError(Connection, QUIC_STATUS_OUT_OF_MEMORY, "Out of memory");
                return FALSE;
            } else {
                Connection->Paths[0].DestCid = DestCid;
                DestCid->CID.UsedLocally = TRUE;
                QuicListInsertHead(&Connection->DestCids, &DestCid->Link);
            }
        }

        if (DestCid != NULL) {
            QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                Connection,
                DestCid->CID.SequenceNumber,
                DestCid->CID.Length,
                DestCid->CID.Data);
        }
    }

    return TRUE;
}

/*
//
// Version negotiation is removed for the first version of QUIC.
// When it is put back, it will probably be implemented as in this
// function.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvVerNeg(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RECV_PACKET* const Packet
    )
{
    uint32_t SupportedVersion = 0;

    // TODO - Validate the packet's SourceCid is equal to our DestCid.

    const uint32_t* ServerVersionList =
        (const uint32_t*)(
        Packet->VerNeg->DestCid +
        QuicCidDecodeLength(Packet->VerNeg->SourceCidLength) +
        QuicCidDecodeLength(Packet->VerNeg->DestCidLength));
    uint16_t ServerVersionListLength =
        (Packet->BufferLength - (uint16_t)((uint8_t*)ServerVersionList - Packet->Buffer)) / sizeof(uint32_t);

    //
    // Go through the list and make sure it doesn't include our originally
    // requested version. If it does, we are supposed to ignore it. Cache the
    // first supported version.
    //
    QuicTraceLogConnVerbose(
        RecvVerNeg,
        Connection,
        "Received Version Negotation:");
    for (uint16_t i = 0; i < ServerVersionListLength; i++) {

        QuicTraceLogConnVerbose(
            VerNegItem,
            Connection,
            "  Ver[%d]: 0x%x", i,
            QuicByteSwapUint32(ServerVersionList[i]));

        //
        // Check to see if this is the current version.
        //
        if (ServerVersionList[i] == Connection->Stats.QuicVersion) {
            QuicTraceLogConnVerbose(
                InvalidVerNeg,
                Connection,
                "Dropping version negotation that includes the current version");
            goto Exit;
        }

        //
        // Check to see if this is supported, if we haven't already found a
        // supported version.
        //
        if (SupportedVersion == 0 &&
            QuicIsVersionSupported(ServerVersionList[i])) {
            SupportedVersion = ServerVersionList[i];
        }
    }

    //
    // Did we find a supported version?
    //
    if (SupportedVersion != 0) {

        Connection->Stats.QuicVersion = SupportedVersion;
        QuicConnOnQuicVersionSet(Connection);

        //
        // Match found! Start connecting with selected version.
        //
        QuicConnRestart(Connection, TRUE);

    } else {

        //
        // No match! Connection failure.
        //
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT,
            QUIC_ERROR_VERSION_NEGOTIATION_ERROR,
            NULL);
    }

Exit:

    return;
}
*/

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvRetry(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RECV_PACKET* Packet
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
    // Decode and validate the Retry packet.
    //

    if (Packet->BufferLength - Packet->HeaderLength <= QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1) {
        QuicPacketLogDrop(Connection, Packet, "No room for Retry Token");
        return;
    }

    const QUIC_VERSION_INFO* VersionInfo = NULL;
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Packet->LH->Version) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }
    QUIC_FRE_ASSERT(VersionInfo != NULL);

    const uint8_t* Token = (Packet->Buffer + Packet->HeaderLength);
    uint16_t TokenLength = Packet->BufferLength - (Packet->HeaderLength + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1);

    QuicPacketLogHeader(
        Connection,
        TRUE,
        0,
        0,
        Packet->BufferLength,
        Packet->Buffer,
        0);

    QUIC_DBG_ASSERT(!QuicListIsEmpty(&Connection->DestCids));
    const QUIC_CID_QUIC_LIST_ENTRY* DestCid =
        QUIC_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_QUIC_LIST_ENTRY,
            Link);

    uint8_t CalculatedIntegrityValue[QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1];

    if (QUIC_FAILED(
        QuicPacketGenerateRetryIntegrity(
            VersionInfo->RetryIntegritySecret,
            DestCid->CID.Length,
            DestCid->CID.Data,
            Packet->BufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1,
            Packet->Buffer,
            CalculatedIntegrityValue))) {
        QuicPacketLogDrop(Connection, Packet, "Failed to generate integrity field");
        return;
    }

    if (memcmp(
            CalculatedIntegrityValue,
            Packet->Buffer + (Packet->BufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1),
            QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1) != 0) {
        QuicPacketLogDrop(Connection, Packet, "Invalid integrity field");
        return;
    }

    //
    // Cache the Retry token.
    //

    Connection->Send.InitialToken = QUIC_ALLOC_PAGED(TokenLength);
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

    QUIC_DBG_ASSERT(!QuicListIsEmpty(&Connection->DestCids));
    DestCid =
        QUIC_CONTAINING_RECORD(
            Connection->DestCids.Flink,
            QUIC_CID_QUIC_LIST_ENTRY,
            Link);

    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
        QuicPacketKeyCreateInitial(
            QuicConnIsServer(Connection),
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
    _In_ QUIC_RECV_PACKET* Packet
    )
{
    if (Packet->KeyType > Connection->Crypto.TlsState.ReadKey) {

        //
        // We don't have the necessary key yet so try to defer the packet until
        // we get the key.
        //

        if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT &&
            Connection->Crypto.TlsState.EarlyDataState != QUIC_TLS_EARLY_DATA_UNKNOWN) {
            //
            // We don't have the 0-RTT key, but we aren't in an unknown
            // "early data" state, so it must be rejected/unsupported. Just drop
            // the packets.
            //
            QUIC_DBG_ASSERT(Connection->Crypto.TlsState.EarlyDataState != QUIC_TLS_EARLY_DATA_ACCEPTED);
            QuicPacketLogDrop(Connection, Packet, "0-RTT not currently accepted");

        } else {
            QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
            QUIC_PACKET_SPACE* Packets = Connection->Packets[EncryptLevel];
            if (Packets->DeferredDatagramsCount == QUIC_MAX_PENDING_DATAGRAMS) {
                //
                // We already have too many packets queued up. Just drop this
                // one.
                //
                QuicPacketLogDrop(Connection, Packet, "Max deferred datagram count reached");

            } else {
                QuicTraceLogConnVerbose(
                    DeferDatagram,
                    Connection,
                    "Deferring datagram (type=%hu)",
                    Packet->KeyType);

                Packets->DeferredDatagramsCount++;
                Packet->DecryptionDeferred = TRUE;

                //
                // Add it to the list of pending packets that are waiting on a
                // key to decrypt with.
                //
                QUIC_RECV_DATAGRAM** Tail = &Packets->DeferredDatagrams;
                while (*Tail != NULL) {
                    Tail = &((*Tail)->Next);
                }
                *Tail = QuicDataPathRecvPacketToRecvDatagram(Packet);
                (*Tail)->Next = NULL;
            }
        }

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
    _In_ QUIC_RECV_PACKET* Packet,
    _Out_writes_all_(16) uint8_t* Cipher
    )
{
    //
    // Check invariants and packet version.
    //

    if (!Packet->ValidatedHeaderInv &&
        !QuicPacketValidateInvariant(Connection, Packet, Connection->State.ShareBinding)) {
        return FALSE;
    }

    if (!Packet->IsShortHeader) {
        if (Packet->Invariant->LONG_HDR.Version != Connection->Stats.QuicVersion) {
            if (Packet->Invariant->LONG_HDR.Version == QUIC_VERSION_VER_NEG) {
                Connection->Stats.VersionNegotiation = TRUE;

                //
                // Version negotiation is removed for the first version of QUIC.
                // When it is put back, it will probably be implemented as in this
                // function:
                // QuicConnRecvVerNeg(Connection, Packet);
                //
                // For now, since there is a single version, receiving
                // a version negotation packet means there is a version
                // mismatch, so abandon the connect attempt.
                //

                QuicConnCloseLocally(
                    Connection,
                    QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                    (uint64_t)QUIC_STATUS_VER_NEG_ERROR,
                    NULL);
            } else {
                QuicPacketLogDropWithValue(Connection, Packet, "Invalid version", QuicByteSwapUint32(Packet->Invariant->LONG_HDR.Version));
            }
            return FALSE;
        }
    } else {
        if (!QuicIsVersionSupported(Connection->Stats.QuicVersion)) {
            QuicPacketLogDrop(Connection, Packet, "SH packet during version negotiation");
            return FALSE;
        }
    }

    QUIC_FRE_ASSERT(QuicIsVersionSupported(Connection->Stats.QuicVersion));

    //
    // Begin non-version-independent logic. When future versions are supported,
    // there may be some switches based on packet version.
    //

    if (!Packet->IsShortHeader) {
        if (Packet->LH->Type == QUIC_RETRY) {
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
                &TokenLength)) {
            return FALSE;
        }

        QUIC_PATH* Path = &Connection->Paths[0];
        if (!Path->IsPeerValidated && Packet->ValidToken) {

            QUIC_DBG_ASSERT(TokenBuffer == NULL);
            QuicPacketDecodeRetryTokenV1(Packet, &TokenBuffer, &TokenLength);
            QUIC_DBG_ASSERT(TokenLength == sizeof(QUIC_RETRY_TOKEN_CONTENTS));

            QUIC_RETRY_TOKEN_CONTENTS Token;
            if (!QuicRetryTokenDecrypt(Packet, TokenBuffer, &Token)) {
                QUIC_DBG_ASSERT(FALSE); // Was already decrypted sucessfully once.
                QuicPacketLogDrop(Connection, Packet, "Retry token decrypt failure");
                return FALSE;
            }

            QUIC_DBG_ASSERT(Token.Encrypted.OrigConnIdLength <= sizeof(Token.Encrypted.OrigConnId));
            QUIC_DBG_ASSERT(QuicAddrCompare(&Path->RemoteAddress, &Token.Encrypted.RemoteAddress));
            QUIC_DBG_ASSERT(Connection->OrigDestCID == NULL);

            Connection->OrigDestCID =
                QUIC_ALLOC_NONPAGED(
                    sizeof(QUIC_CID) +
                    Token.Encrypted.OrigConnIdLength);
            if (Connection->OrigDestCID == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + Token.Encrypted.OrigConnIdLength);
                return FALSE;
            }

            Connection->OrigDestCID->Length = Token.Encrypted.OrigConnIdLength;
            QuicCopyMemory(
                Connection->OrigDestCID->Data,
                Token.Encrypted.OrigConnId,
                Token.Encrypted.OrigConnIdLength);
            Connection->State.HandshakeUsedRetryPacket = TRUE;

            QuicPathSetValid(Connection, Path, QUIC_PATH_VALID_INITIAL_TOKEN);

        } else if (
            Connection->Stats.QuicVersion != QUIC_VERSION_DRAFT_27 &&
            Connection->OrigDestCID == NULL) {

            Connection->OrigDestCID =
                QUIC_ALLOC_NONPAGED(
                    sizeof(QUIC_CID) +
                    Packet->DestCidLen);
            if (Connection->OrigDestCID == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + Packet->DestCidLen);
                return FALSE;
            }

            Connection->OrigDestCID->Length = Packet->DestCidLen;
            QuicCopyMemory(
                Connection->OrigDestCID->Data,
                Packet->DestCid,
                Packet->DestCidLen);

        }

        Packet->KeyType = QuicPacketTypeToKeyType(Packet->LH->Type);

    } else {

        if (!Packet->ValidatedHeaderVer &&
            !QuicPacketValidateShortHeaderV1(Connection, Packet)) {
            return FALSE;
        }

        Packet->KeyType = QUIC_PACKET_KEY_1_RTT;
    }

    if (Connection->State.EncryptionEnabled &&
        Connection->State.HeaderProtectionEnabled &&
        Packet->PayloadLength < 4 + QUIC_HP_SAMPLE_LENGTH) {
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
    QuicCopyMemory(
        Cipher,
        Packet->Buffer + Packet->HeaderLength + 4,
        QUIC_HP_SAMPLE_LENGTH);

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
    _In_ QUIC_RECV_PACKET* Packet,
    _In_reads_(16) const uint8_t* HpMask
    )
{
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderInv);
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderVer);
    QUIC_DBG_ASSERT(Packet->HeaderLength <= Packet->BufferLength);
    QUIC_DBG_ASSERT(Packet->PayloadLength <= Packet->BufferLength);
    QUIC_DBG_ASSERT(Packet->HeaderLength + Packet->PayloadLength <= Packet->BufferLength);

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
        ((uint8_t*)Packet->Buffer)[0] ^= HpMask[0] & 0x1f; // Only the first 5 bits
        CompressedPacketNumberLength = Packet->SH->PnLength + 1;
    } else {
        ((uint8_t*)Packet->Buffer)[0] ^= HpMask[0] & 0x0f; // Only the first 4 bits
        CompressedPacketNumberLength = Packet->LH->PnLength + 1;
    }

    QUIC_DBG_ASSERT(CompressedPacketNumberLength >= 1 && CompressedPacketNumberLength <= 4);
    QUIC_DBG_ASSERT(Packet->HeaderLength + CompressedPacketNumberLength <= Packet->BufferLength);

    //
    // Decrypt the packet number now that we have the length.
    //
    for (uint8_t i = 0; i < CompressedPacketNumberLength; i++) {
        ((uint8_t*)Packet->Buffer)[Packet->HeaderLength + i] ^= HpMask[1 + i];
    }

    //
    // Decode the packet number into the compressed packet number. The
    // compressed packet number only represents the least significant N bytes of
    // the true packet number.
    //

    uint64_t CompressedPacketNumber = 0;
    QuicPktNumDecode(
        CompressedPacketNumberLength,
        Packet->Buffer + Packet->HeaderLength,
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

    QUIC_DBG_ASSERT(Packet->IsShortHeader || Packet->LH->Type != QUIC_RETRY);

    //
    // Ensure minimum encrypted payload length.
    //
    if (Connection->State.EncryptionEnabled &&
        Packet->PayloadLength < QUIC_ENCRYPTION_OVERHEAD) {
        QuicPacketLogDrop(Connection, Packet, "Payload length less than encryption tag");
        return FALSE;
    }

    QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    if (Packet->IsShortHeader && EncryptLevel == QUIC_ENCRYPT_LEVEL_1_RTT &&
        Packet->SH->KeyPhase != PacketSpace->CurrentKeyPhase) {
        if (PacketSpace->AwaitingKeyPhaseConfirmation ||
            Packet->PacketNumber < PacketSpace->ReadKeyPhaseStartPacketNumber) {
            //
            // The packet doesn't match our current key phase and we're awaiting
            // confirmation of our current key phase or the packet number is less
            // than the start of the current key phase, so this is likely using
            // the old key phase.
            //
            QuicTraceLogConnVerbose(
                DecryptOldKey,
                Connection,
                "Using old key to decrypt");
            QUIC_DBG_ASSERT(Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT_OLD] != NULL);
            QUIC_DBG_ASSERT(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT_OLD] != NULL);
            Packet->KeyType = QUIC_PACKET_KEY_1_RTT_OLD;
        } else {
            //
            // The packet doesn't match our key phase, and we're not awaiting
            // confirmation of a key phase change, or this is a newer packet
            // number, so most likely using a new key phase. Update the keys
            // and try it out.
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
    _In_ QUIC_RECV_PACKET* Packet
    )
{
    QUIC_DBG_ASSERT(Packet->BufferLength >= Packet->HeaderLength + Packet->PayloadLength);

    const uint8_t* Payload = Packet->Buffer + Packet->HeaderLength;

    //
    // We need to copy the end of the packet before trying decryption, as a
    // failed decryption trashes the stateless reset token.
    //
    BOOLEAN CanCheckForStatelessReset = FALSE;
    uint8_t PacketResetToken[QUIC_STATELESS_RESET_TOKEN_LENGTH];
    if (!QuicConnIsServer(Connection) &&
        Packet->IsShortHeader &&
        Packet->HeaderLength + Packet->PayloadLength >= QUIC_MIN_STATELESS_RESET_PACKET_LENGTH) {
        CanCheckForStatelessReset = TRUE;
        QuicCopyMemory(
            PacketResetToken,
            Payload + Packet->PayloadLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
            QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }

    uint8_t Iv[QUIC_IV_LENGTH];
    QuicCryptoCombineIvAndPacketNumber(
        Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->Iv,
        (uint8_t*) &Packet->PacketNumber,
        Iv);

    //
    // Decrypt the payload with the appropriate key.
    //
    if (Connection->State.EncryptionEnabled &&
        QUIC_FAILED(
        QuicDecrypt(
            Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->PacketKey,
            Iv,
            Packet->HeaderLength,   // HeaderLength
            Packet->Buffer,         // Header
            Packet->PayloadLength,  // BufferLength
            (uint8_t*)Payload))) {  // Buffer

        //
        // Check for a stateless reset packet.
        //
        if (CanCheckForStatelessReset) {
            for (QUIC_LIST_ENTRY* Entry = Connection->DestCids.Flink;
                    Entry != &Connection->DestCids;
                    Entry = Entry->Flink) {
                //
                // Loop through all our stored stateless reset tokens to see if
                // we have a match.
                //
                QUIC_CID_QUIC_LIST_ENTRY* DestCid =
                    QUIC_CONTAINING_RECORD(
                        Entry,
                        QUIC_CID_QUIC_LIST_ENTRY,
                        Link);
                if (DestCid->CID.HasResetToken &&
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
                Packet->Buffer,
                Connection->Stats.QuicVersion);
        }
        Connection->Stats.Recv.DecryptionFailures++;
        QuicPacketLogDrop(Connection, Packet, "Decryption failure");

        return FALSE;
    }

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
    if (Connection->State.EncryptionEnabled) {
        Packet->PayloadLength -= QUIC_ENCRYPTION_OVERHEAD;
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
                Packet->BufferLength,
                Packet->Buffer,
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
            Packet->Buffer,
            Connection->Stats.QuicVersion);
        QuicFrameLogAll(
            Connection,
            TRUE,
            Packet->PacketNumber,
            Packet->HeaderLength + Packet->PayloadLength,
            Packet->Buffer,
            Packet->HeaderLength);
    }

    QuicTraceEvent(
        ConnPacketRecv,
        "[conn][%p][RX][%llu] %c (%hd bytes)",
        Connection,
        Packet->PacketNumber,
        Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1),
        Packet->HeaderLength + Packet->PayloadLength);

    //
    // Process any connection ID updates as necessary.
    //

    if (!Packet->IsShortHeader) {
        switch (Packet->LH->Type) {
        case QUIC_INITIAL:
            if (!Connection->State.Connected &&
                !QuicConnIsServer(Connection) &&
                !QuicConnUpdateDestCid(Connection, Packet)) {
                //
                // Client side needs to respond to the server's new source
                // connection ID that is received in the first Initial packet.
                //
                return FALSE;
            }
            break;

        case QUIC_0_RTT_PROTECTED:
            QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
            Packet->EncryptedWith0Rtt = TRUE;
            break;

        default:
            break;
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
            Packet->PacketNumber < PacketSpace->ReadKeyPhaseStartPacketNumber) {
            //
            // If this packet is the current key phase, but has an earlier packet
            // number than this key phase's start, update the key phase start.
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
    _In_ QUIC_RECV_PACKET* Packet
    )
{
    BOOLEAN AckPacketImmediately = FALSE; // Allows skipping delayed ACK timer.
    BOOLEAN UpdatedFlowControl = FALSE;
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    BOOLEAN Closed = Connection->State.ClosedLocally || Connection->State.ClosedRemotely;
    const uint8_t* Payload = Packet->Buffer + Packet->HeaderLength;
    uint16_t PayloadLength = Packet->PayloadLength;

    uint16_t Offset = 0;
    while (Offset < PayloadLength) {

        //
        // Read the frame type.
        //
        QUIC_FRAME_TYPE FrameType = Payload[Offset];
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
                    Connection, FrameType,
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
                    FrameType,
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

        Offset += sizeof(uint8_t);

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
            AckPacketImmediately = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_1: {
            BOOLEAN InvalidAckFrame;
            if (!QuicLossDetectionProcessAckFrame(
                    &Connection->LossDetection,
                    Path,
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
                AckPacketImmediately = TRUE;
            } else if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                return FALSE;
            } else {
                if (Status != QUIC_STATUS_INVALID_STATE) {
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

            AckPacketImmediately = TRUE;
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
        case QUIC_FRAME_STREAM_DATA_BLOCKED: {
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

            AckPacketImmediately = TRUE;

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

            BOOLEAN ProtocolViolation;
            QUIC_STREAM* Stream =
                QuicStreamSetGetStreamForPeer(
                    &Connection->Streams,
                    StreamId,
                    Packet->EncryptedWith0Rtt,
                    PeerOriginatedStream,
                    &ProtocolViolation);

            if (Stream) {
                QUIC_STATUS Status =
                    QuicStreamRecv(
                        Stream,
                        Packet->EncryptedWith0Rtt,
                        FrameType,
                        PayloadLength,
                        Payload,
                        &Offset,
                        &UpdatedFlowControl);
                if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                    return FALSE;
                } else if (QUIC_FAILED(Status)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }

                QuicStreamRelease(Stream, QUIC_STREAM_REF_LOOKUP);

            } else if (ProtocolViolation) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Getting stream from ID");
                QuicConnTransportError(Connection, QUIC_ERROR_STREAM_STATE_ERROR);
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
                    FrameType, StreamId);
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

            AckPacketImmediately = TRUE;
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

            AckPacketImmediately = TRUE;
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

            AckPacketImmediately = TRUE;
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
            AckPacketImmediately = TRUE;

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS; // TODO - Uni/Bidi
            QuicTraceLogConnVerbose(
                IndicatePeerNeedStreams,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS");
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
                QUIC_CID_QUIC_LIST_ENTRY* DestCid =
                    QuicCidNewDestination(Frame.Length, Frame.Buffer);
                if (DestCid == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "new DestCid",
                        sizeof(QUIC_CID_QUIC_LIST_ENTRY) + Frame.Length);
                    return FALSE;
                }

                DestCid->CID.HasResetToken = TRUE;
                DestCid->CID.SequenceNumber = Frame.Sequence;
                QuicCopyMemory(
                    DestCid->ResetToken,
                    Frame.Buffer + Frame.Length,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH);
                QuicTraceEvent(
                    ConnDestCidAdded,
                    "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                    Connection,
                    DestCid->CID.SequenceNumber,
                    DestCid->CID.Length,
                    DestCid->CID.Data);
                QuicListInsertTail(&Connection->DestCids, &DestCid->Link);
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
                    QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                    return FALSE;
                }
            }

            if (ReplaceRetiredCids && !QuicConnReplaceRetiredCids(Connection)) {
                return FALSE;
            }

            AckPacketImmediately = TRUE;
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
                QUIC_FREE(SourceCid);
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

            AckPacketImmediately = TRUE;
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
            QuicCopyMemory(Path->Response, Frame.Data, sizeof(Frame.Data));
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_RESPONSE);

            AckPacketImmediately = TRUE;
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

            QUIC_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
            for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
                QUIC_PATH* TempPath = &Connection->Paths[i];
                if (!TempPath->IsPeerValidated &&
                    !memcmp(Frame.Data, TempPath->Challenge, sizeof(Frame.Data))) {
                    QuicPathSetValid(Connection, TempPath, QUIC_PATH_VALID_PATH_RESPONSE);
                    break;
                }
            }

            // TODO - Do we care if there was no match? Possible fishing expedition?

            AckPacketImmediately = TRUE;
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
            QuicConnTryClose(
                Connection,
                Flags,
                Frame.ErrorCode,
                Frame.ReasonPhrase,
                (uint16_t)Frame.ReasonPhraseLength);

            AckPacketImmediately = TRUE;
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
                QuicCryptoHandshakeConfirmed(&Connection->Crypto);
            }

            AckPacketImmediately = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1: {
            if (!Connection->Datagram.ReceiveEnabled) {
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
            AckPacketImmediately = TRUE;
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

    if (!QuicConnIsServer(Connection) &&
        !Connection->State.GotFirstServerResponse) {
        Connection->State.GotFirstServerResponse = TRUE;
    }

    if (UpdatedFlowControl) {
        QuicConnLogOutFlowStats(Connection);
    }

    if (Connection->State.HandleShutdown || Connection->State.HandleClosed) {
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

        QuicAckTrackerAckPacket(
            &Connection->Packets[EncryptLevel]->AckTracker,
            Packet->PacketNumber,
            AckPacketImmediately);
    }

    Packet->CompletelyValid = TRUE;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvPostProcessing(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH** Path,
    _In_ QUIC_RECV_PACKET* Packet
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
            if (SourceCid->CID.IsInitial) {
                if (QuicConnIsServer(Connection) && SourceCid->Link.Next != NULL) {
                    QUIC_CID_HASH_ENTRY* NextSourceCid =
                        QUIC_CONTAINING_RECORD(
                            SourceCid->Link.Next,
                            QUIC_CID_HASH_ENTRY,
                            Link);
                    if (NextSourceCid->CID.IsInitial) {
                        //
                        // The client has started using our new initial CID. We
                        // can discard the old (client chosen) one now.
                        //
                        SourceCid->Link.Next = NextSourceCid->Link.Next;
                        QUIC_DBG_ASSERT(!NextSourceCid->CID.IsInLookupTable);
                        QuicTraceEvent(
                            ConnSourceCidRemoved,
                            "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                            Connection,
                            NextSourceCid->CID.SequenceNumber,
                            NextSourceCid->CID.Length,
                            NextSourceCid->CID.Data);
                        QUIC_FREE(NextSourceCid);
                    }
                }
            } else {
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

            if (PeerUpdatedCid) {
                (*Path)->DestCid = QuicConnGetUnusedDestCid(Connection);
                if ((*Path)->DestCid == NULL) {
                    (*Path)->GotValidPacket = FALSE; // Don't have a new CID to use!!!
                    return;
                }
            }

            (*Path)->SendChallenge = TRUE;
            (*Path)->PathValidationStartTime = QuicTimeUs32();

            //
            // NB: The path challenge payload is initialized here and reused
            // for any retransmits, but the spec requires a new payload in each
            // path challenge.
            //
            QuicRandom(sizeof((*Path)->Challenge), (*Path)->Challenge);

            //
            // We need to also send a challenge on the active path to make sure
            // it is still good.
            //
            QUIC_DBG_ASSERT(Connection->Paths[0].IsActive);
            if (Connection->Paths[0].IsPeerValidated) { // Not already doing peer validation.
                Connection->Paths[0].IsPeerValidated = FALSE;
                Connection->Paths[0].SendChallenge = TRUE;
                Connection->Paths[0].PathValidationStartTime = QuicTimeUs32();
                QuicRandom(sizeof(Connection->Paths[0].Challenge), Connection->Paths[0].Challenge);
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
            "[conn][%p] New Remote IP: %!SOCKADDR!",
            Connection,
            LOG_ADDR_LEN(Connection->Paths[0].RemoteAddress),
            (const uint8_t*)&Connection->Paths[0].RemoteAddress); // TODO - Addr removed event?

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
        Event.PEER_ADDRESS_CHANGED.Address = &(*Path)->RemoteAddress;
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
    _In_reads_(BatchCount) QUIC_RECV_DATAGRAM** Datagrams,
    _In_reads_(BatchCount * QUIC_HP_SAMPLE_LENGTH)
        const uint8_t* Cipher,
    _Inout_ QUIC_RECEIVE_PROCESSING_STATE* RecvState
    )
{
    uint8_t HpMask[QUIC_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];

    QUIC_DBG_ASSERT(BatchCount > 0 && BatchCount <= QUIC_MAX_CRYPTO_BATCH_COUNT);
    QUIC_RECV_PACKET* Packet = QuicDataPathRecvDatagramToRecvPacket(Datagrams[0]);

    QuicTraceLogConnVerbose(
        UdpRecvBatch,
        Connection,
        "Batch Recv %u UDP datagrams",
        BatchCount);

    if (Connection->Crypto.TlsState.ReadKeys[Packet->KeyType] == NULL) {
        QuicPacketLogDrop(Connection, Packet, "Key no longer accepted (batch)");
        return;
    }

    if (Connection->State.EncryptionEnabled &&
        Connection->State.HeaderProtectionEnabled) {
        if (QUIC_FAILED(
            QuicHpComputeMask(
                Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->HeaderKey,
                BatchCount,
                Cipher,
                HpMask))) {
            QuicPacketLogDrop(Connection, Packet, "Failed to compute HP mask");
            return;
        }
    } else {
        QuicZeroMemory(HpMask, BatchCount * QUIC_HP_SAMPLE_LENGTH);
    }

    for (uint8_t i = 0; i < BatchCount; ++i) {
        QUIC_DBG_ASSERT(Datagrams[i]->Allocated);
        Packet = QuicDataPathRecvDatagramToRecvPacket(Datagrams[i]);
        if (QuicConnRecvPrepareDecrypt(
                Connection, Packet, HpMask + i * QUIC_HP_SAMPLE_LENGTH) &&
            QuicConnRecvDecryptAndAuthenticate(Connection, Path, Packet) &&
            QuicConnRecvFrames(Connection, Path, Packet)) {

            QuicConnRecvPostProcessing(Connection, &Path, Packet);
            RecvState->ResetIdleTimeout |= Packet->CompletelyValid;

            if (Path->IsActive && !Path->PartitionUpdated && Packet->CompletelyValid &&
                (Datagrams[i]->PartitionIndex % MsQuicLib.PartitionCount) != RecvState->PartitionIndex) {
                RecvState->PartitionIndex = Datagrams[i]->PartitionIndex % MsQuicLib.PartitionCount;
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

        } else {
            Connection->Stats.Recv.DroppedPackets++;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvDatagrams(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RECV_DATAGRAM* DatagramChain,
    _In_ uint32_t DatagramChainCount,
    _In_ BOOLEAN IsDeferred
    )
{
    QUIC_RECV_DATAGRAM* ReleaseChain = NULL;
    QUIC_RECV_DATAGRAM** ReleaseChainTail = &ReleaseChain;
    uint32_t ReleaseChainCount = 0;
    QUIC_RECEIVE_PROCESSING_STATE RecvState = { FALSE, FALSE, 0 };
    RecvState.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);
    if (Connection->Registration &&
        QuicRegistrationIsSplitPartitioning(Connection->Registration)) {
        QUIC_DBG_ASSERT(RecvState.PartitionIndex != 0);
        RecvState.PartitionIndex -= QUIC_MAX_THROUGHPUT_PARTITION_OFFSET;
    }

    UNREFERENCED_PARAMETER(DatagramChainCount);

    QUIC_PASSIVE_CODE();

    if (IsDeferred) {
        QuicTraceLogConnVerbose(
            UdpRecvDeferred,
            Connection,
            "Recv %u deferred UDP datagrams",
            DatagramChainCount);
    } else {
        QuicTraceLogConnVerbose(
            UdpRecv,
            Connection,
            "Recv %u UDP datagrams",
            DatagramChainCount);
    }

    //
    // Iterate through each QUIC packet in the chain of UDP datagrams until an
    // error is encountered or we run out of buffer.
    //

    uint8_t BatchCount = 0;
    QUIC_RECV_DATAGRAM* Batch[QUIC_MAX_CRYPTO_BATCH_COUNT];
    uint8_t Cipher[QUIC_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];
    QUIC_PATH* CurrentPath = NULL;

    QUIC_RECV_DATAGRAM* Datagram;
    while ((Datagram = DatagramChain) != NULL) {
        QUIC_DBG_ASSERT(Datagram->Allocated);
        QUIC_DBG_ASSERT(Datagram->QueuedOnConnection);
        DatagramChain = Datagram->Next;
        Datagram->Next = NULL;

        QUIC_RECV_PACKET* Packet =
            QuicDataPathRecvDatagramToRecvPacket(Datagram);
        QUIC_DBG_ASSERT(Packet != NULL);

        QUIC_DBG_ASSERT(Packet->DecryptionDeferred == IsDeferred);
        Packet->DecryptionDeferred = FALSE;

        QUIC_PATH* DatagramPath = QuicConnGetPathForDatagram(Connection, Datagram);
        if (DatagramPath == NULL) {
            QuicPacketLogDrop(Connection, Packet, "Max paths already tracked");
            goto Drop;
        }

        if (DatagramPath != CurrentPath) {
            if (BatchCount != 0) {
                //
                // This datagram is from a different path than the current
                // batch. Flush the current batch before continuing.
                //
                QUIC_DBG_ASSERT(CurrentPath != NULL);
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
            Connection->Stats.Recv.TotalBytes += Datagram->BufferLength;
            QuicConnLogInFlowStats(Connection);

            if (!CurrentPath->IsPeerValidated) {
                QuicPathIncrementAllowance(
                    Connection,
                    CurrentPath,
                    QUIC_AMPLIFICATION_RATIO * Datagram->BufferLength);
            }
        }

        do {
            QUIC_DBG_ASSERT(BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT);
            QUIC_DBG_ASSERT(Datagram->Allocated);
            Connection->Stats.Recv.TotalPackets++;

            if (!Packet->ValidatedHeaderInv) {
                //
                // Only calculate the buffer length from the available UDP
                // payload length if the long header hasn't already been
                // validated (which indicates the actual length);
                //
                Packet->BufferLength =
                    Datagram->BufferLength - (uint16_t)(Packet->Buffer - Datagram->Buffer);
            }

            if (!QuicConnRecvHeader(
                    Connection,
                    Packet,
                    Cipher + BatchCount * QUIC_HP_SAMPLE_LENGTH)) {
                if (Packet->DecryptionDeferred) {
                    Connection->Stats.Recv.TotalPackets--; // Don't count the packet right now.
                } else {
                    Connection->Stats.Recv.DroppedPackets++;
                    if (!Packet->IsShortHeader && Packet->ValidatedHeaderVer) {
                        goto NextPacket;
                    }
                }
                break;
            }

            if (!Packet->IsShortHeader && BatchCount != 0) {
                //
                // We already had some batched short header packets and then
                // encountered a long header packet. Finish off the short
                // headers first and then continue with the current packet.
                //
                QuicConnRecvDatagramBatch(
                    Connection,
                    CurrentPath,
                    BatchCount,
                    Batch,
                    Cipher,
                    &RecvState);
                QuicMoveMemory(
                    Cipher + BatchCount * QUIC_HP_SAMPLE_LENGTH,
                    Cipher,
                    QUIC_HP_SAMPLE_LENGTH);
                BatchCount = 0;
            }

            Batch[BatchCount++] = Datagram;
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

            Packet->Buffer += Packet->BufferLength;

            Packet->ValidatedHeaderInv = FALSE;
            Packet->ValidatedHeaderVer = FALSE;
            Packet->ValidToken = FALSE;
            Packet->PacketNumberSet = FALSE;
            Packet->EncryptedWith0Rtt = FALSE;
            Packet->DecryptionDeferred = FALSE;
            Packet->CompletelyValid = FALSE;
            Packet->NewLargestPacketNumber = FALSE;
            Packet->HasNonProbingFrame = FALSE;

        } while (Packet->Buffer - Datagram->Buffer < Datagram->BufferLength);

    Drop:

        if (!Packet->DecryptionDeferred) {
            *ReleaseChainTail = Datagram;
            ReleaseChainTail = &Datagram->Next;
            Datagram->QueuedOnConnection = FALSE;
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
                QuicDataPathBindingReturnRecvDatagrams(ReleaseChain);
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
        BatchCount = 0;
    }

    if (RecvState.ResetIdleTimeout) {
        QuicConnResetIdleTimeout(Connection);
    }

    if (ReleaseChain != NULL) {
        QuicDataPathBindingReturnRecvDatagrams(ReleaseChain);
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

    if (!Connection->State.UpdateWorker &&
        Connection->State.Connected &&
        RecvState.UpdatePartitionId) {
        if (QuicRegistrationIsSplitPartitioning(Connection->Registration)) {
            RecvState.PartitionIndex += QUIC_MAX_THROUGHPUT_PARTITION_OFFSET;
        }
        QUIC_DBG_ASSERT(RecvState.PartitionIndex != QuicPartitionIdGetIndex(Connection->PartitionID));
        Connection->PartitionID = QuicPartitionIdCreate(RecvState.PartitionIndex);
        QuicConnGenerateNewSourceCids(Connection, TRUE);
        Connection->State.UpdateWorker = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnFlushRecv(
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint32_t ReceiveQueueCount;
    QUIC_RECV_DATAGRAM* ReceiveQueue;

    QuicDispatchLockAcquire(&Connection->ReceiveQueueLock);
    ReceiveQueueCount = Connection->ReceiveQueueCount;
    Connection->ReceiveQueueCount = 0;
    ReceiveQueue = Connection->ReceiveQueue;
    Connection->ReceiveQueue = NULL;
    Connection->ReceiveQueueTail = &Connection->ReceiveQueue;
    QuicDispatchLockRelease(&Connection->ReceiveQueueLock);

    QuicConnRecvDatagrams(
        Connection, ReceiveQueue, ReceiveQueueCount, FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnDiscardDeferred0Rtt(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_RECV_DATAGRAM* ReleaseChain = NULL;
    QUIC_RECV_DATAGRAM** ReleaseChainTail = &ReleaseChain;
    QUIC_PACKET_SPACE* Packets = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    QUIC_DBG_ASSERT(Packets != NULL);

    QUIC_RECV_DATAGRAM* DeferredDatagrams = Packets->DeferredDatagrams;
    QUIC_RECV_DATAGRAM** DeferredDatagramsTail = &Packets->DeferredDatagrams;
    Packets->DeferredDatagrams = NULL;

    while (DeferredDatagrams != NULL) {
        QUIC_RECV_DATAGRAM* Datagram = DeferredDatagrams;
        DeferredDatagrams = DeferredDatagrams->Next;

        const QUIC_RECV_PACKET* Packet =
            QuicDataPathRecvDatagramToRecvPacket(Datagram);
        if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT) {
            QuicPacketLogDrop(Connection, Packet, "0-RTT rejected");
            Packets->DeferredDatagramsCount--;
            *ReleaseChainTail = Datagram;
            ReleaseChainTail = &Datagram->Next;
        } else {
            *DeferredDatagramsTail = Datagram;
            DeferredDatagramsTail = &Datagram->Next;
        }
    }

    if (ReleaseChain != NULL) {
        QuicDataPathBindingReturnRecvDatagrams(ReleaseChain);
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

        if (Packets->DeferredDatagrams != NULL) {
            QUIC_RECV_DATAGRAM* DeferredDatagrams = Packets->DeferredDatagrams;
            uint8_t DeferredDatagramsCount = Packets->DeferredDatagramsCount;

            Packets->DeferredDatagramsCount = 0;
            Packets->DeferredDatagrams = NULL;

            QuicConnRecvDatagrams(
                Connection,
                DeferredDatagrams,
                DeferredDatagramsCount,
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

    } else if (QuicAddrCompare(&Connection->Paths[0].RemoteAddress, RemoteAddress)) {
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
QuicConnResetIdleTimeout(
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint64_t IdleTimeoutMs;
    if (Connection->State.Connected) {
        //
        // Use the (non-zero) min value between local and peer's configuration.
        //
        IdleTimeoutMs = Connection->PeerTransportParams.IdleTimeout;
        if (IdleTimeoutMs == 0 ||
            (Connection->IdleTimeoutMs != 0 && Connection->IdleTimeoutMs < IdleTimeoutMs)) {
            IdleTimeoutMs = Connection->IdleTimeoutMs;
        }
    } else {
        IdleTimeoutMs = Connection->HandshakeIdleTimeoutMs;
    }

    if (IdleTimeoutMs != 0) {
        //
        // Idle timeout must be no less than the PTOs for closing.
        //
        uint32_t MinIdleTimeoutMs =
            US_TO_MS(QuicLossDetectionComputeProbeTimeout(
                &Connection->LossDetection,
                &Connection->Paths[0],
                QUIC_CLOSE_PTO_COUNT));
        if (IdleTimeoutMs < MinIdleTimeoutMs) {
            IdleTimeoutMs = MinIdleTimeoutMs;
        }

        QuicConnTimerSet(Connection, QUIC_CONN_TIMER_IDLE, IdleTimeoutMs);

    } else {
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_IDLE);
    }

    if (Connection->KeepAliveIntervalMs != 0) {
        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_KEEP_ALIVE,
            Connection->KeepAliveIntervalMs);
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
        Connection->KeepAliveIntervalMs);
}

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

    switch (Param) {

    case QUIC_PARAM_CONN_QUIC_VERSION:

        if (BufferLength != sizeof(uint32_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Validate new version. We allow the application to set a reserved
        // version number to force version negotiation.
        //
        uint32_t NewVersion = QuicByteSwapUint32(*(uint32_t*)Buffer);
        if (!QuicIsVersionSupported(NewVersion) &&
            !QuicIsVersionReserved(NewVersion)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Only allowed before connection attempt.
        //
        if (Connection->State.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->Stats.QuicVersion = NewVersion;
        QuicConnOnQuicVersionSet(Connection);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_LOCAL_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADDR)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QuicConnIsServer(Connection)) {
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
        QuicCopyMemory(&Connection->Paths[0].LocalAddress, Buffer, sizeof(QUIC_ADDR));
        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!SOCKADDR!",
            Connection,
            LOG_ADDR_LEN(Connection->Paths[0].LocalAddress),
            (const uint8_t*)&Connection->Paths[0].LocalAddress);

        if (Connection->State.Started) {

            QUIC_DBG_ASSERT(Connection->Paths[0].Binding);
            QUIC_DBG_ASSERT(Connection->State.RemoteAddressSet);

            QUIC_BINDING* OldBinding = Connection->Paths[0].Binding;

            Status =
                QuicLibraryGetBinding(
                    Connection->Session,
                    Connection->State.ShareBinding,
                    FALSE,
                    LocalAddress,
                    &Connection->Paths[0].RemoteAddress,
                    &Connection->Paths[0].Binding);
            if (QUIC_FAILED(Status)) {
                Connection->Paths[0].Binding = OldBinding;
                break;
            }

            //
            // TODO - Need to free any queued recv packets from old binding.
            //

            QuicBindingMoveSourceConnectionIDs(
                OldBinding, Connection->Paths[0].Binding, Connection);
            QuicLibraryReleaseBinding(OldBinding);

            QuicTraceEvent(
                ConnLocalAddrRemoved,
                "[conn][%p] Removed Local IP: %!SOCKADDR!",
                Connection,
                LOG_ADDR_LEN(Connection->Paths[0].LocalAddress),
                (const uint8_t*)&Connection->Paths[0].LocalAddress);

            QuicDataPathBindingGetLocalAddress(
                Connection->Paths[0].Binding->DatapathBinding,
                &Connection->Paths[0].LocalAddress);

            QuicTraceEvent(
                ConnLocalAddrAdded,
                "[conn][%p] New Local IP: %!SOCKADDR!",
                Connection,
                LOG_ADDR_LEN(Connection->Paths[0].LocalAddress),
                (const uint8_t*)&Connection->Paths[0].LocalAddress);

            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);
        }

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_REMOTE_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADDR)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->Type == QUIC_HANDLE_TYPE_CHILD) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.RemoteAddressSet = TRUE;
        QuicCopyMemory(&Connection->Paths[0].RemoteAddress, Buffer, sizeof(QUIC_ADDR));
        //
        // Don't log new Remote address added here because it is logged when
        // the connection is started.
        //

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_IDLE_TIMEOUT:

        if (BufferLength != sizeof(Connection->IdleTimeoutMs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->IdleTimeoutMs = *(uint64_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateIdleTimeout,
            Connection,
            "Updated idle timeout to %llu milliseconds",
            Connection->IdleTimeoutMs);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT:

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR :
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR,
            *(uint16_t*)Buffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT:

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR :
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR,
            *(uint16_t*)Buffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:

        if (BufferLength >= 513) { // TODO - Practically, must fit in 1 packet.
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
            QUIC_FREE(Connection->CloseReasonPhrase);
        }

        //
        // Allocate new space.
        //
        Connection->CloseReasonPhrase =
            QUIC_ALLOC_NONPAGED(BufferLength);

        if (Connection->CloseReasonPhrase != NULL) {
            QuicCopyMemory(
                Connection->CloseReasonPhrase,
                Buffer,
                BufferLength);

            Status = QUIC_STATUS_SUCCESS;

        } else {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
        }

        break;

    case QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS:

        if (BufferLength != sizeof(Connection->ServerCertValidationFlags)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QuicConnIsServer(Connection) || Connection->State.Started) {
            //
            // Only allowed on client connections, before the connection starts.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->ServerCertValidationFlags = *(uint32_t*)Buffer;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_KEEP_ALIVE:

        if (BufferLength != sizeof(Connection->KeepAliveIntervalMs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.Started &&
            Connection->KeepAliveIntervalMs != 0) {
            //
            // Cancel any current timer first.
            //
            QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_KEEP_ALIVE);
        }

        Connection->KeepAliveIntervalMs = *(uint32_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateKeepAlive,
            Connection,
            "Updated keep alive interval to %u milliseconds",
            Connection->KeepAliveIntervalMs);

        if (Connection->State.Started &&
            Connection->KeepAliveIntervalMs != 0) {
            QuicConnProcessKeepAliveOperation(Connection);
        }

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DISCONNECT_TIMEOUT:

        if (BufferLength != sizeof(Connection->DisconnectTimeoutUs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (*(uint32_t*)Buffer == 0 ||
            *(uint32_t*)Buffer > QUIC_MAX_DISCONNECT_TIMEOUT) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->DisconnectTimeoutUs = MS_TO_US(*(uint32_t*)Buffer);

        QuicTraceLogConnInfo(
            UpdateDisconnectTimeout,
            Connection,
            "Updated disconnect timeout = %u milliseconds",
            *(uint32_t*)Buffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SEC_CONFIG: {

        if (BufferLength != sizeof(QUIC_SEC_CONFIG*)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_SEC_CONFIG* SecConfig = *(QUIC_SEC_CONFIG**)Buffer;

        if (SecConfig == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!QuicConnIsServer(Connection) ||
            Connection->State.ListenerAccepted == FALSE ||
            Connection->Crypto.TLS != NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QuicTraceLogConnInfo(
            SetSecurityConfig,
            Connection,
            "Security config set, %p",
            SecConfig);
        (void)QuicTlsSecConfigAddRef(SecConfig);

        Status =
            QuicConnHandshakeConfigure(
                Connection,
                SecConfig);
        if (QUIC_FAILED(Status)) {
            break;
        }

        QuicCryptoProcessData(&Connection->Crypto, FALSE);
        break;
    }

    case QUIC_PARAM_CONN_SEND_BUFFERING:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        Connection->State.UseSendBuffer = *(uint8_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateUseSendBuffer,
            Connection,
            "Updated UseSendBuffer = %hhu",
            Connection->State.UseSendBuffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SEND_PACING:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        Connection->State.UsePacing = *(uint8_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateUsePacing,
            Connection,
            "Updated UsePacing = %hhu",
            Connection->State.UsePacing);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.Started || QuicConnIsServer(Connection)) {
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
            Scheme);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_FORCE_KEY_UPDATE:

        if (!Connection->State.Connected ||
            !Connection->State.EncryptionEnabled ||
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

    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:

        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->Datagram.ReceiveEnabled = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;

        QuicTraceLogConnVerbose(
            DatagramReceiveEnableUpdated,
            Connection,
            "Updated datagram receive enabled to %hhu",
            Connection->Datagram.ReceiveEnabled);

        break;

    case QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER:

        if (BufferLength != sizeof(QUIC_PRIVATE_TRANSPORT_PARAMETER)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QuicCopyMemory(
            &Connection->TestTransportParameter, Buffer, BufferLength);
        Connection->State.TestTransportParameterSet = TRUE;

        QuicTraceLogConnVerbose(
            TestTPSet,
            Connection,
            "Setting Test Transport Parameter (type %hu, %hu bytes)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
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
        *(uint32_t*)Buffer = QuicByteSwapUint32(Connection->Stats.QuicVersion);

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
        QuicCopyMemory(
            Buffer,
            &Connection->Paths[0].LocalAddress,
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
        QuicCopyMemory(
            Buffer,
            &Connection->Paths[0].RemoteAddress,
            sizeof(QUIC_ADDR));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_IDLE_TIMEOUT:

        if (*BufferLength < sizeof(Connection->IdleTimeoutMs)) {
            *BufferLength = sizeof(Connection->IdleTimeoutMs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Connection->IdleTimeoutMs);
        *(uint64_t*)Buffer = Connection->IdleTimeoutMs;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT:
        Type =
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR :
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR;
        goto Get_Stream_Count;
    case QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT:
        Type =
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR :
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR;
        goto Get_Stream_Count;
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
        QuicCopyMemory(Buffer, Connection->CloseReasonPhrase, Length);

        Status = QUIC_STATUS_SUCCESS;
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
        Stats->Rtt = Path->SmoothedRtt;
        Stats->MinRtt = Path->MinRtt;
        Stats->MaxRtt = Path->MaxRtt;
        Stats->Timing.Start = Connection->Stats.Timing.Start;
        Stats->Timing.InitialFlightEnd = Connection->Stats.Timing.InitialFlightEnd;
        Stats->Timing.HandshakeFlightEnd = Connection->Stats.Timing.HandshakeFlightEnd;
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
        Stats->Misc.KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;

        if (Param == QUIC_PARAM_CONN_STATISTICS_PLAT) {
            Stats->Timing.Start = QuicTimeUs64ToPlat(Stats->Timing.Start);
            Stats->Timing.InitialFlightEnd = QuicTimeUs64ToPlat(Stats->Timing.InitialFlightEnd);
            Stats->Timing.HandshakeFlightEnd = QuicTimeUs64ToPlat(Stats->Timing.HandshakeFlightEnd);
        }

        *BufferLength = sizeof(QUIC_STATISTICS);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS:

        if (*BufferLength < sizeof(Connection->ServerCertValidationFlags)) {
            *BufferLength = sizeof(Connection->ServerCertValidationFlags);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Connection->ServerCertValidationFlags);
        *(uint32_t*)Buffer = Connection->ServerCertValidationFlags;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_KEEP_ALIVE:

        if (*BufferLength < sizeof(Connection->KeepAliveIntervalMs)) {
            *BufferLength = sizeof(Connection->KeepAliveIntervalMs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Connection->KeepAliveIntervalMs);
        *(uint32_t*)Buffer = Connection->KeepAliveIntervalMs;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DISCONNECT_TIMEOUT:

        if (*BufferLength < sizeof(Connection->DisconnectTimeoutUs)) {
            *BufferLength = sizeof(Connection->DisconnectTimeoutUs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint32_t);
        *(uint32_t*)Buffer = US_TO_MS(Connection->DisconnectTimeoutUs);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_RESUMPTION_STATE: {

        if (QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->RemoteServerName == NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        uint32_t RequiredBufferLength = 0;
        Status = QuicTlsReadTicket(Connection->Crypto.TLS, &RequiredBufferLength, NULL);
        if (Status != QUIC_STATUS_BUFFER_TOO_SMALL) {
            QuicTraceLogConnVerbose(
                ReadTicketFailure,
                Connection,
                "QuicTlsReadTicket failed, 0x%x",
                Status);
            break;
        }

        _Analysis_assume_(strlen(Connection->RemoteServerName) <= (size_t)UINT16_MAX);
        uint16_t RemoteServerNameLength = (uint16_t)strlen(Connection->RemoteServerName);

        QUIC_SERIALIZED_RESUMPTION_STATE* State =
            (QUIC_SERIALIZED_RESUMPTION_STATE*)Buffer;

        RequiredBufferLength += sizeof(QUIC_SERIALIZED_RESUMPTION_STATE);
        RequiredBufferLength += RemoteServerNameLength;

        if (*BufferLength < RequiredBufferLength) {
            *BufferLength = RequiredBufferLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        State->QuicVersion = Connection->Stats.QuicVersion;
        State->TransportParameters = Connection->PeerTransportParams;
        State->ServerNameLength = RemoteServerNameLength;
        memcpy(State->Buffer, Connection->RemoteServerName, State->ServerNameLength);

        uint32_t TempBufferLength = *BufferLength - RemoteServerNameLength;
        Status =
            QuicTlsReadTicket(
                Connection->Crypto.TLS,
                &TempBufferLength,
                State->Buffer + RemoteServerNameLength);
        *BufferLength = RequiredBufferLength;

        break;
    }

    case QUIC_PARAM_CONN_SEND_BUFFERING:

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
        *(uint8_t*)Buffer = Connection->State.UseSendBuffer;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SEND_PACING:

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
        *(uint8_t*)Buffer = Connection->State.UsePacing;

        Status = QUIC_STATUS_SUCCESS;
        break;

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

    case QUIC_PARAM_CONN_IDEAL_PROCESSOR:

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
        *(uint8_t*)Buffer = Connection->Worker->IdealProcessor;

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
        *(BOOLEAN*)Buffer = Connection->Datagram.ReceiveEnabled;

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

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessApiOperation(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_API_CONTEXT* ApiCtx
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    switch (ApiCtx->Type) {

    case QUIC_API_TYPE_CONN_CLOSE:
        QuicConnCloseHandle(Connection);
        break;

    case QUIC_API_TYPE_CONN_SHUTDOWN:
        QuicConnShutdown(
            Connection,
            ApiCtx->CONN_SHUTDOWN.Flags,
            ApiCtx->CONN_SHUTDOWN.ErrorCode);
        break;

    case QUIC_API_TYPE_CONN_START:
        Status =
            QuicConnStart(
                Connection,
                ApiCtx->CONN_START.Family,
                ApiCtx->CONN_START.ServerName,
                ApiCtx->CONN_START.ServerPort);
        ApiCtx->CONN_START.ServerName = NULL;
        break;

    case QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET:
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
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
            ApiCtx->STRM_RECV_COMPLETE.Stream,
            ApiCtx->STRM_RECV_COMPLETE.BufferLength);
        break;

    case QUIC_API_TYPE_STRM_RECV_SET_ENABLED:
        Status =
            QuicStreamRecvSetEnabledState(
                ApiCtx->STRM_RECV_SET_ENABLED.Stream,
                ApiCtx->STRM_RECV_SET_ENABLED.IsEnabled);
        break;

    case QUIC_API_TYPE_SET_PARAM:
        Status =
            QuicLibrarySetParam(
                ApiCtx->SET_PARAM.Handle,
                ApiCtx->SET_PARAM.Level,
                ApiCtx->SET_PARAM.Param,
                ApiCtx->SET_PARAM.BufferLength,
                ApiCtx->SET_PARAM.Buffer);
        break;

    case QUIC_API_TYPE_GET_PARAM:
        Status =
            QuicLibraryGetParam(
                ApiCtx->GET_PARAM.Handle,
                ApiCtx->GET_PARAM.Level,
                ApiCtx->GET_PARAM.Param,
                ApiCtx->GET_PARAM.BufferLength,
                ApiCtx->GET_PARAM.Buffer);
        break;

    case QUIC_API_TYPE_DATAGRAM_SEND:
        QuicDatagramSendFlush(&Connection->Datagram);
        break;

    default:
        QUIC_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    if (ApiCtx->Status) {
        *ApiCtx->Status = Status;
    }
    if (ApiCtx->Completed) {
        QuicEventSet(*ApiCtx->Completed);
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
        QUIC_FRE_ASSERT(FALSE);
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnDrainOperations(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_OPERATION* Oper;
    const uint32_t MaxOperationCount =
        (Connection->Session == NULL || Connection->Session->Registration == NULL) ?
            MsQuicLib.Settings.MaxOperationsPerDrain :
            Connection->Session->Settings.MaxOperationsPerDrain;
    uint32_t OperationCount = 0;
    BOOLEAN HasMoreWorkToDo = TRUE;

    QUIC_PASSIVE_CODE();

    if (!Connection->State.Initialized) {
        //
        // TODO - Try to move this only after the connection is accepted by the
        // listener. But that's going to be pretty complicated.
        //
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_STATUS Status;
        if (QUIC_FAILED(Status = QuicConnInitializeCrypto(Connection))) {
            QuicConnFatalError(Connection, Status, "Lazily initialize failure");
        } else {
            Connection->State.Initialized = TRUE;
            QuicTraceEvent(
                ConnInitializeComplete,
                "[conn][%p] Initialize complete",
                Connection);
        }
    }

    while (!Connection->State.HandleClosed &&
           !Connection->State.UpdateWorker &&
           OperationCount++ < MaxOperationCount) {

        Oper = QuicOperationDequeue(&Connection->OperQ);
        if (Oper == NULL) {
            HasMoreWorkToDo = FALSE;
            break;
        }

        QuicOperLog(Connection, Oper);

        BOOLEAN FreeOper = Oper->FreeAfterProcess;

        switch (Oper->Type) {

        case QUIC_OPER_TYPE_API_CALL:
            QUIC_DBG_ASSERT(Oper->API_CALL.Context != NULL);
            QuicConnProcessApiOperation(
                Connection,
                Oper->API_CALL.Context);
            break;

        case QUIC_OPER_TYPE_FLUSH_RECV:
            QuicConnFlushRecv(Connection);
            break;

        case QUIC_OPER_TYPE_UNREACHABLE:
            QuicConnProcessUdpUnreachable(
                Connection,
                &Oper->UNREACHABLE.RemoteAddress);
            break;

        case QUIC_OPER_TYPE_FLUSH_STREAM_RECV:
            QuicStreamRecvFlush(Oper->FLUSH_STREAM_RECEIVE.Stream);
            break;

        case QUIC_OPER_TYPE_FLUSH_SEND:
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
                (void)QuicOperationEnqueue(&Connection->OperQ, Oper);
            }
            break;

        case QUIC_OPER_TYPE_TLS_COMPLETE:
            QuicCryptoProcessCompleteOperation(&Connection->Crypto);
            break;

        case QUIC_OPER_TYPE_TIMER_EXPIRED:
            QuicConnProcessExpiredTimer(Connection, Oper->TIMER_EXPIRED.Type);
            break;

        case QUIC_OPER_TYPE_TRACE_RUNDOWN:
            QuicConnTraceRundownOper(Connection);
            break;

        default:
            QUIC_FRE_ASSERT(FALSE);
            break;
        }

        QuicConnValidate(Connection);

        if (FreeOper) {
            QuicOperationFree(Connection->Worker, Oper);
        }

        Connection->Stats.Schedule.OperationCount++;
    }

    if (!Connection->State.ExternalOwner && Connection->State.ClosedLocally) {
        //
        // Don't continue processing the connection, since it has been closed
        // locally and it's not referenced externally.
        //
        QuicTraceLogConnVerbose(
            AbandonInternallyClosed,
            Connection,
            "Abandoning internal, closed connection");
        QuicConnOnShutdownComplete(Connection);
    }

    if (!Connection->State.HandleClosed) {
        if (OperationCount >= MaxOperationCount &&
            (Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK)) {
            //
            // We can't process any more operations but still need to send an
            // immediate ACK. So as to not introduce additional queuing delay do
            // one immediate flush now.
            //
            (void)QuicSendFlush(&Connection->Send);
        }

        if (Connection->State.SendShutdownCompleteNotif) {
            QuicConnOnShutdownComplete(Connection);
        }
    }

    if (Connection->State.HandleClosed) {
        if (!Connection->State.Uninitialized) {
            QuicConnUninitialize(Connection);
        }
        HasMoreWorkToDo = FALSE;
    }

    QuicStreamSetDrainClosedStreams(&Connection->Streams);

    QuicConnValidate(Connection);

    return HasMoreWorkToDo;
}
