/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Because automating the logic to convert an event into text is so impossibly
    hard this file hard codes much of the text for converting an event for
    printing to the console.

--*/

#include "quicetw.h"

const char* OperationTypeStr[] = {
    "API",
    "FLUSH_RECV",
    "UNREACHABLE",
    "FLUSH_STREAM_RECV",
    "FLUSH_SEND",
    "TLS_COMPLETE",
    "TIMER_EXPIRED",
    "TRACE_RUNDOWN",
    "VERSION_NEGOTIATION",
    "STATELESS_RESET",
    "RETRY"
};

const char* ApiOperationTypeStr[] = {
    "API.CONN_CLOSE",
    "API.CONN_SHUTDOWN",
    "API.CONN_START",
    "API.STRM_CLOSE",
    "API.STRM_SHUTDOWN",
    "API.STRM_START",
    "API.STRM_SEND",
    "API.STRM_RECV_COMPLETE",
    "API.STRM_RECV_SET_ENABLED",
    "API.SET_PARAM",
    "API.GET_PARAM"
};

const char* TimerOperationTypeStr[] = {
    "TIMER.PACING",
    "TIMER.ACK_DELAY",
    "TIMER.LOSS_DETECTION",
    "TIMER.KEEP_ALIVE",
    "TIMER.IDLE",
    "TIMER.SHUTDOWN"
};

const char* PacktTypeStr[] = {
    "VN",
    "I",
    "0-RTT",
    "HS",
    "R",
    "1-RTT"
};

const char* PacktLostReasonStr[] = {
    "RACK",
    "FACK",
    "PROBE"
};

const char* ApiTypeStr[] = {
    "SET_PARAM",
    "GET_PARAM",
    "REGISTRATION_OPEN",
    "REGISTRATION_CLOSE",
    "SEC_CONFIG_CREATE",
    "SEC_CONFIG_DELETE",
    "SESSION_OPEN",
    "SESSION_CLOSE",
    "SESSION_SHUTDOWN",
    "LISTENER_OPEN",
    "LISTENER_CLOSE",
    "LISTENER_START",
    "LISTENER_STOP",
    "CONNECTION_OPEN",
    "CONNECTION_CLOSE",
    "CONNECTION_SHUTDOWN",
    "CONNECTION_START",
    "STREAM_OPEN",
    "STREAM_CLOSE",
    "STREAM_START",
    "STREAM_SHUTDOWN",
    "STREAM_SEND",
    "STREAM_RECEIVE_COMPLETE",
    "STREAM_RECEIVE_SET_ENABLED"
};

#define TRACE_TIME_FORMAT "%llu.%03llu "
#define TRACE_TIME(Cxn,ev) \
    NS100_TO_US(ev->EventHeader.TimeStamp.QuadPart - Cxn->InitialTimestamp) / 1000, \
    NS100_TO_US(ev->EventHeader.TimeStamp.QuadPart - Cxn->InitialTimestamp) % 1000

void
QuicTraceGlobalEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_GLOBAL* EvData = (QUIC_EVENT_DATA_GLOBAL*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicLibraryInitialized: {
        printf("Initialized, PartitionCount=%u DatapathFeatures=[ ", EvData->LibraryInitialized.PartitionCount);
        if (EvData->LibraryInitialized.DatapathFeatures == 0) {
            printf("NONE ]\n");
        } else {
            if (EvData->LibraryInitialized.DatapathFeatures & QUIC_DATAPATH_FEATURE_RECV_SIDE_SCALING) {
                printf("RSS ");
            }
            if (EvData->LibraryInitialized.DatapathFeatures & QUIC_DATAPATH_FEATURE_RECV_COALESCING) {
                printf("URO ");
            }
            if (EvData->LibraryInitialized.DatapathFeatures & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION) {
                printf("USO ");
            }
            printf("]\n");
        }
        break;
    }
    case EventId_QuicLibraryUninitialized: {
        printf("Uninitialized\n");
        break;
    }
    case EventId_QuicLibraryAddRef: {
        printf("AddRef\n");
        break;
    }
    case EventId_QuicLibraryRelease: {
        printf("Release\n");
        break;
    }
    case EventId_QuicLibraryWorkerPoolInit: {
        printf("Listener worker pool initialized\n");
        break;
    }
    case EventId_QuicAllocFailure: {
        printf("Allocation Failure, %s\n", EvData->QuicAllocFailure.Desc);
        break;
    }
    case EventId_QuicLibraryRundown: {
        printf("Rundown, PartitionCount=%u DatapathFeatures=[ ", EvData->LibraryInitialized.PartitionCount);
        if (EvData->LibraryInitialized.DatapathFeatures == 0) {
            printf("NONE ]\n");
        } else {
            if (EvData->LibraryInitialized.DatapathFeatures & QUIC_DATAPATH_FEATURE_RECV_SIDE_SCALING) {
                printf("RSS ");
            }
            if (EvData->LibraryInitialized.DatapathFeatures & QUIC_DATAPATH_FEATURE_RECV_COALESCING) {
                printf("URO ");
            }
            if (EvData->LibraryInitialized.DatapathFeatures & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION) {
                printf("USO ");
            }
            printf("]\n");
        }
        break;
    }
    case EventId_QuicLibraryError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicLibraryErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    case EventId_QuicLibraryAssert: {
        printf("ASSERT, %s:%u - %s\n", EvData->Assert.File, EvData->Assert.Line,
            EvData->Assert.File + strlen(EvData->Assert.File) + 1);
        break;
    }
    case EventId_QuicApiEnter: {
        printf("API Enter %s (%p)\n", ApiTypeStr[EvData->ApiEnter.Type],
            (void*)EvData->ApiEnter.Handle);
        break;
    }
    case EventId_QuicApiExit: {
        printf("API Exit\n");
        break;
    }
    case EventId_QuicApiExitStatus: {
        printf("API Exit (0x%x)\n", EvData->ApiExitStatus.Status);
        break;
    }
    case EventId_QuicApiWaitOperation: {
        printf("API Waiting on operation\n");
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceRegistrationEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_REGISTRATION* EvData = (QUIC_EVENT_DATA_REGISTRATION*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicRegistrationCreated: {
        printf("Created %llX, AppName='%s'\n",
            (ULONG64)EvData->RegistrationPtr, EvData->Created.AppName);
        break;
    }
    case EventId_QuicRegistrationDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicRegistrationCleanup: {
        printf("Cleanup\n");
        break;
    }
    case EventId_QuicRegistrationRundown: {
        printf("Rundown %llX, AppName='%s'\n",
            (ULONG64)EvData->RegistrationPtr, EvData->Rundown.AppName);
        break;
    }
    case EventId_QuicRegistrationError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicRegistrationErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceWorkerEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_WORKER* EvData = (QUIC_EVENT_DATA_WORKER*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicWorkerCreated: {
        printf("Created %llX, IdealProc=%u Owner=%llX\n",
            (ULONG64)EvData->WorkerPtr, (ULONG)EvData->Created.IdealProcessor, (ULONG64)EvData->Created.OwnerPtr);
        break;
    }
    case EventId_QuicWorkerStart: {
        printf("Start\n");
        break;
    }
    case EventId_QuicWorkerStop: {
        printf("Stop\n");
        break;
    }
    case EventId_QuicWorkerActivityStateUpdated: {
        if (EvData->ActivityStateUpdated.IsActive) {
            if (EvData->ActivityStateUpdated.Arg) {
                printf("Active\n");
            } else {
                printf("Active (timers)\n");
            }
        } else {
            if (EvData->ActivityStateUpdated.Arg == UINT_MAX) {
                printf("Idle\n");
            } else {
                printf("Idle (wait %u ms)\n", EvData->ActivityStateUpdated.Arg);
            }
        }
        break;
    }
    case EventId_QuicWorkerQueueDelayUpdated: {
        printf("QueueDelay: %u us\n", EvData->QueueDelayUpdated.QueueDelay);
        break;
    }
    case EventId_QuicWorkerDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicWorkerCleanup: {
        printf("Cleanup\n");
        break;
    }
    case EventId_QuicWorkerError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicWorkerErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceSessionEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_SESSION* EvData = (QUIC_EVENT_DATA_SESSION*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicSessionCreated: {
        printf("Created %llX, Registration=%llX, ALPN='%s'\n",
            (ULONG64)EvData->SessionPtr, (ULONG64)EvData->Created.RegistrationPtr, EvData->Created.Alpn);
        break;
    }
    case EventId_QuicSessionDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicSessionCleanup: {
        printf("Cleanup\n");
        break;
    }
    case EventId_QuicSessionShutdown: {
        printf("Shutdown, Flags=0x%x, ErrorCode=%llu\n",
            EvData->Shutdown.Flags, EvData->Shutdown.ErrorCode);
        break;
    }
    case EventId_QuicSessionRundown: {
        printf("Rundown %llX, Registration=%llX, ALPN='%s'\n",
            (ULONG64)EvData->SessionPtr, (ULONG64)EvData->Created.RegistrationPtr, EvData->Rundown.Alpn);
        break;
    }
    case EventId_QuicSessionError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicSessionErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceListenerEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_LISTENER* EvData = (QUIC_EVENT_DATA_LISTENER*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicListenerCreated: {
        printf("Created %llX, Session=%llX\n",
            (ULONG64)EvData->ListenerPtr, (ULONG64)EvData->Created.SessionPtr);
        break;
    }
    case EventId_QuicListenerDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicListenerStarted: {
        char AddrStr[INET6_ADDRSTRLEN];
        AddrToString(&EvData->Started.Addr, AddrStr);
        printf("Started, Binding=%llX, Addr=%s\n", (ULONG64)EvData->Started.BindingPtr, AddrStr);
        break;
    }
    case EventId_QuicListenerStopped: {
        printf("Stopped\n");
        break;
    }
    case EventId_QuicListenerRundown: {
        printf("Rundown %llX, Session=%llX\n",
            (ULONG64)EvData->ListenerPtr, (ULONG64)EvData->Rundown.SessionPtr);
        break;
    }
    case EventId_QuicListenerError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicListenerErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

typedef enum QUIC_FLOW_BLOCK_REASON {
    QUIC_FLOW_BLOCKED_SCHEDULING            = 0x01,
    QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x02,
    QUIC_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x04,
    QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x08,
    QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x10,
    QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x20,
    QUIC_FLOW_BLOCKED_APP                   = 0x40
} QUIC_FLOW_BLOCK_REASON;

void
QuicTraceFlowBlockFlags(
    _In_ UINT8 Flags
    )
{
    printf("[ ");
    if (Flags & QUIC_FLOW_BLOCKED_SCHEDULING) {
        printf("SCHED ");
    }
    if (Flags & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) {
        printf("AMP ");
    }
    if (Flags & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) {
        printf("CC ");
    }
    if (Flags & QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL) {
        printf("CFC ");
    }
    if (Flags & QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL) {
        printf("SID_FC ");
    }
    if (Flags & QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL) {
        printf("SFC ");
    }
    if (Flags & QUIC_FLOW_BLOCKED_APP) {
        printf("APP ");
    }
    printf("]");
}

void
QuicTraceConnEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_CONNECTION* EvData = (QUIC_EVENT_DATA_CONNECTION*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicConnCreated: {
        printf("Created %llX, Server=%u, CorrelationId=%llu\n",
            (ULONG64)EvData->CxnPtr, EvData->Created.IsServer,
            EvData->Created.CorrelationId);
        break;
    }
    case EventId_QuicConnDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicConnHandshakeComplete: {
        printf("Handshake complete\n");
        break;
    }
    case EventId_QuicConnScheduleState: {
        const char* StateStr[] = {
            "Idle",
            "Queued",
            "Processing"
        };
        printf("Scheduling: %s\n", StateStr[EvData->ScheduleState.State]);
        break;
    }
    case EventId_QuicConnExecOper: {
        printf("Execute: %s\n", OperationTypeStr[EvData->ExecOper.Type]);
        break;
    }
    case EventId_QuicConnExecApiOper: {
        printf("Execute: %s\n", ApiOperationTypeStr[EvData->ExecApiOper.Type]);
        break;
    }
    case EventId_QuicConnExecTimerOper: {
        printf("Execute: %s\n", TimerOperationTypeStr[EvData->ExecTimerOper.Type]);
        break;
    }
    case EventId_QuicConnLocalAddrAdded: {
        char AddrStr[INET6_ADDRSTRLEN];
        AddrToString(&EvData->LocalAddrAdd.Addr, AddrStr);
        printf("New Local IP: %s\n", AddrStr);
        break;
    }
    case EventId_QuicConnRemoteAddrAdded: {
        char AddrStr[INET6_ADDRSTRLEN];
        AddrToString(&EvData->RemoteAddrAdd.Addr, AddrStr);
        printf("New Remote IP: %s\n", AddrStr);
        break;
    }
    case EventId_QuicConnLocalAddrRemoved: {
        char AddrStr[INET6_ADDRSTRLEN];
        AddrToString(&EvData->LocalAddrRemove.Addr, AddrStr);
        printf("Removed Local IP: %s\n", AddrStr);
        break;
    }
    case EventId_QuicConnRemoteAddrRemoved: {
        char AddrStr[INET6_ADDRSTRLEN];
        AddrToString(&EvData->RemoteAddrRemove.Addr, AddrStr);
        printf("Removed Remote IP: %s\n", AddrStr);
        break;
    }
    case EventId_QuicConnAssignWorker: {
        printf("Assigned worker: %llX\n", (ULONG64)EvData->AssignWorker.WorkerPtr);
        break;
    }
    case EventId_QuicConnHandshakeStart: {
        printf("Handshake start\n");
        break;
    }
    case EventId_QuicConnRegisterSession: {
        printf("Registered with session: %llX\n", (ULONG64)EvData->RegisterSession.SessionPtr);
        break;
    }
    case EventId_QuicConnUnregisterSession: {
        printf("Unregistered from session: %llX\n", (ULONG64)EvData->UnregisterSession.SessionPtr);
        break;
    }
    case EventId_QuicConnTransportShutdown: {
        if (EvData->TransportShutdown.IsQuicStatus) {
            printf("Transport Shutdown: QUIC_STATUS=%llu (Remote=%hu)\n",
                EvData->TransportShutdown.ErrorCode,
                (USHORT)EvData->TransportShutdown.IsRemoteShutdown);
        } else {
            printf("Transport Shutdown: %s (%llu) (Remote=%hu)\n",
                QuicErrorToString(EvData->TransportShutdown.ErrorCode),
                EvData->TransportShutdown.ErrorCode,
                (USHORT)EvData->TransportShutdown.IsRemoteShutdown);
        }
        break;
    }
    case EventId_QuicConnAppShutdown: {
        printf("App Shutdown: %llu (Remote=%hu)\n",
            EvData->AppShutdown.ErrorCode,
            (USHORT)EvData->AppShutdown.IsRemoteShutdown);
        break;
    }
    case EventId_QuicConnInitializeComplete: {
        printf("Initialize complete\n");
        break;
    }
    case EventId_QuicConnHandleClosed: {
        printf("Handle closed\n");
        break;
    }
    case EventId_QuicConnVersionSet: {
        printf("Version: 0x%x\n", EvData->VersionSet.Version);
        break;
    }
    case EventId_QuicConnOutFlowStats: {
        printf("OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu StreamFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u StreamSndWnd=%llu\n",
            EvData->OutFlowStats.BytesSent,
            EvData->OutFlowStats.BytesInFlight,
            EvData->OutFlowStats.BytesInFlightMax,
            EvData->OutFlowStats.CongestionWindow,
            EvData->OutFlowStats.SlowStartThreshold,
            EvData->OutFlowStats.ConnectionFlowControl,
            EvData->OutFlowStats.StreamFlowControl,
            EvData->OutFlowStats.IdealBytes,
            EvData->OutFlowStats.PostedBytes,
            EvData->OutFlowStats.SmoothedRtt,
            EvData->OutFlowStats.StreamSendWindow);
        break;
    }
    case EventId_QuicConnOutFlowBlocked: {
        if (EvData->OutFlowBlocked.ReasonFlags == 0) {
            printf("Send Unblocked\n");
        } else {
            printf("Send Blocked: ");
            QuicTraceFlowBlockFlags(EvData->OutFlowBlocked.ReasonFlags);
            printf("\n");
        }
        break;
    }
    case EventId_QuicConnInFlowStats: {
        printf("IN: BytesRecv=%llu\n",
            EvData->InFlowStats.BytesRecv);
        break;
    }
    case EventId_QuicConnCubic: {
        printf("CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u\n",
            EvData->Cubic.SlowStartThreshold,
            EvData->Cubic.K,
            EvData->Cubic.WindowMax,
            EvData->Cubic.WindowLastMax);
        break;
    }
    case EventId_QuicConnCongestion: {
        printf("Congestion event\n");
        break;
    }
    case EventId_QuicConnPersistentCongestion: {
        printf("Persistent congestion event\n");
        break;
    }
    case EventId_QuicConnRecoveryExit: {
        printf("Recovery exit\n");
        break;
    }
    case EventId_QuicConnRundown: {
        printf("Rundown %llX, Server=%u, CorrelationId=%llu\n",
            (ULONG64)EvData->CxnPtr, EvData->Created.IsServer,
            EvData->Created.CorrelationId);
        break;
    }
    case EventId_QuicConnSourceCidAdded: {
        char CidStr[QUIC_CID_MAX_STR_LEN];
        CidToString(EvData->SourceCidAdd.CidLength, EvData->SourceCidAdd.Cid, CidStr);
        printf("New Source CID: %s\n", CidStr);
        break;
    }
    case EventId_QuicConnDestCidAdded: {
        char CidStr[QUIC_CID_MAX_STR_LEN];
        CidToString(EvData->DestCidAdd.CidLength, EvData->DestCidAdd.Cid, CidStr);
        printf("New Destination CID: %s\n", CidStr);
        break;
    }
    case EventId_QuicConnSourceCidRemoved: {
        char CidStr[QUIC_CID_MAX_STR_LEN];
        CidToString(EvData->SourceCidRemove.CidLength, EvData->SourceCidRemove.Cid, CidStr);
        printf("Removed Source CID: %s\n", CidStr);
        break;
    }
    case EventId_QuicConnDestCidRemoved: {
        char CidStr[QUIC_CID_MAX_STR_LEN];
        CidToString(EvData->DestCidRemove.CidLength, EvData->DestCidRemove.Cid, CidStr);
        printf("Removed Destination CID: %s\n", CidStr);
        break;
    }
    case EventId_QuicConnLossDetectionTimerSet: {
        const char* TypeStr[] = {
            "CRYPTO",
            "RACK",
            "PROBE"
        };
        printf("Setting loss detection %s timer for %u ms. (ProbeCount=%hu)\n",
            TypeStr[EvData->LossDetectionTimerSet.Type], EvData->LossDetectionTimerSet.DelayMs,
            EvData->LossDetectionTimerSet.ProbeCount);
        break;
    }
    case EventId_QuicConnLossDetectionTimerCancel: {
        printf("Cancelling loss detection timer.\n");
        break;
    }
    case EventId_QuicConnDropPacket: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->DropPacket.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->DropPacket.Addrs + EvData->DropPacket.LocalAddrLength),
            RemoteAddrStr);
        char* Reason = (char*)
            EvData->DropPacket.Addrs +
            EvData->DropPacket.LocalAddrLength +
            EvData->DropPacket.RemoteAddrLength;
        if (EvData->DropPacket.PktNum != ULLONG_MAX) {
            printf("DROP packet Num=%llu Src=%s Dst=%s Reason=%s\n",
                EvData->DropPacket.PktNum, RemoteAddrStr, LocalAddrStr, Reason);
        } else {
            printf("DROP packet Src=%s Dst=%s Reason=%s\n",
                RemoteAddrStr, LocalAddrStr, Reason);
        }
        break;
    }
    case EventId_QuicConnDropPacketEx: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->DropPacketEx.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->DropPacketEx.Addrs + EvData->DropPacketEx.LocalAddrLength),
            RemoteAddrStr);
        char* Reason = (char*)
            EvData->DropPacketEx.Addrs +
            EvData->DropPacketEx.LocalAddrLength +
            EvData->DropPacketEx.RemoteAddrLength;
        if (EvData->DropPacketEx.PktNum != ULLONG_MAX) {
            printf("DROP packet Num=%llu Src=%s Dst=%s Reason=%s, %llu\n",
                EvData->DropPacketEx.PktNum, RemoteAddrStr, LocalAddrStr, Reason, EvData->DropPacketEx.Value);
        } else {
            printf("DROP packet Src=%s Dst=%s Reason=%s, %llu\n",
                RemoteAddrStr, LocalAddrStr, Reason, EvData->DropPacketEx.Value);
        }
        break;
    }
    case EventId_QuicConnError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicConnErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    case EventId_QuicConnNewPacketKeys: {
        printf("New packet keys generated\n");
        break;
    }
    case EventId_QuicConnKeyPhaseChange: {
        printf("Key phase change, %s initiated\n",
            (EvData->KeyPhaseChange.IsLocallyInitiated ? "locally" : "remotely"));
        break;
    }
    case EventId_QuicConnStatistics: {
        printf("STATS: LifeTimeUs=%llu SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu SmoothedRtt=%u\n",
            EvData->Statistics.LifeTimeUs,
            EvData->Statistics.SendTotalPackets,
            EvData->Statistics.SendSuspectedLostPackets,
            EvData->Statistics.SendSpuriousLostPackets,
            EvData->Statistics.RecvTotalPackets,
            EvData->Statistics.RecvReorderedPackets,
            EvData->Statistics.RecvDroppedPackets,
            EvData->Statistics.RecvDuplicatePackets,
            EvData->Statistics.RecvDecryptionFailures,
            EvData->Statistics.CongestionCount,
            EvData->Statistics.PersistentCongestionCount,
            EvData->Statistics.SendTotalBytes,
            EvData->Statistics.RecvTotalBytes,
            EvData->Statistics.SmoothedRtt);
        break;
    }
    case EventId_QuicConnShutdownComplete: {
        printf("Shutdown Complete, PeerFailedToAcknowledged=%s\n",
            (EvData->ShutdownComplete.TimedOut ? "true" : "false"));
        break;
    }
    case EventId_QuicConnReadKeyUpdated: {
        printf("Read Key Updated, %u\n", EvData->ReadKeyUpdated.NewValue);
        break;
    }
    case EventId_QuicConnWriteKeyUpdated: {
        printf("Write Key Updated, %u\n", EvData->WriteKeyUpdated.NewValue);
        break;
    }
    case EventId_QuicConnPacketSent: {
        printf("[TX][%llu] %s (%hu bytes)\n", EvData->PacketSent.Number,
            PacktTypeStr[EvData->PacketSent.Type], EvData->PacketSent.Length);
        break;
    }
    case EventId_QuicConnPacketRecv: {
        printf("[RX][%llu] %s (%hu bytes)\n", EvData->PacketRecv.Number,
            PacktTypeStr[EvData->PacketRecv.Type], EvData->PacketRecv.Length);
        break;
    }
    case EventId_QuicConnPacketLost: {
        printf("[TX][%llu] %s Lost: %s\n", EvData->PacketLost.Number,
            PacktTypeStr[EvData->PacketLost.Type],
            PacktLostReasonStr[EvData->PacketLost.Reason]);
        break;
    }
    case EventId_QuicConnPacketACKed: {
        printf("[TX][%llu] %s ACKed\n", EvData->PacketACKed.Number,
            PacktTypeStr[EvData->PacketACKed.Type]);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceStreamEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_STREAM* EvData = (QUIC_EVENT_DATA_STREAM*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicStreamCreated: {
        UINT16 IsServer = !!(EvData->Created.ID & STREAM_ID_FLAG_IS_SERVER);
        UINT16 IsUniDir = !!(EvData->Created.ID & STREAM_ID_FLAG_IS_UNI_DIR);
        printf("Created %llX, Connection=%llX ID=%llu IsLocal=%hu IsServer=%hu IsUniDir=%hu\n",
            (ULONG64)EvData->StreamPtr, (ULONG64)EvData->Created.ConnectionPtr,
            EvData->Created.ID, (UINT16)EvData->Created.IsLocalOwned, IsServer, IsUniDir);
        break;
    }
    case EventId_QuicStreamDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicStreamOutFlowBlocked: {
        if (EvData->OutFlowBlocked.ReasonFlags == 0) {
            printf("Send Unblocked\n");
        } else {
            printf("Send Blocked: ");
            QuicTraceFlowBlockFlags(EvData->OutFlowBlocked.ReasonFlags);
            printf("\n");
        }
        break;
    }
    case EventId_QuicStreamRundown: {
        UINT16 IsServer = !!(EvData->Created.ID & STREAM_ID_FLAG_IS_SERVER);
        UINT16 IsUniDir = !!(EvData->Created.ID & STREAM_ID_FLAG_IS_UNI_DIR);
        printf("Rundown %llX, Connection=%llX ID=%llu IsLocal=%hu IsServer=%hu IsUniDir=%hu\n",
            (ULONG64)EvData->StreamPtr, (ULONG64)EvData->Created.ConnectionPtr,
            EvData->Created.ID, (UINT16)EvData->Created.IsLocalOwned, IsServer, IsUniDir);
        break;
    }
    case EventId_QuicStreamSendState: {
        const char* TypeStr[] = {
            "DISABLED",
            "STARTED",
            "RESET",
            "RESET_ACKED",
            "FIN",
            "FIN_ACKED"
        };
        printf("Send State: %s\n", TypeStr[EvData->SendState.State]);
        break;
    }
    case EventId_QuicStreamRecvState: {
        const char* TypeStr[] = {
            "DISABLED",
            "STARTED",
            "PAUSED",
            "STOPPED",
            "RESET",
            "FIN"
        };
        printf("Recv State: %s\n", TypeStr[EvData->RecvState.State]);
        break;
    }
    case EventId_QuicStreamError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicStreamErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceBindingEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_BINDING* EvData = (QUIC_EVENT_DATA_BINDING*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicBindingCreated: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->Created.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->Created.Addrs + EvData->Created.LocalAddrLength),
            RemoteAddrStr);
        printf("Created %llX, Udp=%llX LocalAddr=%s RemoteAddr=%s\n",
            (ULONG64)EvData->BindingPtr, (ULONG64)EvData->Created.DatapathPtr,
            LocalAddrStr, RemoteAddrStr);
        break;
    }
    case EventId_QuicBindingRundown: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->Rundown.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->Rundown.Addrs + EvData->Rundown.LocalAddrLength),
            RemoteAddrStr);
        printf("Rundown %llX, Udp=%llX LocalAddr=%s RemoteAddr=%s\n",
            (ULONG64)EvData->BindingPtr, (ULONG64)EvData->Rundown.DatapathPtr,
            LocalAddrStr, RemoteAddrStr);
        break;
    }
    case EventId_QuicBindingDestroyed: {
        printf("Destroyed\n");
        break;
    }
    case EventId_QuicBindingCleanup: {
        printf("Cleaning up\n");
        break;
    }
    case EventId_QuicBindingDropPacket: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->DropPacket.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->DropPacket.Addrs + EvData->DropPacket.LocalAddrLength),
            RemoteAddrStr);
        char* Reason = (char*)
            EvData->DropPacket.Addrs +
            EvData->DropPacket.LocalAddrLength +
            EvData->DropPacket.RemoteAddrLength;
        if (EvData->DropPacket.PktNum != ULLONG_MAX) {
            printf("DROP packet Num=%llu Src=%s Dst=%s Reason=%s\n",
                EvData->DropPacket.PktNum, LocalAddrStr, RemoteAddrStr, Reason);
        } else {
            printf("DROP packet Src=%s Dst=%s Reason=%s\n",
                LocalAddrStr, RemoteAddrStr, Reason);
        }
        break;
    }
    case EventId_QuicBindingDropPacketEx: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->DropPacketEx.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->DropPacketEx.Addrs + EvData->DropPacketEx.LocalAddrLength),
            RemoteAddrStr);
        char* Reason = (char*)
            EvData->DropPacketEx.Addrs +
            EvData->DropPacketEx.LocalAddrLength +
            EvData->DropPacketEx.RemoteAddrLength;
        if (EvData->DropPacketEx.PktNum != ULLONG_MAX) {
            printf("DROP packet Num=%llu Src=%s Dst=%s Reason=%s, %llu\n",
                EvData->DropPacketEx.PktNum, LocalAddrStr, RemoteAddrStr, Reason, EvData->DropPacketEx.Value);
        } else {
            printf("DROP packet Src=%s Dst=%s Reason=%s, %llu\n",
                LocalAddrStr, RemoteAddrStr, Reason, EvData->DropPacketEx.Value);
        }
        break;
    }
    case EventId_QuicBindingError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicBindingErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    case EventId_QuicBindingExecOper: {
        printf("Execute: %s\n", OperationTypeStr[EvData->ExecOper.Type]);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceTlsEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_TLS* EvData = (QUIC_EVENT_DATA_TLS*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicTlsError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicTlsErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    case EventId_QuicTlsMessage: {
        printf("%s\n", EvData->Message.Str);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceDatapathEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_DATAPATH* EvData = (QUIC_EVENT_DATA_DATAPATH*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicDatapathSendTo: {
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString(&EvData->SendTo.RemoteAddr, RemoteAddrStr);
        if (EvData->SendTo.BufferCount == 1) {
            if (EvData->SendTo.SegmentSize == 0 ||
                EvData->SendTo.SegmentSize >= EvData->SendTo.TotalSize) {
                printf("Send %u bytes Dst=%s\n", EvData->SendTo.TotalSize, RemoteAddrStr);
            } else {
                printf("Send %u bytes (segment=%hu) Dst=%s\n",
                    EvData->SendTo.TotalSize, EvData->SendTo.SegmentSize, RemoteAddrStr);
            }
        } else {
            printf("Send %u bytes in %hu buffers (segment=%hu) Dst=%s\n",
                EvData->SendTo.TotalSize, (UINT16)EvData->SendTo.BufferCount,
                EvData->SendTo.SegmentSize, RemoteAddrStr);
        }
        break;
    }
    case EventId_QuicDatapathSendFromTo: {
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        char LocalAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->SendFromTo.Addrs, RemoteAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->SendFromTo.Addrs + EvData->SendFromTo.RemoteAddrLength),
            LocalAddrStr);
        if (EvData->SendFromTo.BufferCount == 1) {
            if (EvData->SendFromTo.SegmentSize == 0 ||
                EvData->SendFromTo.SegmentSize >= EvData->SendFromTo.TotalSize) {
                printf("Send %u bytes Src=%s Dst=%s\n",
                    EvData->SendFromTo.TotalSize, LocalAddrStr, RemoteAddrStr);
            } else {
                printf("Send %u bytes (segment=%hu) Src=%s Dst=%s\n",
                    EvData->SendFromTo.TotalSize, EvData->SendFromTo.SegmentSize,
                    LocalAddrStr, RemoteAddrStr);
            }
        } else {
            printf("Send %u bytes in %hu buffers (segment=%hu) Src=%s Dst=%s\n",
                EvData->SendFromTo.TotalSize, (UINT16)EvData->SendFromTo.BufferCount,
                EvData->SendFromTo.SegmentSize, LocalAddrStr, RemoteAddrStr);
        }
        break;
    }
    case EventId_QuicDatapathRecv: {
        char LocalAddrStr[INET6_ADDRSTRLEN];
        char RemoteAddrStr[INET6_ADDRSTRLEN];
        AddrToString((SOCKADDR_INET*)EvData->Recv.Addrs, LocalAddrStr);
        AddrToString(
            (SOCKADDR_INET*)(EvData->Recv.Addrs + EvData->Recv.LocalAddrLength),
            RemoteAddrStr);
        if (EvData->Recv.SegmentSize == 0 ||
            EvData->Recv.TotalSize <= EvData->Recv.SegmentSize) {
            printf("Recv %u bytes Src=%s Dst=%s\n",
                EvData->Recv.TotalSize, LocalAddrStr, RemoteAddrStr);
        } else {
            printf("Recv %u bytes (segment=%hu) Src=%s Dst=%s\n",
                EvData->Recv.TotalSize, EvData->Recv.SegmentSize,
                LocalAddrStr, RemoteAddrStr);
        }
        break;
    }
    case EventId_QuicDatapathError: {
        printf("ERROR, %s\n", EvData->Error.ErrStr);
        break;
    }
    case EventId_QuicDatapathErrorStatus: {
        printf("ERROR, %u, %s\n", EvData->ErrorStatus.Status, EvData->ErrorStatus.ErrStr);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

void
QuicTraceLogEvent(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_LOG* EvData = (QUIC_EVENT_DATA_LOG*)ev->UserData;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicLogError:
    case EventId_QuicLogWarning:
    case EventId_QuicLogInfo:
    case EventId_QuicLogVerbose:
    case EventId_QuicLogDev:
    case EventId_QuicLogPacketWarning:
    case EventId_QuicLogPacketInfo:
    case EventId_QuicLogPacketVerbose: {
        printf("%s\n", EvData->Msg);
        break;
    }
    default: {
        printf("Unknown Event ID=%u\n", ev->EventHeader.EventDescriptor.Id);
        break;
    }
    }
}

const char* TracePrefix[EventType_Count] = {
    "[ lib] ",
    "[ reg][%.5u] ",
    "[wrkr][%.5u] ",
    "[sess][%.5u] ",
    "[list][%.5u] ",
    "[conn][%.5u] ",
    "[strm][%.5u] ",
    "[bind][%.5u] ",
    "[ tls][%.5u] ",
    "[ udp][%.5u] ",
    NULL
};

void (* TraceEventType[EventType_Count])(_In_ PEVENT_RECORD ev) = {
    QuicTraceGlobalEvent,
    QuicTraceRegistrationEvent,
    QuicTraceWorkerEvent,
    QuicTraceSessionEvent,
    QuicTraceListenerEvent,
    QuicTraceConnEvent,
    QuicTraceStreamEvent,
    QuicTraceBindingEvent,
    QuicTraceTlsEvent,
    QuicTraceDatapathEvent,
    QuicTraceLogEvent
};

void
QuicTraceEvent(
    _In_ PEVENT_RECORD ev,
    _In_ ULONG ObjectId,
    _In_ ULONG64 InitialTimestamp
    )
{
    if (++Trace.OutputLineCount > Cmd.MaxOutputLines) {
        return;
    }

    printf(
        "[%2u|%.4X|%.4X] %.3llu.%03llu ",
        (ULONG)ev->BufferContext.ProcessorNumber,
        ev->EventHeader.ProcessId,
        ev->EventHeader.ThreadId,
        NS100_TO_US(ev->EventHeader.TimeStamp.QuadPart - InitialTimestamp) / 1000,
        NS100_TO_US(ev->EventHeader.TimeStamp.QuadPart - InitialTimestamp) % 1000);

    QUIC_EVENT_TYPE EventType = GetEventType(ev->EventHeader.EventDescriptor.Id);
    if (TracePrefix[EventType] != NULL) {
        printf(TracePrefix[EventType], ObjectId);
    }
    TraceEventType[EventType](ev);
}
