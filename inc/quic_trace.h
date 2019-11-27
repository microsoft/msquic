/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic defines two classes of tracing:

    Events      These are well-defined and have explicit formats. Each event is
                defined with its own, unique function. These are generally used
                for automated log processing (quicetw for instance).

    Logs        These use a printf style format for generally tracing more
                detailed information than Events, and are purely for human
                consumption.

    Each class is individually configurable at compile time. Different platforms
    or build configurations can have their own desired behavior. The following
    configuration options are currently supported:

    QUIC_EVENTS_STUB            No-op all Events
    QUIC_EVENTS_MANIFEST_ETW    Write to Windows ETW framework
    QUIC_EVENTS_SYSLOG          Write to Linux syslog

    QUIC_LOGS_STUB              No-op all Logs
    QUIC_LOGS_WPP               Write to Windows WPP framework
    QUIC_LOGS_MANIFEST_ETW      Write to Windows ETW framework
    QUIC_LOGS_SYSLOG            Write to Linux syslog

 --*/

#ifndef _TRACE_H
#define _TRACE_H

#pragma once

#if !defined(QUIC_EVENTS_STUB) && !defined(QUIC_EVENTS_MANIFEST_ETW) && !defined(QUIC_EVENTS_SYSLOG)
#error "Must define one QUIC_EVENTS_*"
#endif

#if !defined(QUIC_LOGS_STUB) && !defined(QUIC_LOGS_WPP) && !defined(QUIC_LOGS_MANIFEST_ETW) && !defined(QUIC_LOGS_SYSLOG)
#error "Must define one QUIC_LOGS_*"
#endif

typedef enum QUIC_FLOW_BLOCK_REASON {
    QUIC_FLOW_BLOCKED_SCHEDULING            = 0x01,
    QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x02,
    QUIC_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x04,
    QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x08,
    QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x10,
    QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x20,
    QUIC_FLOW_BLOCKED_APP                   = 0x40
} QUIC_FLOW_BLOCK_REASON;

typedef enum QUIC_TRACE_PACKET_TYPE {
    QUIC_TRACE_PACKET_VN,
    QUIC_TRACE_PACKET_INITIAL,
    QUIC_TRACE_PACKET_ZERO_RTT,
    QUIC_TRACE_PACKET_HANDSHAKE,
    QUIC_TRACE_PACKET_RETRY,
    QUIC_TRACE_PACKET_ONE_RTT
} QUIC_TRACE_PACKET_TYPE;

typedef enum QUIC_TRACE_PACKET_LOSS_REASON {
    QUIC_TRACE_PACKET_LOSS_RACK,
    QUIC_TRACE_PACKET_LOSS_FACK,
    QUIC_TRACE_PACKET_LOSS_PROBE
} QUIC_TRACE_PACKET_LOSS_REASON;

typedef enum QUIC_TRACE_API_TYPE {
    QUIC_TRACE_API_SET_PARAM,
    QUIC_TRACE_API_GET_PARAM,
    QUIC_TRACE_API_REGISTRATION_OPEN,
    QUIC_TRACE_API_REGISTRATION_CLOSE,
    QUIC_TRACE_API_SEC_CONFIG_CREATE,
    QUIC_TRACE_API_SEC_CONFIG_DELETE,
    QUIC_TRACE_API_SESSION_OPEN,
    QUIC_TRACE_API_SESSION_CLOSE,
    QUIC_TRACE_API_SESSION_SHUTDOWN,
    QUIC_TRACE_API_LISTENER_OPEN,
    QUIC_TRACE_API_LISTENER_CLOSE,
    QUIC_TRACE_API_LISTENER_START,
    QUIC_TRACE_API_LISTENER_STOP,
    QUIC_TRACE_API_CONNECTION_OPEN,
    QUIC_TRACE_API_CONNECTION_CLOSE,
    QUIC_TRACE_API_CONNECTION_SHUTDOWN,
    QUIC_TRACE_API_CONNECTION_START,
    QUIC_TRACE_API_STREAM_OPEN,
    QUIC_TRACE_API_STREAM_CLOSE,
    QUIC_TRACE_API_STREAM_START,
    QUIC_TRACE_API_STREAM_SHUTDOWN,
    QUIC_TRACE_API_STREAM_SEND,
    QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
    QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED
} QUIC_TRACE_API_TYPE;

typedef enum QUIC_TRACE_LEVEL {
    QUIC_TRACE_LEVEL_DEV,
    QUIC_TRACE_LEVEL_VERBOSE,
    QUIC_TRACE_LEVEL_INFO,
    QUIC_TRACE_LEVEL_WARNING,
    QUIC_TRACE_LEVEL_ERROR,
    QUIC_TRACE_LEVEL_PACKET_VERBOSE,
    QUIC_TRACE_LEVEL_PACKET_INFO,
    QUIC_TRACE_LEVEL_PACKET_WARNING
} QUIC_TRACE_LEVEL;

//
// Called from the platform code to trigger a tracing rundown for all objects
// in the current process (or kernel mode).
//
#ifdef __cplusplus
extern "C"
#endif
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTraceRundown(
    void
    );

#if defined(QUIC_EVENTS_SYSLOG) || defined(QUIC_LOGS_SYSLOG)

#ifdef __cplusplus
extern "C"
#endif
void
QuicSysLogWrite(
    _In_ QUIC_TRACE_LEVEL Level,
    _In_ const char* Fmt,
    ...
    );

#endif // defined(QUIC_EVENTS_SYSLOG) || defined(QUIC_TRACE_SYSLOG)

#if defined(QUIC_EVENTS_STUB) || defined(QUIC_EVENTS_SYSLOG)

#ifdef QUIC_EVENTS_SYSLOG
#define QUIC_WRITE_EVENT QuicSysLogWrite
#else // QUIC_EVENTS_STUB
#define QUIC_WRITE_EVENT(...)
#endif

#define EventWriteQuicLibraryInitialized(PartitionCount, DatapathFeatures) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ lib] Initialized, PartitionCount=%u DatapathFeatures=%u", PartitionCount, DatapathFeatures)
#define EventWriteQuicLibraryUninitialized() \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ lib] Uninitialized")
#define EventWriteQuicLibraryAddRef() \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ lib] AddRef")
#define EventWriteQuicLibraryRelease() \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ lib] Release")
#define EventWriteQuicLibraryWorkerPoolInit() \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ lib] Shared worker pool initializing")
#define EventWriteQuicAllocFailure(Desc, ByteCount) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_WARNING, "Allocation of '%s' failed. (%llu bytes)")
#define EventWriteQuicLibraryRundown(PartitionCount, DatapathFeatures) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ lib] Rundown, PartitionCount=%u DatapathFeatures=%u", PartitionCount, DatapathFeatures)
#define EventWriteQuicLibraryError(ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ lib] ERROR, %s.", ErrStr)
#define EventWriteQuicLibraryErrorStatus(Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ lib] ERROR, 0x%x, %s.", Status, ErrStr)
#define EventWriteQuicLibraryAssert(Line, File, Expression) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ lib] ASSERT, %s:%u - %s.", File, Line, Expression)
#define EventWriteQuicApiEnter(Type, Handle) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Enter %u (%p).", Type, Handle)
#define EventWriteQuicApiExit() \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Exit")
#define EventWriteQuicApiExitStatus(Status) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Exit 0x%x", Status)
#define EventWriteQuicApiWaitOperation() \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Waiting on operation")

#define EventWriteQuicRegistrationCreated(Registration, AppName) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Created, AppName=%s", Registration, AppName)
#define EventWriteQuicRegistrationDestroyed(Registration) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Destroyed", Registration)
#define EventWriteQuicRegistrationCleanup(Registration) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Cleanup", Registration)
#define EventWriteQuicRegistrationRundown(Registration, AppName) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Rundown, AppName=%s", Registration, AppName)
#define EventWriteQuicRegistrationError(Registration, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ reg][%p] ERROR, %s", Registration, ErrStr)
#define EventWriteQuicRegistrationErrorStatus(Registration, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ reg][%p] ERROR, %u, %s", Registration, Status, ErrStr)

#define EventWriteQuicWorkerCreated(Worker, IdealProcessor, Owner) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Created, IdealProc=%u Owner=%p", Worker, IdealProcessor, Owner)
#define EventWriteQuicWorkerStart(Worker) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Start", Worker)
#define EventWriteQuicWorkerStop(Worker) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Stop", Worker)
#define EventWriteQuicWorkerActivityStateUpdated(Worker, IsActive, Arg) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[wrkr][%p] IsActive = %u, Arg = %u", IsActive, Arg)
#define EventWriteQuicWorkerQueueDelayUpdated(Worker, QueueDelay) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[wrkr][%p] QueueDelay: %u us", Worker, QueueDelay)
#define EventWriteQuicWorkerDestroyed(Worker) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Destroyed", Worker)
#define EventWriteQuicWorkerCleanup(Worker) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Cleanup", Worker)
#define EventWriteQuicWorkerError(Worker, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[wrkr][%p] ERROR, %s", Worker, ErrStr)
#define EventWriteQuicWorkerErrorStatus(Worker, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[wrkr][%p] ERROR, %u, %s", Worker, Status, ErrStr)

#define EventWriteQuicSessionCreated(Session, Registration, Alpn) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Created, Registration=%p, ALPN='%s'", Session, Registration, Alpn)
#define EventWriteQuicSessionDestroyed(Session) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Destroyed", Session)
#define EventWriteQuicSessionCleanup(Session) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Cleanup", Session)
#define EventWriteQuicSessionShutdown(Session, Flags, ErrorCode) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Shutdown, Flags=0x%x, ErrorCode=%llu", Session, Flags, ErrorCode)
#define EventWriteQuicSessionRundown(Session, Registration, Alpn) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Rundown, Registration=%p, ALPN='%s'", Session, Registration, Alpn)
#define EventWriteQuicSessionError(Session, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[sess][%p] ERROR, %s", Session, ErrStr)
#define EventWriteQuicSessionErrorStatus(Session, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[sess][%p] ERROR, %u, %s", Session, Status, ErrStr)

#define EventWriteQuicListenerCreated(Listener, Session) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[list][%p] Created, Session=%p", Listener, Session)
#define EventWriteQuicListenerDestroyed(Listener) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[list][%p] Destroyed", Listener)
#define EventWriteQuicListenerStarted(Listener, Binding, AddrLen, Addr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[list][%p] Started, Binding=%p, Addr=TODO", Listener, Binding)
#define EventWriteQuicListenerStopped(Listener) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[list][%p] Stopped", Listener)
#define EventWriteQuicListenerRundown(Listener, Session) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[list][%p] Rundown, Session=%p", Listener, Session)
#define EventWriteQuicListenerError(Listener, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[list][%p] ERROR, %s", Listener, ErrStr)
#define EventWriteQuicListenerErrorStatus(Listener, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[list][%p] ERROR, %u, %s", Listener, Status, ErrStr)

#define EventWriteQuicConnCreated(Connection, IsServer, CorrelationId) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Created, Server=%u, CorrelationId=%llu", Connection, IsServer, CorrelationId)
#define EventWriteQuicConnDestroyed(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Destroyed", Connection)
#define EventWriteQuicConnHandshakeComplete(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Handshake complete", Connection)
#define EventWriteQuicConnScheduleState(Connection, State) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Scheduling: %u", Connection, State)
#define EventWriteQuicConnExecOper(Connection, Type) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Execute: %u", Connection, Type)
#define EventWriteQuicConnExecApiOper(Connection, Type) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Execute: API %u", Connection, Type)
#define EventWriteQuicConnExecTimerOper(Connection, Type) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Execute: Timer %u", Connection, Type)
#define EventWriteQuicConnLocalAddrAdded(Connection, AddrLen, Addr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Local IP: TODO", Connection)
#define EventWriteQuicConnRemoteAddrAdded(Connection, AddrLen, Addr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Remote IP: TODO", Connection)
#define EventWriteQuicConnLocalAddrRemoved(Connection, AddrLen, Addr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Local IP: TODO", Connection)
#define EventWriteQuicConnRemoteAddrRemoved(Connection, AddrLen, Addr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Remote IP: TODO", Connection)
#define EventWriteQuicConnAssignWorker(Connection, Worker) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Assigned worker %p", Connection, Worker)
#define EventWriteQuicConnHandshakeStart(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Handshake start", Connection)
#define EventWriteQuicConnRegisterSession(Connection, Session) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Registered with session: %p", Connection, Session)
#define EventWriteQuicConnUnregisterSession(Connection, Session) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Unregistered from session: %p", Connection, Session)
#define EventWriteQuicConnTransportShutdown(Connection, ErrorCode, IsRemoteShutdown, IsQuicStatus) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Transport Shutdown: 0x%x (Remote=%u) (QS=%u)", Connection, ErrorCode, IsRemoteShutdown, IsQuicStatus)
#define EventWriteQuicConnAppShutdown(Connection, ErrorCode, IsRemoteShutdown) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] App Shutdown: 0x%x (Remote=%u)", ErrorCode, IsRemoteShutdown)
#define EventWriteQuicConnInitializeComplete(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Initialize complete", Connection)
#define EventWriteQuicConnHandleClosed(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Handle closed", Connection)
#define EventWriteQuicConnVersionSet(Connection, Value) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Version: 0x%x", Connection, Value)
#define EventWriteQuicConnOutFlowStats(Connection, BytesSent, BytesInFlight, BytesInFlightMax, CongestionWindow, SlowStartThreshold, ConnectionFlowControl, StreamFlowControl, IdealBytes, PostedBytes, SmoothedRtt, StreamSendWindow) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu StreamFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u StreamSndWnd=%llu", Connection, \
        BytesSent, BytesInFlight, BytesInFlightMax, CongestionWindow, SlowStartThreshold, ConnectionFlowControl, StreamFlowControl, IdealBytes, PostedBytes, SmoothedRtt, StreamSendWindow)
#define EventWriteQuicConnOutFlowBlocked(Connection, ReasonFlags) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Send Blocked: 0x%x", Connection, ReasonFlags)
#define EventEnabledQuicConnOutFlowStats() TRUE
#define EventWriteQuicConnInFlowStats(Connection, BytesReceived) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] IN: BytesRecv=%llu", Connection, BytesReceived)
#define EventWriteQuicConnCubic(Connection, SlowStartThreshold, K, WindowMax, WindowLastMax) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u", Connection, SlowStartThreshold, K, WindowMax, WindowLastMax)
#define EventWriteQuicConnCongestion(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Congestion event", Connection)
#define EventWriteQuicConnPersistentCongestion(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Persistent congestion event", Connection)
#define EventWriteQuicConnRecoveryExit(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Recovery exit", Connection)
#define EventWriteQuicConnRundown(Connection, IsServer, CorrelationId) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Rundown, Server=%u, CorrelationId=%llu", Connection, IsServer, CorrelationId)
#define EventWriteQuicConnSourceCidAdded(Connection, CidLen, Cid) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Source CID: TODO", Connection)
#define EventWriteQuicConnDestCidAdded(Connection, CidLen, Cid) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Destination CID: TODO", Connection)
#define EventWriteQuicConnSourceCidRemoved(Connection, CidLen, Cid) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Source CID: TODO", Connection)
#define EventWriteQuicConnDestCidRemoved(Connection, CidLen, Cid) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Destination CID: TODO", Connection)
#define EventWriteQuicConnLossDetectionTimerSet(Connection, TimerType, DelayMs, ProbeCount) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Setting loss detection timer (type %u) for %u ms. (ProbeCount=%hu)", TimerType, DelayMs, ProbeCount)
#define EventWriteQuicConnLossDetectionTimerCancel(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Cancelling loss detection timer.", Connection)
#define EventWriteQuicConnDropPacket(Connection, PktNum, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s", Connection, PktNum, Reason)
#define EventWriteQuicConnDropPacketEx(Connection, PktNum, Value, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s, %u", Connection, PktNum, Reason, Value)
#define EventWriteQuicConnError(Connection, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[conn][%p] ERROR, %s", Connection, ErrStr)
#define EventWriteQuicConnErrorStatus(Connection, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[conn][%p] ERROR, %u, %s", Connection, Status, ErrStr)
#define EventWriteQuicConnNewPacketKeys(Connection) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New packet keys generated", Connection)
#define EventWriteQuicConnKeyPhaseChange(Connection, IsLocallyInitiated) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Key phase change, IsLocallyInitiated=%u", Connection, IsLocallyInitiated)
#define EventWriteQuicConnStatistics(Connection, LifeTimeUs, SendTotalPackets, SendSuspectedLostPackets, SendSpuriousLostPackets, RecvTotalPackets, RecvReorderedPackets, RecvDroppedPackets, RecvDuplicatePackets, RecvDecryptionFailures, CongestionCount, PersistentCongestionCount, SendTotalBytes, RecvTotalBytes, SmoothedRtt) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] STATS: LifeTimeUs=%llu SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu SmoothedRtt=%u", \
    Connection, LifeTimeUs, SendTotalPackets, SendSuspectedLostPackets, SendSpuriousLostPackets, RecvTotalPackets, RecvReorderedPackets, RecvDroppedPackets, RecvDuplicatePackets, RecvDecryptionFailures, CongestionCount, PersistentCongestionCount, SendTotalBytes, RecvTotalBytes, SmoothedRtt)
#define EventWriteQuicConnShutdownComplete(Connection, TimedOut) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Shutdown Complete, PeerFailedToAcknowledged=%u", Connection, TimedOut)
#define EventWriteQuicConnReadKeyUpdated(Connection, NewValue) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Read Key Updated, %u", Connection, NewValue)
#define EventWriteQuicConnWriteKeyUpdated(Connection, NewValue) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Write Key Updated, %u", Connection, NewValue)
#define EventWriteQuicConnPacketSent(Connection, Number, Type, Length) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [TX][%llu] %u (%hu bytes)", Connection, Number, Type, Length)
#define EventWriteQuicConnPacketRecv(Connection, Number, Type, Length) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [RX][%llu] %u (%hu bytes)", Connection, Number, Type, Length)
#define EventWriteQuicConnPacketLost(Connection, Number, Type, Reason) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [TX][%llu] %u Lost: %u", Connection, Number, Type, Reason)
#define EventWriteQuicConnPacketACKed(Connection, Number, Type) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [TX][%llu] %u ACKed", Connection, Number, Type)

#define EventWriteQuicStreamCreated(Stream, Connection, ID, IsLocalOwned) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Created, Connection=%p ID=%llu IsLocal=%hu", Stream, Connection, ID, IsLocalOwned)
#define EventWriteQuicStreamDestroyed(Stream) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Destroyed", Stream)
#define EventWriteQuicStreamOutFlowBlocked(Stream, ReasonFlags) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Send Blocked: 0x%x", Stream, ReasonFlags)
#define EventWriteQuicStreamRundown(Stream, Connection, ID, IsLocalOwned) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Rundown, Connection=%p ID=%llu IsLocal=%hu", Stream, Connection, ID, IsLocalOwned)
#define EventWriteQuicStreamSendState(Stream, State) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Send State: %u", Stream, State)
#define EventWriteQuicStreamRecvState(Stream, State) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Recv State: %u", Stream, State)
#define EventWriteQuicStreamError(Stream, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[strm][%p] ERROR, %s", Stream, ErrStr)
#define EventWriteQuicStreamErrorStatus(Stream, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[strm][%p] ERROR, %u, %s", Stream,  Status, ErrStr)

#define EventWriteQuicBindingCreated(Binding, UdpBinding, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Created %p, Udp=%llX LocalAddr=TODO RemoteAddr=TODO", Binding, UdpBinding);\
    UNREFERENCED_PARAMETER(RemoteAddr); UNREFERENCED_PARAMETER(LocalAddr)
#define EventWriteQuicBindingRundown(Binding, UdpBinding, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Rundown %p, Udp=%llX LocalAddr=TODO RemoteAddr=TODO", Binding, UdpBinding);\
    UNREFERENCED_PARAMETER(RemoteAddr); UNREFERENCED_PARAMETER(LocalAddr)
#define EventWriteQuicBindingDestroyed(Binding) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Destroyed", Binding)
#define EventWriteQuicBindingCleanup(Binding) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Cleaning up", Binding)
#define EventWriteQuicBindingDropPacket(Binding, PktNum, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[bind][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s", Binding, PktNum, Reason)
#define EventWriteQuicBindingDropPacketEx(Binding, PktNum, Value, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_INFO, "[bind][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s, %u", Binding, PktNum, Reason, Value)
#define EventWriteQuicBindingError(Binding, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[bind][%p] ERROR, %s", Binding, ErrStr)
#define EventWriteQuicBindingErrorStatus(Binding, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[bind][%p] ERROR, %u, %s", Binding,  Status, ErrStr)
#define EventWriteQuicBindingExecOper(Binding, OperType) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[bind][%p] Execute: %u", Binding, OperType)

#define EventWriteQuicTlsError(Connection, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ tls][%p] ERROR, %s", Connection, ErrStr)
#define EventWriteQuicTlsErrorStatus(Connection, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ tls][%p] ERROR, %u, %s", Connection, Status, ErrStr)

#define EventWriteMiTLSTrace(Message) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[mitls] %s", Message)

#define EventWriteQuicDatapathSendTo(Binding, TotalSize, BufferCount, SegmentSize, RemoteAddrLen, RemoteAddr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ udp][%p] Send %u bytes in %u buffers (segment=%u) Dst=TODO", Binding, TotalSize, BufferCount, SegmentSize)
#define EventWriteQuicDatapathSendFromTo(Binding, TotalSize, BufferCount, SegmentSize, RemoteAddrLen, LocalAddrLen, RemoteAddr, LocalAddr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ udp][%p] Send %u bytes in %u buffers (segment=%u) Src=TODO Dst=TODO", Binding, TotalSize, BufferCount, SegmentSize)
#define EventWriteQuicDatapathRecv(Binding, TotalSize, SegmentSize, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_VERBOSE, "[ udp][%p] Recv %u bytes (segment=%u) Src=TODO Dst=TODO", Binding, TotalSize, SegmentSize)
#define EventWriteQuicDatapathError(Binding, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ udp][%p] ERROR, %s", Binding, ErrStr)
#define EventWriteQuicDatapathErrorStatus(Binding, Status, ErrStr) \
    QUIC_WRITE_EVENT(QUIC_TRACE_LEVEL_ERROR, "[ udp][%p] ERROR, %u, %s", Binding, Status, ErrStr)

#define LOG_ADDR_LEN(Addr) sizeof(Addr)

#endif // defined(QUIC_EVENTS_STUB) || defined(QUIC_EVENTS_SYSLOG)

#ifdef QUIC_EVENTS_MANIFEST_ETW

#include <evntprov.h>

#ifdef __cplusplus
extern "C"
#endif
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
void
NTAPI
QuicEtwCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG ControlCode,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext
    );

//
// Defining MCGEN_PRIVATE_ENABLE_CALLBACK_V2, makes McGenControlCallbackV2
// call our user-defined callback routine. See MsQuicEvents.h.
//
#define MCGEN_PRIVATE_ENABLE_CALLBACK_V2 QuicEtwCallback

#include "MsQuicEtw.h"

#define LOG_ADDR_LEN(Addr) \
    (uint8_t)((Addr).si_family == AF_INET6 ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN))

#endif // QUIC_EVENTS_MANIFEST_ETW

#ifdef QUIC_LOGS_STUB

#define WPP_COMPID_LEVEL_ENABLED(...) 0

#define LogFuncEntryMsg(...)
#define LogFuncEntry(...)
#define LogFuncExit(...)
#define LogVerbose(...)
#define LogWarning(...)
#define LogError(...)
#define LogInfo(...)
#define LogFuncExitMsg(...)
#define LogPacketVerbose(...)
#define LogPacketInfo(...)
#define LogDev(...)
#define LogPacketWarning(...)
#define LogTLS(...)

#endif // QUIC_LOGS_STUB

#ifdef QUIC_LOGS_WPP

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer

#include <fastwpp.h>

//
// WPP Tracing
// {620FD025-BE51-42EF-A5C0-50F13F183AD9}
//

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(quicGUID,(620FD025,BE51,42EF,A5C0,50F13F183AD9),  \
        WPP_DEFINE_BIT(FLAG_DEFAULT)          \
        WPP_DEFINE_BIT(FLAG_PACKET)           \
        WPP_DEFINE_BIT(FLAG_DEVELOPMENT)      \
        )

#ifdef WPP_COMPID_LEVEL_ENABLED
#undef WPP_COMPID_LEVEL_ENABLED
#endif

#define WPP_COMPID_LEVEL_ENABLED(CTL,LEVEL)                            \
    ((WPP_CONTROL (WPP_BIT_##CTL).Level >= LEVEL) &&                   \
     (WPP_CONTROL (WPP_BIT_##CTL).Flags[WPP_FLAG_NO (WPP_BIT_##CTL)] & \
      WPP_MASK (WPP_BIT_##CTL)))

#ifndef WPP_COMPID_LEVEL_LOGGER
#define WPP_COMPID_LEVEL_LOGGER(CTL,LEVEL)      \
    (WPP_CONTROL(WPP_BIT_ ## CTL).Logger),
#endif

#define WPP_COMPID_LEVEL__ENABLED(COMPID,LEVEL,DUMMY)   \
    WPP_COMPID_LEVEL_ENABLED (COMPID,LEVEL)
#define WPP_COMPID_LEVEL__LOGGER(COMPID,LEVEL,DUMMY)    \
    WPP_COMPID_LEVEL_LOGGER (COMPID,LEVEL)

#define WPP_COMPID_LEVEL_EXP_ENABLED(COMPID,LEVEL,EXP)  \
    WPP_COMPID_LEVEL_ENABLED (COMPID,LEVEL)
#define WPP_COMPID_LEVEL_EXP_LOGGER(COMPID,LEVEL,EXP)   \
    WPP_COMPID_LEVEL_LOGGER (COMPID,LEVEL)

#define WPP_COMPID_LEVEL__PRE(COMPID,LEVEL,DUMMY)
#define WPP_COMPID_LEVEL__POST(COMPID,LEVEL,DUMMY)

// begin_wpp config
// USEPREFIX (LogError, " ");
// FUNC LogError{LEVEL=TRACE_LEVEL_ERROR,FLAGS=FLAG_DEFAULT}(MSG,...);
// end_wpp

// begin_wpp config
// USEPREFIX (LogWarning, " ");
// FUNC LogWarning{LEVEL=TRACE_LEVEL_WARNING,FLAGS=FLAG_DEFAULT}(MSG,...);
// end_wpp

// begin_wpp config
// USEPREFIX (LogInfo, " ");
// FUNC LogInfo{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FLAG_DEFAULT}(MSG,...);
// end_wpp

// begin_wpp config
// USEPREFIX (LogVerbose, " ");
// FUNC LogVerbose{LEVEL=TRACE_LEVEL_VERBOSE,FLAGS=FLAG_DEFAULT}(MSG,...);
// end_wpp

//
// Packet
//

// begin_wpp config
// USEPREFIX (LogPacketWarning, " ");
// FUNC LogPacketWarning{LEVEL=TRACE_LEVEL_WARNING,FLAGS=FLAG_PACKET}(MSG,...);
// end_wpp

// begin_wpp config
// USEPREFIX (LogPacketInfo, " ");
// FUNC LogPacketInfo{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FLAG_PACKET}(MSG,...);
// end_wpp

// begin_wpp config
// USEPREFIX (LogPacketVerbose, " ");
// FUNC LogPacketVerbose{LEVEL=TRACE_LEVEL_VERBOSE,FLAGS=FLAG_PACKET}(MSG,...);
// end_wpp

//
// Development
//

// begin_wpp config
// USEPREFIX (LogDev, " ");
// FUNC LogDev{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FLAG_DEVELOPMENT}(MSG,...);
// end_wpp

typedef struct _ByteArray {
    USHORT usLength;
    const void * pvBuffer;
} ByteArray;

__inline ByteArray
log_hexbuf(const void* Buffer, UINT32 Length) {
    ByteArray Bytes = { (USHORT)Length, Buffer };
    return Bytes;
}

#define WPP_LOGHEXBUF(x) \
    WPP_LOGPAIR(2, &((x).usLength)) \
    WPP_LOGPAIR((x).usLength, (x).pvBuffer)

// begin_wpp config
// DEFINE_CPLX_TYPE(IPV4ADDR, WPP_LOGIPV4, const IN_ADDR *, ItemIPAddr, "s", _IPV4_, 0);
// DEFINE_CPLX_TYPE(IPV6ADDR, WPP_LOGIPV6, const IN6_ADDR *, ItemIPV6Addr, "s", _IPV6_, 0);
// DEFINE_CPLX_TYPE(HEXBUF, WPP_LOGHEXBUF, ByteArray, ItemHEXDump,"s", _HEX_, 0, 2);
// WPP_FLAGS(-DLOG_HEXBUF(buffer,length)=log_hexbuf(buffer,length));
// end_wpp

#ifdef __cplusplus
}
#endif

#endif // QUIC_LOGS_WPP

#ifdef QUIC_LOGS_MANIFEST_ETW

#include "MsQuicEtw.h"
#include <stdio.h>

#define WPP_COMPID_LEVEL_ENABLED(...) TRUE

#define LogEtw(EventName, Fmt, ...) \
    if (EventEnabledQuicLog##EventName()) { \
        char EtwBuffer[256]; \
        sprintf_s(EtwBuffer, 256, Fmt, ##__VA_ARGS__); \
        EventWriteQuicLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogError(Fmt, ...)          LogEtw(Error, Fmt, ##__VA_ARGS__)
#define LogWarning(Fmt, ...)        LogEtw(Warning, Fmt, ##__VA_ARGS__)
#define LogInfo(Fmt, ...)           LogEtw(Info, Fmt, ##__VA_ARGS__)
#define LogVerbose(Fmt, ...)        LogEtw(Verbose, Fmt, ##__VA_ARGS__)
#define LogDev(Fmt, ...)            LogEtw(Dev, Fmt, ##__VA_ARGS__)
#define LogPacketWarning(Fmt, ...)  LogEtw(PacketWarning, Fmt, ##__VA_ARGS__)
#define LogPacketInfo(Fmt, ...)     LogEtw(PacketInfo, Fmt, ##__VA_ARGS__)
#define LogPacketVerbose(Fmt, ...)  LogEtw(PacketVerbose, Fmt, ##__VA_ARGS__)

#endif // QUIC_LOGS_MANIFEST_ETW

#ifdef QUIC_LOGS_SYSLOG

#define WPP_COMPID_LEVEL_ENABLED(...) TRUE

#define LogDev(Fmt, ...)            QuicSysLogWrite(QUIC_TRACE_LEVEL_DEV, Fmt, ##__VA_ARGS__)
#define LogVerbose(Fmt, ...)        QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, Fmt, ##__VA_ARGS__)
#define LogInfo(Fmt, ...)           QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, Fmt, ##__VA_ARGS__)
#define LogWarning(Fmt, ...)        QuicSysLogWrite(QUIC_TRACE_LEVEL_WARNING, Fmt, ##__VA_ARGS__)
#define LogError(Fmt, ...)          QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, Fmt, ##__VA_ARGS__)
#define LogPacketVerbose(Fmt, ...)  QuicSysLogWrite(QUIC_TRACE_LEVEL_PACKET_VERBOSE, Fmt, ##__VA_ARGS__)
#define LogPacketInfo(Fmt, ...)     QuicSysLogWrite(QUIC_TRACE_LEVEL_PACKET_INFO, Fmt, ##__VA_ARGS__)
#define LogPacketWarning(Fmt, ...)  QuicSysLogWrite(QUIC_TRACE_LEVEL_PACKET_WARNING, Fmt, ##__VA_ARGS__)

#endif // QUIC_LOGS_SYSLOG

#endif // _TRACE_H
