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
    QUIC_EVENTS_LTTNG           Write to Linux LTTng framework

    QUIC_LOGS_STUB              No-op all Logs
    QUIC_LOGS_WPP               Write to Windows WPP framework
    QUIC_LOGS_MANIFEST_ETW      Write to Windows ETW framework
    QUIC_LOGS_SYSLOG            Write to Linux syslog
    QUIC_LOGS_LTTNG             Write to Linux LTTng framework

 --*/

#ifndef _TRACE_H
#define _TRACE_H

#pragma once

#if !defined(QUIC_EVENTS_STUB) && !defined(QUIC_EVENTS_MANIFEST_ETW) && !defined(QUIC_EVENTS_SYSLOG) && !defined(QUIC_EVENTS_LTTNG)
#error "Must define one QUIC_EVENTS_*"
#endif

#if !defined(QUIC_LOGS_STUB) && !defined(QUIC_LOGS_WPP) && !defined(QUIC_LOGS_MANIFEST_ETW) && !defined(QUIC_LOGS_SYSLOG) && !defined(QUIC_LOGS_LTTNG)
#error "Must define one QUIC_LOGS_*"
#endif

typedef enum QUIC_FLOW_BLOCK_REASON {
    QUIC_FLOW_BLOCKED_SCHEDULING            = 0x01,
    QUIC_FLOW_BLOCKED_PACING                = 0x02,
    QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x04,
    QUIC_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x08,
    QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x10,
    QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x20,
    QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x40,
    QUIC_FLOW_BLOCKED_APP                   = 0x80
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

#endif // defined(QUIC_EVENTS_SYSLOG) || defined(QUIC_LOGS_SYSLOG)

#ifdef QUIC_EVENTS_STUB

#define QuicTraceEventEnabled(Name) FALSE
#define QuicTraceEvent(Name, ...)
#define LOG_ADDR_LEN(Addr)

#endif // QUIC_EVENTS_STUB

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

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#include "MsQuicEtw.h"
#pragma warning(pop)

#define QuicTraceEventEnabled(Name) EventEnabledQuic##Name()
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(Name, ...) _QuicTraceEvent(Name, (__VA_ARGS__))

#define LOG_ADDR_LEN(Addr) \
    (uint8_t)((Addr).si_family == AF_INET6 ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN))

#endif // QUIC_EVENTS_MANIFEST_ETW

#ifdef QUIC_EVENTS_SYSLOG

#define QuicTraceEventEnabled(Name) TRUE
#define QuicTraceEvent(Name, ...) EventWriteQuic##Name(__VA_ARGS__)

#define EventWriteQuicLibraryInitialized(PartitionCount, DatapathFeatures) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ lib] Initialized, PartitionCount=%u DatapathFeatures=%u", PartitionCount, DatapathFeatures)
#define EventWriteQuicLibraryUninitialized() \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ lib] Uninitialized")
#define EventWriteQuicLibraryAddRef() \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ lib] AddRef")
#define EventWriteQuicLibraryRelease() \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ lib] Release")
#define EventWriteQuicLibraryWorkerPoolInit() \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ lib] Shared worker pool initializing")
#define EventWriteQuicAllocFailure(Desc, ByteCount) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_WARNING, "Allocation of '%s' failed. (%llu bytes)", Desc, ByteCount)
#define EventWriteQuicLibraryRundown(PartitionCount, DatapathFeatures) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ lib] Rundown, PartitionCount=%u DatapathFeatures=%u", PartitionCount, DatapathFeatures)
#define EventWriteQuicLibraryError(ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ lib] ERROR, %s.", ErrStr)
#define EventWriteQuicLibraryErrorStatus(Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ lib] ERROR, 0x%x, %s.", Status, ErrStr)
#define EventWriteQuicLibraryAssert(Line, File, Expression) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ lib] ASSERT, %s:%u - %s.", File, Line, Expression)
#define EventWriteQuicApiEnter(Type, Handle) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Enter %u (%p).", Type, Handle)
#define EventWriteQuicApiExit() \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Exit")
#define EventWriteQuicApiExitStatus(Status) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Exit 0x%x", Status)
#define EventWriteQuicApiWaitOperation() \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ api] Waiting on operation")

#define EventWriteQuicRegistrationCreated(Registration, AppName) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Created, AppName=%s", Registration, AppName)
#define EventWriteQuicRegistrationDestroyed(Registration) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Destroyed", Registration)
#define EventWriteQuicRegistrationCleanup(Registration) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Cleanup", Registration)
#define EventWriteQuicRegistrationRundown(Registration, AppName) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[ reg][%p] Rundown, AppName=%s", Registration, AppName)
#define EventWriteQuicRegistrationError(Registration, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ reg][%p] ERROR, %s", Registration, ErrStr)
#define EventWriteQuicRegistrationErrorStatus(Registration, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ reg][%p] ERROR, %u, %s", Registration, Status, ErrStr)

#define EventWriteQuicWorkerCreated(Worker, IdealProcessor, Owner) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Created, IdealProc=%u Owner=%p", Worker, IdealProcessor, Owner)
#define EventWriteQuicWorkerStart(Worker) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Start", Worker)
#define EventWriteQuicWorkerStop(Worker) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Stop", Worker)
#define EventWriteQuicWorkerActivityStateUpdated(Worker, IsActive, Arg) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[wrkr][%p] IsActive = %u, Arg = %u", IsActive, Arg)
#define EventWriteQuicWorkerQueueDelayUpdated(Worker, QueueDelay) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[wrkr][%p] QueueDelay: %u us", Worker, QueueDelay)
#define EventWriteQuicWorkerDestroyed(Worker) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Destroyed", Worker)
#define EventWriteQuicWorkerCleanup(Worker) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[wrkr][%p] Cleanup", Worker)
#define EventWriteQuicWorkerError(Worker, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[wrkr][%p] ERROR, %s", Worker, ErrStr)
#define EventWriteQuicWorkerErrorStatus(Worker, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[wrkr][%p] ERROR, %u, %s", Worker, Status, ErrStr)

#define EventWriteQuicSessionCreated(Session, Registration, Alpn) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Created, Registration=%p, ALPN='%s'", Session, Registration, Alpn)
#define EventWriteQuicSessionDestroyed(Session) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Destroyed", Session)
#define EventWriteQuicSessionCleanup(Session) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Cleanup", Session)
#define EventWriteQuicSessionShutdown(Session, Flags, ErrorCode) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Shutdown, Flags=0x%x, ErrorCode=%llu", Session, Flags, ErrorCode)
#define EventWriteQuicSessionRundown(Session, Registration, Alpn) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[sess][%p] Rundown, Registration=%p, ALPN='%s'", Session, Registration, Alpn)
#define EventWriteQuicSessionError(Session, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[sess][%p] ERROR, %s", Session, ErrStr)
#define EventWriteQuicSessionErrorStatus(Session, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[sess][%p] ERROR, %u, %s", Session, Status, ErrStr)

#define EventWriteQuicListenerCreated(Listener, Session) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[list][%p] Created, Session=%p", Listener, Session)
#define EventWriteQuicListenerDestroyed(Listener) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[list][%p] Destroyed", Listener)
#define EventWriteQuicListenerStarted(Listener, Binding, AddrLen, Addr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[list][%p] Started, Binding=%p, Addr=TODO", Listener, Binding)
#define EventWriteQuicListenerStopped(Listener) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[list][%p] Stopped", Listener)
#define EventWriteQuicListenerRundown(Listener, Session) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[list][%p] Rundown, Session=%p", Listener, Session)
#define EventWriteQuicListenerError(Listener, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[list][%p] ERROR, %s", Listener, ErrStr)
#define EventWriteQuicListenerErrorStatus(Listener, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[list][%p] ERROR, %u, %s", Listener, Status, ErrStr)

#define EventWriteQuicConnCreated(Connection, IsServer, CorrelationId) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Created, Server=%u, CorrelationId=%llu", Connection, IsServer, CorrelationId)
#define EventWriteQuicConnDestroyed(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Destroyed", Connection)
#define EventWriteQuicConnHandshakeComplete(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Handshake complete", Connection)
#define EventWriteQuicConnScheduleState(Connection, State) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Scheduling: %u", Connection, State)
#define EventWriteQuicConnExecOper(Connection, Type) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Execute: %u", Connection, Type)
#define EventWriteQuicConnExecApiOper(Connection, Type) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Execute: API %u", Connection, Type)
#define EventWriteQuicConnExecTimerOper(Connection, Type) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Execute: Timer %u", Connection, Type)
#define EventWriteQuicConnLocalAddrAdded(Connection, AddrLen, Addr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Local IP: TODO", Connection)
#define EventWriteQuicConnRemoteAddrAdded(Connection, AddrLen, Addr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Remote IP: TODO", Connection)
#define EventWriteQuicConnLocalAddrRemoved(Connection, AddrLen, Addr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Local IP: TODO", Connection)
#define EventWriteQuicConnRemoteAddrRemoved(Connection, AddrLen, Addr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Remote IP: TODO", Connection)
#define EventWriteQuicConnAssignWorker(Connection, Worker) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Assigned worker %p", Connection, Worker)
#define EventWriteQuicConnHandshakeStart(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Handshake start", Connection)
#define EventWriteQuicConnRegisterSession(Connection, Session) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Registered with session: %p", Connection, Session)
#define EventWriteQuicConnUnregisterSession(Connection, Session) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Unregistered from session: %p", Connection, Session)
#define EventWriteQuicConnTransportShutdown(Connection, ErrorCode, IsRemoteShutdown, IsQuicStatus) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Transport Shutdown: 0x%x (Remote=%u) (QS=%u)", Connection, ErrorCode, IsRemoteShutdown, IsQuicStatus)
#define EventWriteQuicConnAppShutdown(Connection, ErrorCode, IsRemoteShutdown) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] App Shutdown: 0x%x (Remote=%u)", ErrorCode, IsRemoteShutdown)
#define EventWriteQuicConnInitializeComplete(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Initialize complete", Connection)
#define EventWriteQuicConnHandleClosed(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Handle closed", Connection)
#define EventWriteQuicConnVersionSet(Connection, Value) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Version: 0x%x", Connection, Value)
#define EventWriteQuicConnOutFlowStats(Connection, BytesSent, BytesInFlight, BytesInFlightMax, CongestionWindow, SlowStartThreshold, ConnectionFlowControl, StreamFlowControl, IdealBytes, PostedBytes, SmoothedRtt, StreamSendWindow) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu StreamFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u StreamSndWnd=%llu", Connection, \
        BytesSent, BytesInFlight, BytesInFlightMax, CongestionWindow, SlowStartThreshold, ConnectionFlowControl, StreamFlowControl, IdealBytes, PostedBytes, SmoothedRtt, StreamSendWindow)
#define EventWriteQuicConnOutFlowBlocked(Connection, ReasonFlags) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Send Blocked: 0x%x", Connection, ReasonFlags)
#define EventEnabledQuicConnOutFlowStats() TRUE
#define EventWriteQuicConnInFlowStats(Connection, BytesReceived) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] IN: BytesRecv=%llu", Connection, BytesReceived)
#define EventWriteQuicConnCubic(Connection, SlowStartThreshold, K, WindowMax, WindowLastMax) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u", Connection, SlowStartThreshold, K, WindowMax, WindowLastMax)
#define EventWriteQuicConnCongestion(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Congestion event", Connection)
#define EventWriteQuicConnPersistentCongestion(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Persistent congestion event", Connection)
#define EventWriteQuicConnRecoveryExit(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Recovery exit", Connection)
#define EventWriteQuicConnRundown(Connection, IsServer, CorrelationId) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Rundown, Server=%u, CorrelationId=%llu", Connection, IsServer, CorrelationId)
#define EventWriteQuicConnSourceCidAdded(Connection, SequenceNumber, CidLen, Cid) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Source CID: TODO", Connection)
#define EventWriteQuicConnDestCidAdded(Connection, SequenceNumber, CidLen, Cid) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New Destination CID: TODO", Connection)
#define EventWriteQuicConnSourceCidRemoved(Connection, SequenceNumber, CidLen, Cid) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Source CID: TODO", Connection)
#define EventWriteQuicConnDestCidRemoved(Connection, SequenceNumber, CidLen, Cid) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Removed Destination CID: TODO", Connection)
#define EventWriteQuicConnLossDetectionTimerSet(Connection, TimerType, DelayMs, ProbeCount) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Setting loss detection timer (type %u) for %u ms. (ProbeCount=%hu)", TimerType, DelayMs, ProbeCount)
#define EventWriteQuicConnLossDetectionTimerCancel(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Cancelling loss detection timer.", Connection)
#define EventWriteQuicConnDropPacket(Connection, PktNum, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s", Connection, PktNum, Reason)
#define EventWriteQuicConnDropPacketEx(Connection, PktNum, Value, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s, %u", Connection, PktNum, Reason, Value)
#define EventWriteQuicConnError(Connection, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[conn][%p] ERROR, %s", Connection, ErrStr)
#define EventWriteQuicConnErrorStatus(Connection, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[conn][%p] ERROR, %u, %s", Connection, Status, ErrStr)
#define EventWriteQuicConnNewPacketKeys(Connection) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] New packet keys generated", Connection)
#define EventWriteQuicConnKeyPhaseChange(Connection, IsLocallyInitiated) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Key phase change, IsLocallyInitiated=%u", Connection, IsLocallyInitiated)
#define EventWriteQuicConnStatistics(Connection, LifeTimeUs, SendTotalPackets, SendSuspectedLostPackets, SendSpuriousLostPackets, RecvTotalPackets, RecvReorderedPackets, RecvDroppedPackets, RecvDuplicatePackets, RecvDecryptionFailures, CongestionCount, PersistentCongestionCount, SendTotalBytes, RecvTotalBytes, SmoothedRtt) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] STATS: LifeTimeUs=%llu SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu SmoothedRtt=%u", \
    Connection, LifeTimeUs, SendTotalPackets, SendSuspectedLostPackets, SendSpuriousLostPackets, RecvTotalPackets, RecvReorderedPackets, RecvDroppedPackets, RecvDuplicatePackets, RecvDecryptionFailures, CongestionCount, PersistentCongestionCount, SendTotalBytes, RecvTotalBytes, SmoothedRtt)
#define EventWriteQuicConnShutdownComplete(Connection, TimedOut) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] Shutdown Complete, PeerFailedToAcknowledged=%u", Connection, TimedOut)
#define EventWriteQuicConnReadKeyUpdated(Connection, NewValue) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Read Key Updated, %u", Connection, NewValue)
#define EventWriteQuicConnWriteKeyUpdated(Connection, NewValue) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Write Key Updated, %u", Connection, NewValue)
#define EventWriteQuicConnPacketSent(Connection, Number, Type, Length) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [TX][%llu] %u (%hu bytes)", Connection, Number, Type, Length)
#define EventWriteQuicConnPacketRecv(Connection, Number, Type, Length) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [RX][%llu] %u (%hu bytes)", Connection, Number, Type, Length)
#define EventWriteQuicConnPacketLost(Connection, Number, Type, Reason) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [TX][%llu] %u Lost: %u", Connection, Number, Type, Reason)
#define EventWriteQuicConnPacketACKed(Connection, Number, Type) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] [TX][%llu] %u ACKed", Connection, Number, Type)
#define EventWriteQuicConnQueueSendFlush(Connection, Reason) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] Queueing send flush, reason=%u", Connection, Reason)

#define EventWriteQuicStreamCreated(Stream, Connection, ID, IsLocalOwned) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Created, Connection=%p ID=%llu IsLocal=%hu", Stream, Connection, ID, IsLocalOwned)
#define EventWriteQuicStreamDestroyed(Stream) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Destroyed", Stream)
#define EventWriteQuicStreamOutFlowBlocked(Stream, ReasonFlags) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Send Blocked: 0x%x", Stream, ReasonFlags)
#define EventWriteQuicStreamRundown(Stream, Connection, ID, IsLocalOwned) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Rundown, Connection=%p ID=%llu IsLocal=%hu", Stream, Connection, ID, IsLocalOwned)
#define EventWriteQuicStreamSendState(Stream, State) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Send State: %u", Stream, State)
#define EventWriteQuicStreamRecvState(Stream, State) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] Recv State: %u", Stream, State)
#define EventWriteQuicStreamError(Stream, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[strm][%p] ERROR, %s", Stream, ErrStr)
#define EventWriteQuicStreamErrorStatus(Stream, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[strm][%p] ERROR, %u, %s", Stream,  Status, ErrStr)

#define EventWriteQuicBindingCreated(Binding, UdpBinding, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Created %p, Udp=%llX LocalAddr=TODO RemoteAddr=TODO", Binding, UdpBinding);\
    UNREFERENCED_PARAMETER(RemoteAddr); UNREFERENCED_PARAMETER(LocalAddr)
#define EventWriteQuicBindingRundown(Binding, UdpBinding, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Rundown %p, Udp=%llX LocalAddr=TODO RemoteAddr=TODO", Binding, UdpBinding);\
    UNREFERENCED_PARAMETER(RemoteAddr); UNREFERENCED_PARAMETER(LocalAddr)
#define EventWriteQuicBindingDestroyed(Binding) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Destroyed", Binding)
#define EventWriteQuicBindingCleanup(Binding) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[bind][%p] Cleaning up", Binding)
#define EventWriteQuicBindingDropPacket(Binding, PktNum, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[bind][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s", Binding, PktNum, Reason)
#define EventWriteQuicBindingDropPacketEx(Binding, PktNum, Value, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[bind][%p] DROP packet Num=%llu Src=TODO Dst=TODO Reason=%s, %u", Binding, PktNum, Reason, Value)
#define EventWriteQuicBindingError(Binding, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[bind][%p] ERROR, %s", Binding, ErrStr)
#define EventWriteQuicBindingErrorStatus(Binding, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[bind][%p] ERROR, %u, %s", Binding,  Status, ErrStr)
#define EventWriteQuicBindingExecOper(Binding, OperType) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[bind][%p] Execute: %u", Binding, OperType)

#define EventWriteQuicTlsError(Connection, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ tls][%p] ERROR, %s", Connection, ErrStr)
#define EventWriteQuicTlsErrorStatus(Connection, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ tls][%p] ERROR, %u, %s", Connection, Status, ErrStr)
#define EventWriteQuicTlsMessage(Connection, Message) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ tls][%p] %s", Connection, Message)

#define EventWriteQuicDatapathSendTo(Binding, TotalSize, BufferCount, SegmentSize, RemoteAddrLen, RemoteAddr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ udp][%p] Send %u bytes in %u buffers (segment=%u) Dst=TODO", Binding, TotalSize, BufferCount, SegmentSize)
#define EventWriteQuicDatapathSendFromTo(Binding, TotalSize, BufferCount, SegmentSize, RemoteAddrLen, LocalAddrLen, RemoteAddr, LocalAddr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ udp][%p] Send %u bytes in %u buffers (segment=%u) Src=TODO Dst=TODO", Binding, TotalSize, BufferCount, SegmentSize)
#define EventWriteQuicDatapathRecv(Binding, TotalSize, SegmentSize, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[ udp][%p] Recv %u bytes (segment=%u) Src=TODO Dst=TODO", Binding, TotalSize, SegmentSize)
#define EventWriteQuicDatapathError(Binding, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ udp][%p] ERROR, %s", Binding, ErrStr)
#define EventWriteQuicDatapathErrorStatus(Binding, Status, ErrStr) \
    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[ udp][%p] ERROR, %u, %s", Binding, Status, ErrStr)

#define LOG_ADDR_LEN(Addr) sizeof(Addr)

#endif // QUIC_EVENTS_SYSLOG

#ifdef QUIC_EVENTS_LTTNG

#include "quic_trace_lttng.h"

#endif // QUIC_EVENTS_LTTNG

#ifdef QUIC_LOGS_STUB

#define QuicTraceLogErrorEnabled()   FALSE
#define QuicTraceLogWarningEnabled() FALSE
#define QuicTraceLogInfoEnabled()    FALSE
#define QuicTraceLogVerboseEnabled() FALSE

inline
void
QuicTraceStubVarArgs(
    _In_ const void* Fmt,
    ...
    )
{
    UNREFERENCED_PARAMETER(Fmt);
}

#define IGNORE_FIRST_PARAM(A, ...) QuicTraceStubVarArgs(__VA_ARGS__)

#define QuicTraceLogError(...) QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogWarning(...) QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogInfo(...) QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogVerbose(...) QuicTraceStubVarArgs(__VA_ARGS__)

#define QuicTraceLogConnError(...) IGNORE_FIRST_PARAM(__VA_ARGS__)
#define QuicTraceLogConnWarning(...) IGNORE_FIRST_PARAM(__VA_ARGS__)
#define QuicTraceLogConnInfo(...) IGNORE_FIRST_PARAM(__VA_ARGS__)
#define QuicTraceLogConnVerbose(...) IGNORE_FIRST_PARAM(__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() FALSE

#define QuicTraceLogStreamError(...) IGNORE_FIRST_PARAM(__VA_ARGS__)
#define QuicTraceLogStreamWarning(...) IGNORE_FIRST_PARAM(__VA_ARGS__)
#define QuicTraceLogStreamInfo(...) IGNORE_FIRST_PARAM(__VA_ARGS__)
#define QuicTraceLogStreamVerbose(...) IGNORE_FIRST_PARAM(__VA_ARGS__)

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
        WPP_DEFINE_BIT(FLAG_DEFAULT)        \
        WPP_DEFINE_BIT(FLAG_REGISTRATION)   \
        WPP_DEFINE_BIT(FLAG_SESSION)        \
        WPP_DEFINE_BIT(FLAG_LISTENER)       \
        WPP_DEFINE_BIT(FLAG_WORKER)         \
        WPP_DEFINE_BIT(FLAG_BINDING)        \
        WPP_DEFINE_BIT(FLAG_CONNECTION)     \
        WPP_DEFINE_BIT(FLAG_STREAM)         \
        WPP_DEFINE_BIT(FLAG_UDP)            \
        WPP_DEFINE_BIT(FLAG_PACKET)         \
        WPP_DEFINE_BIT(FLAG_TLS)            \
        WPP_DEFINE_BIT(FLAG_PLATFORM)       \
        )

#define WPP_LEVEL_FLAGS_NOOP_ENABLED(LEVEL,FLAGS,NOOP)   \
    WPP_LEVEL_FLAGS_ENABLED(LEVEL,FLAGS)
#define WPP_LEVEL_FLAGS_NOOP_LOGGER(LEVEL,FLAGS,NOOP)   \
    WPP_LEVEL_FLAGS_LOGGER(LEVEL,FLAGS)

#define WPP_LEVEL_FLAGS_NOOP_POINTER_ENABLED(LEVEL,FLAGS,NOOP,POINTER)   \
    WPP_LEVEL_FLAGS_ENABLED(LEVEL,FLAGS)
#define WPP_LEVEL_FLAGS_NOOP_POINTER_LOGGER(LEVEL,FLAGS,NOOP,POINTER)   \
    WPP_LEVEL_FLAGS_LOGGER(LEVEL,FLAGS)

#define QuicTraceLogErrorEnabled()   WPP_FLAGS_LEVEL_ENABLED(FLAG_DEFAULT, TRACE_LEVEL_ERROR)
#define QuicTraceLogWarningEnabled() WPP_FLAGS_LEVEL_ENABLED(FLAG_DEFAULT, TRACE_LEVEL_WARNING)
#define QuicTraceLogInfoEnabled()    WPP_FLAGS_LEVEL_ENABLED(FLAG_DEFAULT, TRACE_LEVEL_INFORMATION)
#define QuicTraceLogVerboseEnabled() WPP_FLAGS_LEVEL_ENABLED(FLAG_DEFAULT, TRACE_LEVEL_VERBOSE)

#define QuicTraceLogStreamVerboseEnabled() WPP_FLAGS_LEVEL_ENABLED(FLAG_STREAM, TRACE_LEVEL_VERBOSE)

// begin_wpp config

// FUNC QuicTraceLogError{LEVEL=TRACE_LEVEL_ERROR,FLAGS=FLAG_DEFAULT}(MSG,...);
// FUNC QuicTraceLogWarning{LEVEL=TRACE_LEVEL_WARNING,FLAGS=FLAG_DEFAULT}(MSG,...);
// FUNC QuicTraceLogInfo{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FLAG_DEFAULT}(MSG,...);
// FUNC QuicTraceLogVerbose{LEVEL=TRACE_LEVEL_VERBOSE,FLAGS=FLAG_DEFAULT}(MSG,...);

// USEPREFIX(QuicTraceLogConnError,"%!STDPREFIX![conn][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogConnError{LEVEL=TRACE_LEVEL_ERROR,FLAGS=FLAG_CONNECTION}(NOOP,POINTER,MSG,...);
// USEPREFIX(QuicTraceLogConnWarning,"%!STDPREFIX![conn][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogConnWarning{LEVEL=TRACE_LEVEL_WARNING,FLAGS=FLAG_CONNECTION}(NOOP,POINTER,MSG,...);
// USEPREFIX(QuicTraceLogConnInfo,"%!STDPREFIX![conn][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogConnInfo{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FLAG_CONNECTION}(NOOP,POINTER,MSG,...);
// USEPREFIX(QuicTraceLogConnVerbose,"%!STDPREFIX![conn][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogConnVerbose{LEVEL=TRACE_LEVEL_VERBOSE,FLAGS=FLAG_CONNECTION}(NOOP,POINTER,MSG,...);

// USEPREFIX(QuicTraceLogStreamError,"%!STDPREFIX![strm][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogStreamError{LEVEL=TRACE_LEVEL_ERROR,FLAGS=FLAG_STREAM}(NOOP,POINTER,MSG,...);
// USEPREFIX(QuicTraceLogStreamWarning,"%!STDPREFIX![strm][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogStreamWarning{LEVEL=TRACE_LEVEL_WARNING,FLAGS=FLAG_STREAM}(NOOP,POINTER,MSG,...);
// USEPREFIX(QuicTraceLogStreamInfo,"%!STDPREFIX![strm][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogStreamInfo{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FLAG_STREAM}(NOOP,POINTER,MSG,...);
// USEPREFIX(QuicTraceLogStreamVerbose,"%!STDPREFIX![strm][%p]%!SPACE!",POINTER);
// FUNC QuicTraceLogStreamVerbose{LEVEL=TRACE_LEVEL_VERBOSE,FLAGS=FLAG_STREAM}(NOOP,POINTER,MSG,...);

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

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#include "MsQuicEtw.h"
#pragma warning(pop)

#include <stdio.h>

#define QuicTraceLogErrorEnabled()   EventEnabledQuicLogError()
#define QuicTraceLogWarningEnabled() EventEnabledQuicLogWarning()
#define QuicTraceLogInfoEnabled()    EventEnabledQuicLogInfo()
#define QuicTraceLogVerboseEnabled() EventEnabledQuicLogVerbose()

#define LogEtw(EventName, Fmt, ...) \
    if (EventEnabledQuicLog##EventName()) { \
        char EtwBuffer[256]; \
        sprintf_s(EtwBuffer, 256, Fmt, ##__VA_ARGS__); \
        EventWriteQuicLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogEtwType(Type, EventName, Ptr, Fmt, ...) \
    if (EventEnabledQuic##Type##Log##EventName()) { \
        char EtwBuffer[256]; \
        sprintf_s(EtwBuffer, 256, Fmt, ##__VA_ARGS__); \
        EventWriteQuic##Type##Log##EventName##_AssumeEnabled(Ptr, EtwBuffer); \
    }

#define QuicTraceLogError(Fmt, ...)          LogEtw(Error, Fmt, ##__VA_ARGS__)
#define QuicTraceLogWarning(Fmt, ...)        LogEtw(Warning, Fmt, ##__VA_ARGS__)
#define QuicTraceLogInfo(Fmt, ...)           LogEtw(Info, Fmt, ##__VA_ARGS__)
#define QuicTraceLogVerbose(Fmt, ...)        LogEtw(Verbose, Fmt, ##__VA_ARGS__)

#define QuicTraceLogConnError(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Error, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnWarning(Name, Ptr, Fmt, ...)  LogEtwType(Conn, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnInfo(Name, Ptr, Fmt, ...)     LogEtwType(Conn, Info, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnVerbose(Name, Ptr, Fmt, ...)  LogEtwType(Conn, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() EventEnabledQuicStreamLogVerbose()

#define QuicTraceLogStreamError(Name, Ptr, Fmt, ...)    LogEtwType(Stream, Error, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamWarning(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamInfo(Name, Ptr, Fmt, ...)     LogEtwType(Stream, Info, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamVerbose(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#endif // QUIC_LOGS_MANIFEST_ETW

#ifdef QUIC_LOGS_SYSLOG

#define QuicTraceLogErrorEnabled()   TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled()    TRUE
#define QuicTraceLogVerboseEnabled() TRUE

#define QuicTraceLogError(Fmt, ...)          QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, Fmt, ##__VA_ARGS__)
#define QuicTraceLogWarning(Fmt, ...)        QuicSysLogWrite(QUIC_TRACE_LEVEL_WARNING, Fmt, ##__VA_ARGS__)
#define QuicTraceLogInfo(Fmt, ...)           QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, Fmt, ##__VA_ARGS__)
#define QuicTraceLogVerbose(Fmt, ...)        QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, Fmt, ##__VA_ARGS__)

#define QuicTraceLogConnError(Name, Ptr, Fmt, ...)   QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[conn][%p] " Fmt, Ptr, ##__VA_ARGS__)
#define QuicTraceLogConnWarning(Name, Ptr, Fmt, ...) QuicSysLogWrite(QUIC_TRACE_LEVEL_WARNING, "[conn][%p] " Fmt, Ptr, ##__VA_ARGS__)
#define QuicTraceLogConnInfo(Name, Ptr, Fmt, ...)    QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[conn][%p] " Fmt, Ptr, ##__VA_ARGS__)
#define QuicTraceLogConnVerbose(Name, Ptr, Fmt, ...) QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[conn][%p] " Fmt, Ptr, ##__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() TRUE

#define QuicTraceLogStreamError(Name, Ptr, Fmt, ...)    QuicSysLogWrite(QUIC_TRACE_LEVEL_ERROR, "[strm][%p] " Fmt, Ptr, ##__VA_ARGS__)
#define QuicTraceLogStreamWarning(Name, Ptr, Fmt, ...)  QuicSysLogWrite(QUIC_TRACE_LEVEL_WARNING, "[strm][%p] " Fmt, Ptr, ##__VA_ARGS__)
#define QuicTraceLogStreamInfo(Name, Ptr, Fmt, ...)     QuicSysLogWrite(QUIC_TRACE_LEVEL_INFO, "[strm][%p] " Fmt, Ptr, ##__VA_ARGS__)
#define QuicTraceLogStreamVerbose(Name, Ptr, Fmt, ...)  QuicSysLogWrite(QUIC_TRACE_LEVEL_VERBOSE, "[strm][%p] " Fmt, Ptr, ##__VA_ARGS__)

#endif // QUIC_LOGS_SYSLOG

#ifdef QUIC_LOGS_LTTNG

#error "LTTng not supported yet!"

#endif // QUIC_LOGS_LTTNG

#endif // _TRACE_H
