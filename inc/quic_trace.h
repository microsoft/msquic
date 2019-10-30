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

    QUIC_LOGS_STUB              No-op all Logs
    QUIC_LOGS_WPP               Write to Windows WPP framework
    QUIC_LOGS_SYSLOG            Write to Linux syslog

 --*/

#ifndef _TRACE_H
#define _TRACE_H

#pragma once

#if !defined(QUIC_EVENTS_STUB) && !defined(QUIC_EVENTS_MANIFEST_ETW)
#error "Must define one QUIC_EVENTS_*"
#endif

#if !defined(QUIC_LOGS_STUB) && !defined(QUIC_LOGS_WPP) && !defined(QUIC_LOGS_SYSLOG)
#error "Must define one QUIC_LOGS_*"
#endif

typedef enum _QUIC_FLOW_BLOCK_REASON {
    QUIC_FLOW_BLOCKED_SCHEDULING            = 0x01,
    QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x02,
    QUIC_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x04,
    QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x08,
    QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x10,
    QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x20,
    QUIC_FLOW_BLOCKED_APP                   = 0x40
} QUIC_FLOW_BLOCK_REASON;

typedef enum _QUIC_TRACE_PACKET_TYPE {
    QUIC_TRACE_PACKET_VN,
    QUIC_TRACE_PACKET_INITIAL,
    QUIC_TRACE_PACKET_ZERO_RTT,
    QUIC_TRACE_PACKET_HANDSHAKE,
    QUIC_TRACE_PACKET_RETRY,
    QUIC_TRACE_PACKET_ONE_RTT
} QUIC_TRACE_PACKET_TYPE;

typedef enum _QUIC_TRACE_PACKET_LOSS_REASON {
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

#ifdef QUIC_EVENTS_STUB

#define EventWriteQuicLibraryInitialized(PartitionCount, DatapathFeatures)
#define EventWriteQuicLibraryUninitialized()
#define EventWriteQuicLibraryAddRef()
#define EventWriteQuicLibraryRelease()
#define EventWriteQuicLibraryWorkerPoolInit()
#define EventWriteQuicAllocFailure(Desc, ByteCount)
#define EventWriteQuicLibraryRundown(PartitionCount, DatapathFeatures)
#define EventWriteQuicLibraryError(ErrStr)
#define EventWriteQuicLibraryErrorStatus(Status, ErrStr)
#define EventWriteQuicLibraryAssert(Line, File, Expression)
#define EventWriteQuicApiEnter(Type, Handle)
#define EventWriteQuicApiExit()
#define EventWriteQuicApiExitStatus(Status)
#define EventWriteQuicApiWaitOperation()

#define EventWriteQuicRegistrationCreated(Registration, AppName)
#define EventWriteQuicRegistrationDestroyed(Registration)
#define EventWriteQuicRegistrationCleanup(Registration)
#define EventWriteQuicRegistrationRundown(Registration, AppName)
#define EventWriteQuicRegistrationError(Registration, ErrStr)
#define EventWriteQuicRegistrationErrorStatus(Registration, Status, ErrStr)

#define EventWriteQuicWorkerCreated(Worker, IdealProcessor, Owner)
#define EventWriteQuicWorkerStart(Worker)
#define EventWriteQuicWorkerStop(Worker)
#define EventWriteQuicWorkerActivityStateUpdated(Worker, IsActive, Arg)
#define EventWriteQuicWorkerQueueDelayUpdated(Worker, QueueDelay)
#define EventWriteQuicWorkerDestroyed(Worker)
#define EventWriteQuicWorkerCleanup(Worker)
#define EventWriteQuicWorkerError(Worker, ErrStr)
#define EventWriteQuicWorkerErrorStatus(Worker, Status, ErrStr)

#define EventWriteQuicSessionCreated(Session, Registration, Alpn)
#define EventWriteQuicSessionDestroyed(Session)
#define EventWriteQuicSessionCleanup(Session)
#define EventWriteQuicSessionShutdown(Session, Flags, ErrorCode)
#define EventWriteQuicSessionRundown(Session, Registration, Alpn)
#define EventWriteQuicSessionError(Session, ErrStr)
#define EventWriteQuicSessionErrorStatus(Session, Status, ErrStr)

#define EventWriteQuicListenerCreated(Listener, Session)
#define EventWriteQuicListenerDestroyed(Listener)
#define EventWriteQuicListenerStarted(Listener, Binding, AddrLen, Addr)
#define EventWriteQuicListenerStopped(Listener)
#define EventWriteQuicListenerRundown(Listener, Session)
#define EventWriteQuicListenerError(Listener, ErrStr)
#define EventWriteQuicListenerErrorStatus(Listener, Status, ErrStr)

#define EventWriteQuicConnCreated(Connection, IsServer, CorrelationId)
#define EventWriteQuicConnDestroyed(Connection)
#define EventWriteQuicConnInitializeComplete(Connection)
#define EventWriteQuicConnHandleClosed(Connection)
#define EventWriteQuicConnHandshakeStart(Connection)
#define EventWriteQuicConnHandshakeComplete(Connection)
#define EventWriteQuicConnScheduleState(Connection, State)
#define EventWriteQuicConnExecOper(Connection, Type)
#define EventWriteQuicConnExecApiOper(Connection, Type)
#define EventWriteQuicConnExecTimerOper(Connection, Type)
#define EventWriteQuicConnLocalAddrAdded(Connection, AddrLen, Addr)
#define EventWriteQuicConnRemoteAddrAdded(Connection, AddrLen, Addr)
#define EventWriteQuicConnLocalAddrRemoved(Connection, AddrLen, Addr)
#define EventWriteQuicConnRemoteAddrRemoved(Connection, AddrLen, Addr)
#define EventWriteQuicConnAssignWorker(Connection, Worker)
#define EventWriteQuicConnRegisterSession(Connection, Session)
#define EventWriteQuicConnUnregisterSession(Connection, Session)
#define EventWriteQuicConnOutFlowStats(Connection, BytesSent, BytesInFlight, BytesInFlightMax, CongestionWindow, SlowStartThreshold, ConnectionFlowControl, StreamFlowControl, IdealBytes, PostedBytes, SmoothedRtt, StreamSendWindow)
#define EventEnabledQuicConnOutFlowStats() FALSE
#define EventWriteQuicConnInFlowStats(Connection, BytesReceived)
#define EventWriteQuicConnOutFlowBlocked(Connection, ReasonFlags)
#define EventWriteQuicConnCubic(Connection, SlowStartThreshold, K, WindowMax, WindowLastMax)
#define EventWriteQuicConnCongestion(Connection)
#define EventWriteQuicConnPersistentCongestion(Connection)
#define EventWriteQuicConnRecoveryExit(Connection)
#define EventWriteQuicConnTransportShutdown(Connection, ErrorCode, IsRemoteShutdown, IsQuicStatus)
#define EventWriteQuicConnAppShutdown(Connection, ErrorCode, IsRemoteShutdown)
#define EventWriteQuicConnVersionSet(Connection, Value)
#define EventWriteQuicConnRundown(Connection, IsServer, CorrelationId)
#define EventWriteQuicConnSourceCidAdded(Connection, CidLen, Cid)
#define EventWriteQuicConnDestCidAdded(Connection, CidLen, Cid)
#define EventWriteQuicConnSourceCidRemoved(Connection, CidLen, Cid)
#define EventWriteQuicConnDestCidRemoved(Connection, CidLen, Cid)
#define EventWriteQuicConnLossDetectionTimerSet(Connection, TimerType, DelayMs, ProbeCount) UNREFERENCED_PARAMETER(TimerType)
#define EventWriteQuicConnLossDetectionTimerCancel(Connection)
#define EventWriteQuicConnDropPacket(Connection, PktNum, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason)
#define EventWriteQuicConnDropPacketEx(Connection, PktNum, Value, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason)
#define EventWriteQuicConnError(Connection, ErrStr)
#define EventWriteQuicConnErrorStatus(Connection, Status, ErrStr)
#define EventWriteQuicConnNewPacketKeys(Connection)
#define EventWriteQuicConnKeyPhaseChange(Connection, IsLocallyInitiated)
#define EventWriteQuicConnStatistics(Connection, LifeTimeUs, SendTotalPackets, SendSuspectedLostPackets, SendSpuriousLostPackets, RecvTotalPackets, RecvReorderedPackets, RecvDroppedPackets, RecvDuplicatePackets, RecvDecryptionFailures, CongestionCount, PersistentCongestionCount, SendTotalBytes, RecvTotalBytes, SmoothedRtt)
#define EventWriteQuicConnShutdownComplete(Connection, TimedOut)
#define EventWriteQuicConnReadKeyUpdated(Connection, NewValue)
#define EventWriteQuicConnWriteKeyUpdated(Connection, NewValue)
#define EventWriteQuicConnPacketSent(Connection, Number, Type, Length)
#define EventWriteQuicConnPacketRecv(Connection, Number, Type, Length)
#define EventWriteQuicConnPacketLost(Connection, Number, Type, Reason)
#define EventWriteQuicConnPacketACKed(Connection, Number, Type)

#define EventWriteQuicStreamCreated(Stream, Connection, ID, IsLocalOwned)
#define EventWriteQuicStreamDestroyed(Stream)
#define EventWriteQuicStreamOutFlowBlocked(Stream, ReasonFlags)
#define EventWriteQuicStreamRundown(Stream, Connection, ID, IsLocalOwned)
#define EventWriteQuicStreamSendState(Stream, State)
#define EventWriteQuicStreamRecvState(Stream, State)
#define EventWriteQuicStreamError(Stream, ErrStr)
#define EventWriteQuicStreamErrorStatus(Stream, Status, ErrStr)

#define EventWriteQuicBindingCreated(Binding, UdpBinding, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) UNREFERENCED_PARAMETER(RemoteAddr); UNREFERENCED_PARAMETER(LocalAddr)
#define EventWriteQuicBindingRundown(Binding, UdpBinding, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr) UNREFERENCED_PARAMETER(RemoteAddr); UNREFERENCED_PARAMETER(LocalAddr)
#define EventWriteQuicBindingDestroyed(Binding)
#define EventWriteQuicBindingCleanup(Binding)
#define EventWriteQuicBindingDropPacket(Binding, PktNum, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason)
#define EventWriteQuicBindingDropPacketEx(Binding, PktNum, Value, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr, Reason)
#define EventWriteQuicBindingError(Binding, ErrStr)
#define EventWriteQuicBindingErrorStatus(Binding, Status, ErrStr)
#define EventWriteQuicBindingExecOper(Binding, OperType)

#define EventWriteQuicTlsError(Connection, ErrStr)
#define EventWriteQuicTlsErrorStatus(Connection, Status, ErrStr)
#define EventWriteMiTLSTrace(Message)

#define EventWriteQuicDatapathSendTo(Binding, TotalSize, BufferCount, SegmentSize, RemoteAddrLen, RemoteAddr)
#define EventWriteQuicDatapathSendFromTo(Binding, TotalSize, BufferCount, SegmentSize, RemoteAddrLen, LocalAddrLen, RemoteAddr, LocalAddr)
#define EventWriteQuicDatapathRecv(Binding, TotalSize, SegmentSize, LocalAddrLen, RemoteAddrLen, LocalAddr, RemoteAddr)
#define EventWriteQuicDatapathError(Binding, ErrStr)
#define EventWriteQuicDatapathErrorStatus(Binding, Status, ErrStr)

#define LOG_ADDR_LEN(Addr) sizeof(Addr)

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

#ifdef QUIC_LOGS_SYSLOG

typedef enum _QUIC_LOG_LEVEL {
    QUIC_LOG_DEV,
    QUIC_LOG_VERBOSE,
    QUIC_LOG_INFO,
    QUIC_LOG_WARNING,
    QUIC_LOG_ERROR,
    QUIC_LOG_PACKET_VERBOSE,
    QUIC_LOG_PACKET_INFO,
    QUIC_LOG_PACKET_WARNING
} QUIC_LOG_LEVEL;

#ifdef __cplusplus
extern "C"
#endif
void
QuicSysLogWriteLog(
    _In_ QUIC_LOG_LEVEL Kind,
    _In_ const char* File,
    _In_ int Line,
    _In_ const char* Func,
    _In_ const char* Fmt,
    ...
    );

#define WPP_COMPID_LEVEL_ENABLED(...) TRUE

#define LogDev(Fmt, ...)            QuicSysLogWriteLog(QUIC_LOG_DEV, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogVerbose(Fmt, ...)        QuicSysLogWriteLog(QUIC_LOG_VERBOSE, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogInfo(Fmt, ...)           QuicSysLogWriteLog(QUIC_LOG_INFO, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogWarning(Fmt, ...)        QuicSysLogWriteLog(QUIC_LOG_WARNING, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogError(Fmt, ...)          QuicSysLogWriteLog(QUIC_LOG_ERROR, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogPacketVerbose(Fmt, ...)  QuicSysLogWriteLog(QUIC_LOG_PACKET_VERBOSE, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogPacketInfo(Fmt, ...)     QuicSysLogWriteLog(QUIC_LOG_PACKET_INFO, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)
#define LogPacketWarning(Fmt, ...)  QuicSysLogWriteLog(QUIC_LOG_PACKET_WARNING, __FILE__, __LINE__, __func__, Fmt, ##__VA_ARGS__)

#endif // QUIC_LOGS_SYSLOG

#endif // _TRACE_H
