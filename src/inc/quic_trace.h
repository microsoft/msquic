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
    QUIC_EVENTS_LTTNG           Write to Linux LTTng framework

    QUIC_LOGS_STUB              No-op all Logs
    QUIC_LOGS_MANIFEST_ETW      Write to Windows ETW framework
    QUIC_LOGS_LTTNG             Write to Linux LTTng framework

 --*/

#ifndef _TRACE_H
#define _TRACE_H

#pragma once

#if !defined(QUIC_EVENTS_STUB) && !defined(QUIC_EVENTS_MANIFEST_ETW) && !defined(QUIC_EVENTS_LTTNG)
#error "Must define one QUIC_EVENTS_*"
#endif

#if !defined(QUIC_LOGS_STUB) && !defined(QUIC_LOGS_MANIFEST_ETW) && !defined(QUIC_LOGS_LTTNG)
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
    QUIC_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
    QUIC_TRACE_API_STREAM_OPEN,
    QUIC_TRACE_API_STREAM_CLOSE,
    QUIC_TRACE_API_STREAM_START,
    QUIC_TRACE_API_STREAM_SHUTDOWN,
    QUIC_TRACE_API_STREAM_SEND,
    QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
    QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
    QUIC_TRACE_API_DATAGRAM_SEND
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

#ifdef QUIC_EVENTS_STUB

#define QUIC_TRACE_EVENT(x, ...) 
#define QUIC_TRACE_LEVEL(...)

QUIC_TRACE_EVENT(LibraryInitialized,
    TP_ARGS(
        uint32_t, PartitionCount,
        uint32_t, DatapathFeatures),
    TP_FIELDS(
        ctf_integer(uint32_t, PartitionCount, PartitionCount)
        ctf_integer(uint32_t, DatapathFeatures, DatapathFeatures))
)
QUIC_TRACE_LEVEL(LibraryInitialized, TRACE_INFO)
QUIC_TRACE_EVENT(LibraryUninitialized,
    TP_ARGS(),
    TP_FIELDS()
)
QUIC_TRACE_LEVEL(LibraryUninitialized, TRACE_INFO)
QUIC_TRACE_EVENT(LibraryAddRef,
    TP_ARGS(),
    TP_FIELDS()
)
QUIC_TRACE_LEVEL(LibraryAddRef, TRACE_INFO)
QUIC_TRACE_EVENT(LibraryRelease,
    TP_ARGS(),
    TP_FIELDS()
)
QUIC_TRACE_LEVEL(LibraryRelease, TRACE_INFO)
QUIC_TRACE_EVENT(LibraryWorkerPoolInit,
    TP_ARGS(),
    TP_FIELDS()
)
QUIC_TRACE_LEVEL(LibraryWorkerPoolInit, TRACE_INFO)
QUIC_TRACE_EVENT(AllocFailure,
    TP_ARGS(
        const char*, Desc,
        uint64_t, ByteCount),
    TP_FIELDS(
        ctf_string(Desc, Desc)
        ctf_integer(uint64_t, ByteCount, ByteCount))
)
QUIC_TRACE_LEVEL(AllocFailure, TRACE_WARNING)
QUIC_TRACE_EVENT(LibraryRundown,
    TP_ARGS(
        uint32_t, PartitionCount,
        uint32_t, DatapathFeatures),
    TP_FIELDS(
        ctf_integer(uint32_t, PartitionCount, PartitionCount)
        ctf_integer(uint32_t, DatapathFeatures, DatapathFeatures))
)
QUIC_TRACE_LEVEL(LibraryRundown, TRACE_INFO)
QUIC_TRACE_EVENT(LibraryError,
    TP_ARGS(
        const char*, ErrStr),
    TP_FIELDS(
        ctf_string(ErrStr, ErrStr))
)
QUIC_TRACE_LEVEL(LibraryError, TRACE_ERR)
QUIC_TRACE_EVENT(LibraryErrorStatus,
    TP_ARGS(
        uint32_t, Status,
        const char*, ErrStr),
    TP_FIELDS(
        ctf_integer(uint32_t, Status, Status)
        ctf_string(ErrStr, ErrStr))
)
QUIC_TRACE_LEVEL(LibraryErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(LibraryAssert,
    TP_ARGS(
        uint32_t, Line,
        const char*, File,
        const char*, Expression),
    TP_FIELDS(
        ctf_integer(uint32_t, Line, Line)
        ctf_string(File, File)
        ctf_string(Expression, Expression))
)
QUIC_TRACE_LEVEL(LibraryAssert, TRACE_ERR)
QUIC_TRACE_EVENT(ApiEnter,
    TP_ARGS(
        uint32_t, Type, // TODO - Use Enum
        const void*, Handle),
    TP_FIELDS(
        ctf_integer(uint32_t, Type, Type)
        ctf_integer_hex(uint64_t, Handle, Handle))
)
QUIC_TRACE_LEVEL(ApiEnter, TRACE_DEBUG)
QUIC_TRACE_EVENT(ApiExit,
    TP_ARGS(),
    TP_FIELDS()
)
QUIC_TRACE_LEVEL(ApiExit, TRACE_DEBUG)
QUIC_TRACE_EVENT(ApiExitStatus,
    TP_ARGS(
        uint32_t, Status),
    TP_FIELDS(
        ctf_integer(uint32_t, Status, Status))
)
QUIC_TRACE_LEVEL(ApiExitStatus, TRACE_DEBUG)
QUIC_TRACE_EVENT(ApiWaitOperation,
    TP_ARGS(),
    TP_FIELDS()
)
QUIC_TRACE_LEVEL(ApiWaitOperation, TRACE_DEBUG)
QUIC_TRACE_EVENT(RegistrationCreated,
    TP_ARGS(
        const void*, Registration,
        const char*, AppName),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Registration, Registration)
        ctf_string(AppName, AppName))
)
QUIC_TRACE_EVENT(RegistrationDestroyed,
    TP_ARGS(
        const void*, Registration),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Registration, Registration))
)
QUIC_TRACE_EVENT(RegistrationCleanup,
    TP_ARGS(
        const void*, Registration),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Registration, Registration))
)
QUIC_TRACE_EVENT(RegistrationRundown,
    TP_ARGS(
        const void*, Registration,
        const char*, AppName),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Registration, Registration)
        ctf_string(AppName, AppName))
)
QUIC_TRACE_EVENT(RegistrationError,
    TP_ARGS(
        const void*, Registration,
        const char*, ErrStr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Registration, Registration)
        ctf_string(ErrStr, ErrStr))
)
QUIC_TRACE_LEVEL(RegistrationError, TRACE_ERR)
QUIC_TRACE_EVENT(RegistrationErrorStatus,
    TP_ARGS(
        const void*, Registration,
        uint32_t, Status,
        const char*, ErrStr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Registration, Registration)
        ctf_integer(uint32_t, Status, Status)
        ctf_string(ErrStr, ErrStr))
)
QUIC_TRACE_LEVEL(RegistrationErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(WorkerCreated,
    TP_ARGS(
        const void*, Worker,
        uint8_t, IdealProcessor,
        const void*, Owner),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker)
        ctf_integer(uint8_t, IdealProcessor, IdealProcessor)
        ctf_integer_hex(uint64_t, Owner, Owner))
)
QUIC_TRACE_EVENT(WorkerStart,
    TP_ARGS(
        const void*, Worker),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker))
)
QUIC_TRACE_EVENT(WorkerStop,
    TP_ARGS(
        const void*, Worker),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker))
)
QUIC_TRACE_EVENT(WorkerActivityStateUpdated,
    TP_ARGS(
        const void*, Worker,
        uint32_t, arg3,
        uint32_t, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4))
)
QUIC_TRACE_EVENT(WorkerQueueDelayUpdated,
    TP_ARGS(
        const void*, Worker,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(WorkerDestroyed,
    TP_ARGS(
        const void*, Worker),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker))
)
QUIC_TRACE_EVENT(WorkerCleanup,
    TP_ARGS(
        const void*, Worker),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker))
)
QUIC_TRACE_EVENT(WorkerError,
    TP_ARGS(
        const void*, Worker,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_LEVEL(WorkerError, TRACE_ERR)
QUIC_TRACE_EVENT(WorkerErrorStatus,
    TP_ARGS(
        const void*, Worker,
        uint32_t, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Worker, Worker)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_LEVEL(WorkerErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(SessionCreated,
    TP_ARGS(
        const void*, Session,
        const void*, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_EVENT(SessionDestroyed,
    TP_ARGS(
        const void*, Session),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session))
)
QUIC_TRACE_EVENT(SessionCleanup,
    TP_ARGS(
        const void*, Session),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session))
)
QUIC_TRACE_EVENT(SessionShutdown,
    TP_ARGS(
        const void*, Session,
        uint32_t, arg3,
        uint64_t, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4))
)
QUIC_TRACE_EVENT(SessionRundown,
    TP_ARGS(
        const void*, Session,
        const void*, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_EVENT(SessionError,
    TP_ARGS(
        const void*, Session,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_LEVEL(SessionError, TRACE_ERR)
QUIC_TRACE_EVENT(SessionErrorStatus,
    TP_ARGS(
        const void*, Session,
        uint32_t, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Session, Session)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_LEVEL(SessionErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(ListenerCreated,
    TP_ARGS(
        const void*, Listener,
        const void*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener)
        ctf_integer_hex(uint64_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ListenerDestroyed,
    TP_ARGS(
        const void*, Listener),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener))
)
QUIC_TRACE_EVENT(ListenerStarted,
    TP_ARGS(
        const void*, Listener,
        const void*, arg3,
        uint8_t, AddrLength,
        const void*, Addr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener)
        ctf_integer_hex(uint64_t, arg3, arg3)
        /*ctf_sequence_hex(uint8_t, Addr, Addr, uint8_t, AddrLength)*/)
)
QUIC_TRACE_EVENT(ListenerStopped,
    TP_ARGS(
        const void*, Listener),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener))
)
QUIC_TRACE_EVENT(ListenerRundown,
    TP_ARGS(
        const void*, Listener,
        const void*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener)
        ctf_integer_hex(uint64_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ListenerError,
    TP_ARGS(
        const void*, Listener,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_LEVEL(ListenerError, TRACE_ERR)
QUIC_TRACE_EVENT(ListenerErrorStatus,
    TP_ARGS(
        const void*, Listener,
        uint32_t, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Listener, Listener)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_LEVEL(ListenerErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(ConnCreated,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        uint64_t, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4))
)
QUIC_TRACE_EVENT(ConnDestroyed,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnHandshakeComplete,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnScheduleState,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnExecOper,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnExecApiOper,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnExecTimerOper,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnLocalAddrAdded,
    TP_ARGS(
        const void*, Connection,
        uint8_t, AddrLength,
        const void*, Addr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        /*ctf_sequence_hex(uint8_t, Addr, Addr, uint8_t, AddrLength)*/)
)
QUIC_TRACE_EVENT(ConnRemoteAddrAdded,
    TP_ARGS(
        const void*, Connection,
        uint8_t, AddrLength,
        const void*, Addr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        /*ctf_sequence_hex(uint8_t, Addr, Addr, uint8_t, AddrLength)*/)
)
QUIC_TRACE_EVENT(ConnLocalAddrRemoved,
    TP_ARGS(
        const void*, Connection,
        uint8_t, AddrLength,
        const void*, Addr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        /*ctf_sequence_hex(uint8_t, Addr, Addr, uint8_t, AddrLength)*/)
)
QUIC_TRACE_EVENT(ConnRemoteAddrRemoved,
    TP_ARGS(
        const void*, Connection,
        uint8_t, AddrLength,
        const void*, Addr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        /*ctf_sequence_hex(uint8_t, Addr, Addr, uint8_t, AddrLength)*/)
)
QUIC_TRACE_EVENT(ConnAssignWorker,
    TP_ARGS(
        const void*, Connection,
        const void*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnHandshakeStart,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnRegisterSession,
    TP_ARGS(
        const void*, Connection,
        const void*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnUnregisterSession,
    TP_ARGS(
        const void*, Connection,
        const void*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnTransportShutdown,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(ConnAppShutdown,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        uint32_t, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4))
)
QUIC_TRACE_EVENT(ConnInitializeComplete,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnHandleClosed,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnVersionSet,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnOutFlowStats,
    TP_ARGS(
        const void*, Connection,
        uint64_t, BytesSent,
        uint32_t, BytesInFlight,
        uint32_t, BytesInFlightMax,
        uint32_t, CongestionWindow,
        uint32_t, SlowStartThreshold,
        uint64_t, ConnectionFlowControl,
        uint64_t, IdealBytes,
        uint64_t, PostedBytes,
        uint32_t, SmoothedRtt),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, BytesSent, BytesSent)
        ctf_integer(uint32_t, BytesInFlight, BytesInFlight)
        ctf_integer(uint32_t, BytesInFlightMax, BytesInFlightMax)
        ctf_integer(uint32_t, CongestionWindow, CongestionWindow)
        ctf_integer(uint32_t, SlowStartThreshold, SlowStartThreshold)
        ctf_integer(uint64_t, ConnectionFlowControl, ConnectionFlowControl)
        ctf_integer(uint64_t, IdealBytes, IdealBytes)
        ctf_integer(uint64_t, PostedBytes, PostedBytes)
        ctf_integer(uint32_t, SmoothedRtt, SmoothedRtt))
)
QUIC_TRACE_EVENT(ConnOutFlowStreamStats,
    TP_ARGS(
        const void*, Connection,
        uint64_t, StreamFlowControl,
        uint64_t, StreamSendWindow),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, StreamFlowControl, StreamFlowControl)
        ctf_integer(uint64_t, StreamSendWindow, StreamSendWindow))
)
QUIC_TRACE_EVENT(ConnOutFlowBlocked,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnInFlowStats,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnCubic,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5,
        uint32_t, arg6),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5)
        ctf_integer(uint32_t, arg6, arg6))
)
QUIC_TRACE_EVENT(ConnCongestion,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnPersistentCongestion,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnRecoveryExit,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnRundown,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        uint64_t, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4))
)
QUIC_TRACE_EVENT(ConnSourceCidAdded,
    TP_ARGS(
        const void*, Connection,
        uint64_t, SequenceNumber,
        uint8_t, CidLength,
        const void*, Cid),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, SequenceNumber, SequenceNumber)
        /*ctf_sequence_hex(uint8_t, Cid, Cid, uint8_t, CidLength)*/)
)
QUIC_TRACE_EVENT(ConnDestCidAdded,
    TP_ARGS(
        const void*, Connection,
        uint64_t, SequenceNumber,
        uint8_t, CidLength,
        const void*, Cid),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, SequenceNumber, SequenceNumber)
        /*ctf_sequence_hex(uint8_t, Cid, Cid, uint8_t, CidLength)*/)
)
QUIC_TRACE_EVENT(ConnSourceCidRemoved,
    TP_ARGS(
        const void*, Connection,
        uint64_t, SequenceNumber,
        uint8_t, CidLength,
        const void*, Cid),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, SequenceNumber, SequenceNumber)
        /*ctf_sequence_hex(uint8_t, Cid, Cid, uint8_t, CidLength)*/)
)
QUIC_TRACE_EVENT(ConnDestCidRemoved,
    TP_ARGS(
        const void*, Connection,
        uint64_t, SequenceNumber,
        uint8_t, CidLength,
        const void*, Cid),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer_hex(uint64_t, SequenceNumber, SequenceNumber)
        /*ctf_sequence_hex(uint8_t, Cid, Cid, uint8_t, CidLength)*/)
)
QUIC_TRACE_EVENT(ConnLossDetectionTimerSet,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(ConnLossDetectionTimerCancel,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnDropPacket,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr,
        const char*, Reason),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3)
        /*ctf_sequence_hex(uint8_t, LocalAddr, LocalAddr, uint8_t, LocalAddrLength)*/
        /*ctf_sequence_hex(uint8_t, RemoteAddr, RemoteAddr, uint8_t, RemoteAddrLength)*/
        ctf_string(Reason, Reason))
)
QUIC_TRACE_EVENT(ConnDropPacketEx,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3,
        uint64_t, arg4,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr,
        const char*, Reason),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        /*ctf_sequence_hex(uint8_t, LocalAddr, LocalAddr, uint8_t, LocalAddrLength)*/
        /*ctf_sequence_hex(uint8_t, RemoteAddr, RemoteAddr, uint8_t, RemoteAddrLength)*/
        ctf_string(Reason, Reason))
)
QUIC_TRACE_EVENT(ConnError,
    TP_ARGS(
        const void*, Connection,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_LEVEL(ConnError, TRACE_ERR)
QUIC_TRACE_EVENT(ConnErrorStatus,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_LEVEL(ConnErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(ConnNewPacketKeys,
    TP_ARGS(
        const void*, Connection),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection))
)
QUIC_TRACE_EVENT(ConnKeyPhaseChange,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnStats,
    TP_ARGS(
        const void*, Connection,
        uint32_t, SmoothedRtt,
        uint32_t, CongestionCount,
        uint32_t, PersistentCongestionCount,
        uint64_t, SendTotalBytes,
        uint64_t, RecvTotalBytes),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, SmoothedRtt, SmoothedRtt)
        ctf_integer(uint32_t, CongestionCount, CongestionCount)
        ctf_integer(uint32_t, PersistentCongestionCount, PersistentCongestionCount)
        ctf_integer(uint64_t, SendTotalBytes, SendTotalBytes)
        ctf_integer(uint64_t, RecvTotalBytes, RecvTotalBytes))
)
QUIC_TRACE_EVENT(ConnPacketStats,
    TP_ARGS(
        const void*, Connection,
        uint64_t, SendTotalPackets,
        uint64_t, SendSuspectedLostPackets,
        uint64_t, SendSpuriousLostPackets,
        uint64_t, RecvTotalPackets,
        uint64_t, RecvReorderedPackets,
        uint64_t, RecvDroppedPackets,
        uint64_t, RecvDuplicatePackets,
        uint64_t, RecvDecryptionFailures),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, SendTotalPackets, SendTotalPackets)
        ctf_integer(uint64_t, SendSuspectedLostPackets, SendSuspectedLostPackets)
        ctf_integer(uint64_t, SendSpuriousLostPackets, SendSpuriousLostPackets)
        ctf_integer(uint64_t, RecvTotalPackets, RecvTotalPackets)
        ctf_integer(uint64_t, RecvReorderedPackets, RecvReorderedPackets)
        ctf_integer(uint64_t, RecvDroppedPackets, RecvDroppedPackets)
        ctf_integer(uint64_t, RecvDuplicatePackets, RecvDuplicatePackets)
        ctf_integer(uint64_t, RecvDecryptionFailures, RecvDecryptionFailures))
)
QUIC_TRACE_EVENT(ConnShutdownComplete,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnReadKeyUpdated,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnWriteKeyUpdated,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(ConnPacketSent,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(ConnPacketRecv,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(ConnPacketLost,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(ConnPacketACKed,
    TP_ARGS(
        const void*, Connection,
        uint64_t, arg3,
        uint32_t, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4))
)
QUIC_TRACE_EVENT(ConnQueueSendFlush,
    TP_ARGS(
        const void*, Connection,
        uint32_t, Reason),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, Reason, Reason))
)
QUIC_TRACE_EVENT(StreamCreated,
    TP_ARGS(
        const void*, Stream,
        const void*, arg3,
        uint64_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(StreamDestroyed,
    TP_ARGS(
        const void*, Stream),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream))
)
QUIC_TRACE_EVENT(StreamOutFlowBlocked,
    TP_ARGS(
        const void*, Stream,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(StreamRundown,
    TP_ARGS(
        const void*, Stream,
        const void*, arg3,
        uint64_t, arg4,
        uint32_t, arg5),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(StreamSendState,
    TP_ARGS(
        const void*, Stream,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(StreamRecvState,
    TP_ARGS(
        const void*, Stream,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(StreamError,
    TP_ARGS(
        const void*, Stream,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_LEVEL(StreamError, TRACE_ERR)
QUIC_TRACE_EVENT(StreamErrorStatus,
    TP_ARGS(
        const void*, Stream,
        uint32_t, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Stream, Stream)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_LEVEL(StreamErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(BindingCreated,
    TP_ARGS(
        const void*, Binding,
        const void*, DatapathBinding,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_integer_hex(uint64_t, DatapathBinding, DatapathBinding)
        /*ctf_sequence_hex(uint8_t, LocalAddr, LocalAddr, uint8_t, LocalAddrLength)*/
        /*ctf_sequence_hex(uint8_t, RemoteAddr, RemoteAddr, uint8_t, RemoteAddrLength)*/)
)
QUIC_TRACE_EVENT(BindingRundown,
    TP_ARGS(
        const void*, Binding,
        const void*, DatapathBinding,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_integer_hex(uint64_t, DatapathBinding, DatapathBinding)
        /*ctf_sequence_hex(uint8_t, LocalAddr, LocalAddr, uint8_t, LocalAddrLength)*/
        /*ctf_sequence_hex(uint8_t, RemoteAddr, RemoteAddr, uint8_t, RemoteAddrLength)*/)
)
QUIC_TRACE_EVENT(BindingDestroyed,
    TP_ARGS(
        const void*, Binding),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding))
)
QUIC_TRACE_EVENT(BindingCleanup,
    TP_ARGS(
        const void*, Binding),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding))
)
QUIC_TRACE_EVENT(BindingDropPacket,
    TP_ARGS(
        const void*, Binding,
        uint64_t, arg3,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr,
        const char*, Reason),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_integer(uint64_t, arg3, arg3)
        /*ctf_sequence_hex(uint8_t, LocalAddr, LocalAddr, uint8_t, LocalAddrLength)*/
        /*ctf_sequence_hex(uint8_t, RemoteAddr, RemoteAddr, uint8_t, RemoteAddrLength)*/
        ctf_string(Reason, Reason))
)
QUIC_TRACE_EVENT(BindingDropPacketEx,
    TP_ARGS(
        const void*, Binding,
        uint64_t, arg3,
        uint64_t, arg4,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr,
        const char*, Reason),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        /*ctf_sequence_hex(uint8_t, LocalAddr, LocalAddr, uint8_t, LocalAddrLength)*/
        /*ctf_sequence_hex(uint8_t, RemoteAddr, RemoteAddr, uint8_t, RemoteAddrLength)*/
        ctf_string(Reason, Reason))
)
QUIC_TRACE_EVENT(BindingError,
    TP_ARGS(
        const void*, Binding,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_LEVEL(BindingError, TRACE_ERR)
QUIC_TRACE_EVENT(BindingErrorStatus,
    TP_ARGS(
        const void*, Binding,
        uint32_t, arg3,
        const char*, arg4),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(arg4, arg4))
)
QUIC_TRACE_LEVEL(BindingErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(BindingExecOper,
    TP_ARGS(
        const void*, Binding,
        uint32_t, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Binding, Binding)
        ctf_integer(uint32_t, arg3, arg3))
)
QUIC_TRACE_EVENT(TlsError,
    TP_ARGS(
        const void*, Connection,
        const char*, Msg),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_string(Msg, Msg))
)
QUIC_TRACE_LEVEL(TlsError, TRACE_ERR)
QUIC_TRACE_EVENT(TlsErrorStatus,
    TP_ARGS(
        const void*, Connection,
        uint32_t, arg3,
        const char*, Msg),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(Msg, Msg))
)
QUIC_TRACE_LEVEL(TlsErrorStatus, TRACE_ERR)
QUIC_TRACE_EVENT(TlsMessage,
    TP_ARGS(
        const void*, Connection,
        const char*, arg3),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, Connection, Connection)
        ctf_string(arg3, arg3))
)
QUIC_TRACE_EVENT(DatapathSendTo,
    TP_ARGS(
        const void*, UdpBinding,
        uint32_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5,
        uint8_t, LocalAddrLength,
        const void*, LocalAddr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, UdpBinding, UdpBinding)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(DatapathSendFromTo,
    TP_ARGS(
        const void*, UdpBinding,
        uint32_t, arg3,
        uint32_t, arg4,
        uint32_t, arg5,
        uint8_t, RemoteAddrLength,
        uint8_t, LocalAddrLength,
        const void*, RemoteAddr,
        const void*, LocalAddr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, UdpBinding, UdpBinding)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4)
        ctf_integer(uint32_t, arg5, arg5))
)
QUIC_TRACE_EVENT(DatapathRecv,
    TP_ARGS(
        const void*, UdpBinding,
        uint32_t, arg3,
        uint32_t, arg4,
        uint8_t, LocalAddrLength,
        uint8_t, RemoteAddrLength,
        const void*, LocalAddr,
        const void*, RemoteAddr),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, UdpBinding, UdpBinding)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_integer(uint32_t, arg4, arg4))
)
QUIC_TRACE_EVENT(DatapathError,
    TP_ARGS(
        const void*, UdpBinding,
        const char*, Msg),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, UdpBinding, UdpBinding)
        ctf_string(Msg, Msg))
)
QUIC_TRACE_LEVEL(DatapathError, TRACE_ERR)
QUIC_TRACE_EVENT(DatapathErrorStatus,
    TP_ARGS(
        const void*, UdpBinding,
        uint32_t, arg3,
        const char*, Msg),
    TP_FIELDS(
        ctf_integer_hex(uint64_t, UdpBinding, UdpBinding)
        ctf_integer(uint32_t, arg3, arg3)
        ctf_string(Msg, Msg))
)
QUIC_TRACE_LEVEL(DatapathErrorStatus, TRACE_ERR)

#define QuicTraceEventEnabled(Name) FALSE
#define QuicTraceEvent(Name, ...) 

//printf("\n" __VA_ARGS__)
#define LOG_ADDR_LEN(Addr) Addr

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
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#pragma warning(pop)

#define QuicTraceEventEnabled(Name) EventEnabledQuic##Name()
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(Name, Fmt, ...) _QuicTraceEvent(Name, (__VA_ARGS__))

#define LOG_ADDR_LEN(Addr) \
    (uint8_t)((Addr).si_family == AF_INET6 ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN))

#endif // QUIC_EVENTS_MANIFEST_ETW

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

#define QuicTraceLogError(X,...)            QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogWarning(X,...)          QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogInfo(X,...)             QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogVerbose(X,...)          QuicTraceStubVarArgs(__VA_ARGS__)

#define QuicTraceLogConnError(X,...)        QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogConnWarning(X,...)      QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogConnInfo(X,...)         QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogConnVerbose(X,...)      QuicTraceStubVarArgs(__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() FALSE

#define QuicTraceLogStreamError(X,...)      QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogStreamWarning(X,...)    QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogStreamInfo(X,...)       QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogStreamVerbose(X,...)    QuicTraceStubVarArgs(__VA_ARGS__)

#endif // QUIC_LOGS_STUB

#ifdef QUIC_LOGS_MANIFEST_ETW

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#pragma warning(pop)

#include <stdio.h>

#define QuicTraceLogErrorEnabled()   EventEnabledQuicLogError()
#define QuicTraceLogWarningEnabled() EventEnabledQuicLogWarning()
#define QuicTraceLogInfoEnabled()    EventEnabledQuicLogInfo()
#define QuicTraceLogVerboseEnabled() EventEnabledQuicLogVerbose()

#if DEBUG
#define QUIC_ETW_BUFFER_LENGTH 512
#else
#define QUIC_ETW_BUFFER_LENGTH 256
#endif

#define LogEtw(EventName, Fmt, ...) \
    if (EventEnabledQuicLog##EventName()) { \
        char EtwBuffer[QUIC_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteQuicLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogEtwType(Type, EventName, Ptr, Fmt, ...) \
    if (EventEnabledQuic##Type##Log##EventName()) { \
        char EtwBuffer[QUIC_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteQuic##Type##Log##EventName##_AssumeEnabled(Ptr, EtwBuffer); \
    }

#define QuicTraceLogError(Name, Fmt, ...)               LogEtw(Error, Fmt, ##__VA_ARGS__)
#define QuicTraceLogWarning(Name, Fmt, ...)             LogEtw(Warning, Fmt, ##__VA_ARGS__)
#define QuicTraceLogInfo(Name, Fmt, ...)                LogEtw(Info, Fmt, ##__VA_ARGS__)
#define QuicTraceLogVerbose(Name, Fmt, ...)             LogEtw(Verbose, Fmt, ##__VA_ARGS__)

#define QuicTraceLogConnError(Name, Ptr, Fmt, ...)      LogEtwType(Conn, Error, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnWarning(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnInfo(Name, Ptr, Fmt, ...)       LogEtwType(Conn, Info, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnVerbose(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() EventEnabledQuicStreamLogVerbose()

#define QuicTraceLogStreamError(Name, Ptr, Fmt, ...)    LogEtwType(Stream, Error, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamWarning(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamInfo(Name, Ptr, Fmt, ...)     LogEtwType(Stream, Info, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamVerbose(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#endif // QUIC_LOGS_MANIFEST_ETW

#ifdef QUIC_LOGS_LTTNG

#error "LTTng not supported yet!"

#endif // QUIC_LOGS_LTTNG

#endif // _TRACE_H
