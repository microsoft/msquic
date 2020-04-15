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
    or build configurations can have their own desired behavior.

 --*/

#ifndef _TRACE_H
#define _TRACE_H

#pragma once

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

#define QuicTraceLogStreamVerboseEnabled() TRUE
#define QuicTraceLogErrorEnabled()   TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled()    TRUE
#define QuicTraceLogVerboseEnabled() TRUE
#define QuicTraceEventEnabled(x) TRUE

#ifdef QUIC_EVENTS_MANIFEST_ETW
#include "quic_trace_manifested_etw.h"
#endif

#ifdef QUIC_EVENTS_TRACELOGGING
#include "quic_trace_tracelogging.h"
#endif

#endif // _TRACE_H
