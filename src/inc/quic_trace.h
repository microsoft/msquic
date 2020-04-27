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
    QUIC_LOGS_WPP               Write to Windows WPP framework
    QUIC_LOGS_MANIFEST_ETW      Write to Windows ETW framework
    QUIC_LOGS_LTTNG             Write to Linux LTTng framework

 --*/

#ifndef _TRACE_H
#define _TRACE_H

#pragma once

#if !defined(QUIC_EVENTS_STUB) && !defined(QUIC_EVENTS_MANIFEST_ETW) && !defined(QUIC_EVENTS_LTTNG)
#error "Must define one QUIC_EVENTS_*"
#endif

#if !defined(QUIC_LOGS_STUB) && !defined(QUIC_LOGS_WPP) && !defined(QUIC_LOGS_MANIFEST_ETW) && !defined(QUIC_LOGS_LTTNG)
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
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#pragma warning(pop)

#define QuicTraceEventEnabled(Name) EventEnabledQuic##Name()
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(Name, ...) _QuicTraceEvent(Name, (__VA_ARGS__))

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
        sprintf_s(EtwBuffer, sizeof(EtwBuffer), Fmt, ##__VA_ARGS__); \
        EventWriteQuicLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogEtwType(Type, EventName, Ptr, Fmt, ...) \
    if (EventEnabledQuic##Type##Log##EventName()) { \
        char EtwBuffer[QUIC_ETW_BUFFER_LENGTH]; \
        sprintf_s(EtwBuffer, sizeof(EtwBuffer), Fmt, ##__VA_ARGS__); \
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

#ifdef QUIC_LOGS_LTTNG

#error "LTTng not supported yet!"

#endif // QUIC_LOGS_LTTNG

#endif // _TRACE_H
