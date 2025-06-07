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
    QUIC_EVENTS_STDOUT          Write to stdout

    QUIC_LOGS_STUB              No-op all Logs
    QUIC_LOGS_MANIFEST_ETW      Write to Windows ETW framework
    QUIC_LOGS_STDOUT            Write to stdout

    QUIC_CLOG                   Bypasses these mechanisms and uses CLOG to generate logging

 --*/

#pragma once

#if !defined(QUIC_CLOG)
#if !defined(QUIC_EVENTS_STUB) && !defined(QUIC_EVENTS_MANIFEST_ETW) && !defined(QUIC_EVENTS_STDOUT)
#error "Must define one QUIC_EVENTS_*"
#endif

#if !defined(QUIC_LOGS_STUB) && !defined(QUIC_LOGS_MANIFEST_ETW) && !defined(QUIC_LOGS_STDOUT)
#error "Must define one QUIC_LOGS_*"
#endif
#endif

//
// Every data structure here has a matching ETW manifest definition. If you
// want to add something new, be sure to append it to the relevant enum block so
// as to preserve the existing values / order.
//
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
    QUIC_TRACE_API_REGISTRATION_SHUTDOWN,
    QUIC_TRACE_API_CONFIGURATION_OPEN,
    QUIC_TRACE_API_CONFIGURATION_CLOSE,
    QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
    QUIC_TRACE_API_LISTENER_OPEN,
    QUIC_TRACE_API_LISTENER_CLOSE,
    QUIC_TRACE_API_LISTENER_START,
    QUIC_TRACE_API_LISTENER_STOP,
    QUIC_TRACE_API_CONNECTION_OPEN,
    QUIC_TRACE_API_CONNECTION_CLOSE,
    QUIC_TRACE_API_CONNECTION_SHUTDOWN,
    QUIC_TRACE_API_CONNECTION_START,
    QUIC_TRACE_API_CONNECTION_SET_CONFIGURATION,
    QUIC_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
    QUIC_TRACE_API_STREAM_OPEN,
    QUIC_TRACE_API_STREAM_CLOSE,
    QUIC_TRACE_API_STREAM_START,
    QUIC_TRACE_API_STREAM_SHUTDOWN,
    QUIC_TRACE_API_STREAM_SEND,
    QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
    QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
    QUIC_TRACE_API_DATAGRAM_SEND,
    QUIC_TRACE_API_CONNECTION_COMPLETE_RESUMPTION_TICKET_VALIDATION,
    QUIC_TRACE_API_CONNECTION_COMPLETE_CERTIFICATE_VALIDATION,
    QUIC_TRACE_API_STREAM_PROVIDE_RECEIVE_BUFFERS,
    QUIC_TRACE_API_CONNECTION_POOL_CREATE,
    QUIC_TRACE_API_EXECUTION_CREATE,
    QUIC_TRACE_API_EXECUTION_DELETE,
    QUIC_TRACE_API_EXECUTION_POLL,
    QUIC_TRACE_API_COUNT // Must be last
} QUIC_TRACE_API_TYPE;

//
// Called from the platform code to trigger a tracing rundown for all objects
// in the current process (or kernel mode).
//
#ifdef __cplusplus
extern "C"
#endif
typedef
_Function_class_(QUIC_TRACE_RUNDOWN_CALLBACK)
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_TRACE_RUNDOWN_CALLBACK)(
    void
    );

extern QUIC_TRACE_RUNDOWN_CALLBACK* QuicTraceRundownCallback;

#ifdef QUIC_CLOG

#if DEBUG
#define QuicTraceLogStreamVerboseEnabled() TRUE
#define QuicTraceLogErrorEnabled()   TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled()    TRUE
#define QuicTraceLogVerboseEnabled() TRUE
#define QuicTraceEventEnabled(x) TRUE
#else
#define QuicTraceLogStreamVerboseEnabled() FALSE
#define QuicTraceLogErrorEnabled()   FALSE
#define QuicTraceLogWarningEnabled() FALSE
#define QuicTraceLogInfoEnabled()    FALSE
#define QuicTraceLogVerboseEnabled() FALSE
#define QuicTraceEventEnabled(x) FALSE
#endif

#define CASTED_CLOG_BYTEARRAY(Len, Data) CLOG_BYTEARRAY((unsigned char)(Len), (const unsigned char*)(Data))
#define CASTED_CLOG_BYTEARRAY16(Len, Data) CLOG_BYTEARRAY((unsigned short)(Len), (const unsigned char*)(Data))
#else

#if defined(QUIC_EVENTS_STDOUT) || defined(QUIC_LOGS_STDOUT) ||                \
    defined(QUIC_EVENTS_STUB) || defined(QUIC_LOGS_STUB)

struct clog_param {
    char * str;
    struct clog_param * next;
};

#if defined(QUIC_EVENTS_STDOUT) || defined(QUIC_LOGS_STDOUT)
extern
#ifdef __cplusplus
    "C"
#endif
void //__attribute__((no_instrument_function, format(printf, 2, 3)))
clog_stdout(struct clog_param * head, const char * format, ...);
#else
QUIC_INLINE void //__attribute__((no_instrument_function, format(printf, 2, 3)))
clog_stdout(struct clog_param * head, const char * format, ...)
{
    UNREFERENCED_PARAMETER(head);
    UNREFERENCED_PARAMETER(format);
}
#endif

#define clog(Fmt, ...)                                                         \
    do {                                                                       \
        struct clog_param * __head = 0;                                        \
        clog_stdout(__head, (Fmt), ##__VA_ARGS__);                             \
    } while (0)

#endif

#if defined(QUIC_EVENTS_STDOUT) || defined(QUIC_LOGS_STUB)
#define QuicTraceEventEnabled(Name) TRUE

#define QuicTrace(Name, Fmt, ...)                                              \
    clog((Fmt " [" #Name ":%s:%d]\n"), ##__VA_ARGS__, __FILE__, __LINE__)

#define QuicTraceEvent(Name, Fmt, ...) QuicTrace(Name, Fmt, ##__VA_ARGS__)

#if defined(QUIC_EVENTS_STDOUT)
extern
#ifdef __cplusplus
    "C"
#endif
char *
#ifndef _WIN32
__attribute__((no_instrument_function))
#endif
casted_clog_bytearray(const uint8_t * const data,
                      const size_t len,
                      struct clog_param ** head);
#else
QUIC_INLINE char *
#ifndef _WIN32
__attribute__((no_instrument_function))
#endif
casted_clog_bytearray(const uint8_t * const data,
                      const size_t len,
                      struct clog_param ** head)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(head);
    return 0;
}

#endif

#define CASTED_CLOG_BYTEARRAY(Len, Data)                                       \
    casted_clog_bytearray((const uint8_t *)(Data), (Len), &__head)

#define CASTED_CLOG_BYTEARRAY16(Len, Data)                                       \
    casted_clog_bytearray((const uint8_t *)(Data), (Len), &__head)

#endif

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
#if defined(_MSVC_TRADITIONAL) && _MSVC_TRADITIONAL
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(Name, Fmt, ...) _QuicTraceEvent(Name, (__VA_ARGS__))
#else
#define QuicTraceEvent(Name, Fmt, ...) EventWriteQuic##Name (__VA_ARGS__)
#endif

#define CLOG_BYTEARRAY(Len, Data) (uint8_t)(Len), (uint8_t*)(Data)
#define CASTED_CLOG_BYTEARRAY(Len, Data) CLOG_BYTEARRAY((unsigned char)(Len), (const unsigned char*)(Data))

#define CLOG_BYTEARRAY16(Len, Data) (uint16_t)(Len), (uint8_t*)(Data)
#define CASTED_CLOG_BYTEARRAY16(Len, Data) CLOG_BYTEARRAY16((unsigned short)(Len), (const unsigned char*)(Data))


#endif // QUIC_EVENTS_MANIFEST_ETW

#if defined(QUIC_LOGS_STDOUT) || defined(QUIC_LOGS_STUB)

#define QuicTraceLogErrorEnabled() TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled() TRUE
#define QuicTraceLogVerboseEnabled() TRUE

#define QuicTraceLogError(Name, Fmt, ...) QuicTrace(Name, Fmt, ##__VA_ARGS__)
#define QuicTraceLogWarning(Name, Fmt, ...) QuicTrace(Name, Fmt, ##__VA_ARGS__)
#define QuicTraceLogInfo(Name, Fmt, ...) QuicTrace(Name, Fmt, ##__VA_ARGS__)
#define QuicTraceLogVerbose(Name, Fmt, ...) QuicTrace(Name, Fmt, ##__VA_ARGS__)

#define QuicTraceLogConnError(Name, X, Fmt, ...)                               \
    do {                                                                       \
        UNREFERENCED_PARAMETER(X);                                             \
        QuicTrace(Name, Fmt, ##__VA_ARGS__);                                   \
    } while (0)
#define QuicTraceLogConnWarning(Name, X, Fmt, ...)                             \
    do {                                                                       \
        UNREFERENCED_PARAMETER(X);                                             \
        QuicTrace(Name, Fmt, ##__VA_ARGS__);                                   \
    } while (0)
#define QuicTraceLogConnInfo(Name, X, Fmt, ...)                                \
    do {                                                                       \
        UNREFERENCED_PARAMETER(X);                                             \
        QuicTrace(Name, Fmt, ##__VA_ARGS__);                                   \
    } while (0)
#define QuicTraceLogConnVerbose(Name, X, Fmt, ...)                             \
    do {                                                                       \
        UNREFERENCED_PARAMETER(X);                                             \
        QuicTrace(Name, Fmt, ##__VA_ARGS__);                                   \
    } while (0)

#define QuicTraceLogStreamVerboseEnabled() TRUE

#define QuicTraceLogStreamError(Name, X, Fmt, ...)                             \
    QuicTrace(Name, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamWarning(Name, X, Fmt, ...)                           \
    QuicTrace(Name, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamInfo(Name, X, Fmt, ...)                              \
    QuicTrace(Name, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamVerbose(Name, X, Fmt, ...)                           \
    QuicTrace(Name, Fmt, ##__VA_ARGS__)

#endif

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

#define QUIC_ETW_BUFFER_LENGTH 128

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

#endif // QUIC_CLOG
