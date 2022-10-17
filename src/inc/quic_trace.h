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
    QUIC_LOGS_STDOUT            Write to Windows ETW framework

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

#define QuicTraceLogStreamVerboseEnabled() TRUE
#define QuicTraceLogErrorEnabled()   TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled()    TRUE
#define QuicTraceLogVerboseEnabled() TRUE
#define QuicTraceEventEnabled(x) TRUE

#define CASTED_CLOG_BYTEARRAY(Len, Data) CLOG_BYTEARRAY((unsigned char)(Len), (const unsigned char*)(Data))
#else

#if defined(QUIC_EVENTS_STDOUT) || defined(QUIC_LOGS_STDOUT)
#include "msquichelper.h"
#include <stdio.h>

static inline void //__attribute__((format(printf, 1, 2)))
clog_stdout(const char * format, ...)
{
    static const char * repls[] = {"!CID!", "!ADDR!"};
    char * reformat = strdup(format);

    for (size_t i = 0; i < ARRAYSIZE(repls); i++) {
        char * match = reformat;

        while (1) {
            // find next match
            match = strstr(match, repls[i]);

            // break if no match
            if (match == 0) {
                break;
            }

            // replace match with 's' and shift rest of string
            *match++ = 's';
            const size_t repl_len = strlen(repls[i]) - 1;
            const size_t match_len = strlen(match + repl_len);
            memmove(match, match + repl_len, match_len + 1);
        }
    }

    va_list ap;
    va_start(ap, format);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vprintf(reformat, ap);
#pragma clang diagnostic pop
    va_end(ap);
    free(reformat);
}

#endif

#ifdef QUIC_EVENTS_STDOUT

#define QuicTraceEventEnabled(Name) TRUE

#define QuicTraceEvent(Name, Fmt, ...) clog_stdout((Fmt "\n"), ##__VA_ARGS__)

#define QUIC_CLOG_BYTEARRAY_MAX_LEN 256

#define DIAG_PUSH                                                              \
    _Pragma("clang diagnostic push")                                           \
    _Pragma("clang diagnostic ignored \"-Wtautological-constant-out-of-range-compare\"") \

#define DIAG_POP _Pragma("clang diagnostic pop")

// TODO: This just prints CASTED_CLOG_BYTEARRAYs as hexdumps. It would be nice
// to print the individual datatypes in better ways.

#define CASTED_CLOG_BYTEARRAY(Len, Data)                                       \
    ({                                                                         \
        DIAG_PUSH;                                                             \
        char _HexString[QUIC_CLOG_BYTEARRAY_MAX_LEN + 1] = "[buf too short]";  \
        if ((Len) < QUIC_CLOG_BYTEARRAY_MAX_LEN) {                             \
            EncodeHexBuffer((uint8_t *)(Data), (Len), _HexString);             \
            _HexString[QUIC_CLOG_BYTEARRAY_MAX_LEN] = 0;                       \
        }                                                                      \
        DIAG_POP;                                                              \
        _HexString;                                                            \
    })

#endif // QUIC_EVENTS_STDOUT

#ifdef QUIC_EVENTS_STUB

#define QuicTraceEventEnabled(Name) FALSE

inline
void
QuicTraceEventStubVarArgs(
    _In_ const void* Fmt,
    ...
    )
{
    UNREFERENCED_PARAMETER(Fmt);
}

#define QuicTraceEvent(Name, ...) QuicTraceEventStubVarArgs("", __VA_ARGS__)

#define CLOG_BYTEARRAY(Len, Data) (Len)
#define CASTED_CLOG_BYTEARRAY(Len, Data) (Len)

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
#if defined(_MSVC_TRADITIONAL) && _MSVC_TRADITIONAL
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(Name, Fmt, ...) _QuicTraceEvent(Name, (__VA_ARGS__))
#else
#define QuicTraceEvent(Name, Fmt, ...) EventWriteQuic##Name (__VA_ARGS__)
#endif

#define CLOG_BYTEARRAY(Len, Data) (uint8_t)(Len), (uint8_t*)(Data)
#define CASTED_CLOG_BYTEARRAY(Len, Data) CLOG_BYTEARRAY((unsigned char)(Len), (const unsigned char*)(Data))


#endif // QUIC_EVENTS_MANIFEST_ETW

#ifdef QUIC_LOGS_STDOUT

#define QuicTraceLogErrorEnabled() TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled() TRUE
#define QuicTraceLogVerboseEnabled() TRUE

#define QuicTraceLogError(A, Fmt, ...) clog_stdout((Fmt "\n"), ##__VA_ARGS__)
#define QuicTraceLogWarning(A, Fmt, ...) clog_stdout((Fmt "\n"), ##__VA_ARGS__)
#define QuicTraceLogInfo(A, Fmt, ...) clog_stdout((Fmt "\n"), ##__VA_ARGS__)
#define QuicTraceLogVerbose(A, Fmt, ...) clog_stdout((Fmt "\n"), ##__VA_ARGS__)

#define QuicTraceLogConnError(A, B, Fmt, ...)                                  \
    do {                                                                       \
        UNREFERENCED_PARAMETER(B);                                             \
        clog_stdout((Fmt "\n"), ##__VA_ARGS__);                                \
    } while (0)
#define QuicTraceLogConnWarning(A, B, Fmt, ...)                                \
    do {                                                                       \
        UNREFERENCED_PARAMETER(B);                                             \
        clog_stdout((Fmt "\n"), ##__VA_ARGS__);                                \
    } while (0)
#define QuicTraceLogConnInfo(A, B, Fmt, ...)                                   \
    do {                                                                       \
        UNREFERENCED_PARAMETER(B);                                             \
        clog_stdout((Fmt "\n"), ##__VA_ARGS__);                                \
    } while (0)
#define QuicTraceLogConnVerbose(A, B, Fmt, ...)                                \
    do {                                                                       \
        UNREFERENCED_PARAMETER(B);                                             \
        clog_stdout((Fmt "\n"), ##__VA_ARGS__);                                \
    } while (0)

#define QuicTraceLogStreamVerboseEnabled() TRUE

#define QuicTraceLogStreamError(A, B, Fmt, ...)                                \
    clog_stdout((Fmt "\n"), ##__VA_ARGS__)
#define QuicTraceLogStreamWarning(A, B, Fmt, ...)                              \
    clog_stdout((Fmt "\n"), ##__VA_ARGS__)
#define QuicTraceLogStreamInfo(A, B, Fmt, ...)                                 \
    clog_stdout((Fmt "\n"), ##__VA_ARGS__)
#define QuicTraceLogStreamVerbose(A, B, Fmt, ...)                              \
    clog_stdout((Fmt "\n"), ##__VA_ARGS__)

#endif // QUIC_LOGS_STDOUT

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
