#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_LISTENER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "listener.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_LISTENER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_LISTENER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "listener.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_4_ARGS_TRACE_ListenerIndicateNewConnection



/*----------------------------------------------------------
// Decoder Ring for ListenerIndicateNewConnection
// [list][%p] Indicating NEW_CONNECTION %p
// QuicTraceLogVerbose(
        ListenerIndicateNewConnection,
        "[list][%p] Indicating NEW_CONNECTION %p",
        Listener,
        Connection);
// arg2 = arg2 = Listener
// arg3 = arg3 = Connection
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ListenerIndicateNewConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerIndicateNewConnection , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_OPEN,
        RegistrationHandle);
// arg2 = arg2 = QUIC_TRACE_API_LISTENER_OPEN
// arg3 = arg3 = RegistrationHandle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ApiEnter , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "listener",
            sizeof(QUIC_LISTENER));
// arg2 = arg2 = "listener"
// arg3 = arg3 = sizeof(QUIC_LISTENER)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ListenerCreated



/*----------------------------------------------------------
// Decoder Ring for ListenerCreated
// [list][%p] Created, Registration=%p
// QuicTraceEvent(
        ListenerCreated,
        "[list][%p] Created, Registration=%p",
        Listener,
        Listener->Registration);
// arg2 = arg2 = Listener
// arg3 = arg3 = Listener->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ListenerCreated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerCreated , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_ApiExitStatus



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ApiExitStatus , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_CLOSE,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_LISTENER_CLOSE
// arg3 = arg3 = Handle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ListenerDestroyed



/*----------------------------------------------------------
// Decoder Ring for ListenerDestroyed
// [list][%p] Destroyed
// QuicTraceEvent(
        ListenerDestroyed,
        "[list][%p] Destroyed",
        Listener);
// arg2 = arg2 = Listener
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ListenerDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ListenerDestroyed , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_ApiExit



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_ApiExit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LISTENER_C, ApiExit );\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_START,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_LISTENER_START
// arg3 = arg3 = Handle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "AlpnList" ,
            AlpnListLength);
// arg2 = arg2 = "AlpnList"
// arg3 = arg3 = AlpnListLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ListenerErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ListenerErrorStatus
// [list][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "Get binding");
// arg2 = arg2 = Listener
// arg3 = arg3 = Status
// arg4 = arg4 = "Get binding"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ListenerErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LISTENER_C, ListenerErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ListenerError



/*----------------------------------------------------------
// Decoder Ring for ListenerError
// [list][%p] ERROR, %s.
// QuicTraceEvent(
            ListenerError,
            "[list][%p] ERROR, %s.",
            Listener,
            "Register with binding");
// arg2 = arg2 = Listener
// arg3 = arg3 = "Register with binding"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ListenerError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerError , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_ListenerStarted



/*----------------------------------------------------------
// Decoder Ring for ListenerStarted
// [list][%p] Started, Binding=%p, LocalAddr=%!ADDR!
// QuicTraceEvent(
        ListenerStarted,
        "[list][%p] Started, Binding=%p, LocalAddr=%!ADDR!",
        Listener,
        Listener->Binding,
        CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress));
// arg2 = arg2 = Listener
// arg3 = arg3 = Listener->Binding
// arg4 = arg4 = CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ListenerStarted(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_LISTENER_C, ListenerStarted , arg2, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_ApiExitStatus



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_STOP,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_LISTENER_STOP
// arg3 = arg3 = Handle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ListenerStopped



/*----------------------------------------------------------
// Decoder Ring for ListenerStopped
// [list][%p] Stopped
// QuicTraceEvent(
                ListenerStopped,
                "[list][%p] Stopped",
                Listener);
// arg2 = arg2 = Listener
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ListenerStopped(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ListenerStopped , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_ApiExit



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_ApiExit(uniqueId, encoded_arg_string)\

#endif




#ifndef _clog_4_ARGS_TRACE_ListenerRundown



/*----------------------------------------------------------
// Decoder Ring for ListenerRundown
// [list][%p] Rundown, Registration=%p
// QuicTraceEvent(
        ListenerRundown,
        "[list][%p] Rundown, Registration=%p",
        Listener,
        Listener->Registration);
// arg2 = arg2 = Listener
// arg3 = arg3 = Listener->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ListenerRundown(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerRundown , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_ListenerStarted



/*----------------------------------------------------------
// Decoder Ring for ListenerStarted
// [list][%p] Started, Binding=%p, LocalAddr=%!ADDR!
// QuicTraceEvent(
            ListenerStarted,
            "[list][%p] Started, Binding=%p, LocalAddr=%!ADDR!",
            Listener,
            Listener->Binding,
            CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress));
// arg2 = arg2 = Listener
// arg3 = arg3 = Listener->Binding
// arg4 = arg4 = CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ListenerStarted(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ListenerErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ListenerErrorStatus
// [list][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "NEW_CONNECTION callback");
// arg2 = arg2 = Listener
// arg3 = arg3 = Status
// arg4 = arg4 = "NEW_CONNECTION callback"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ListenerErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Connection rejected by registration (overloaded)");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Connection rejected by registration (overloaded)"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ConnError , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_listener.c.clog.h.c"
#endif
