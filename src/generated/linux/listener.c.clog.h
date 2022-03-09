#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
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
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for ListenerIndicateStopComplete
// [list][%p] Indicating STOP_COMPLETE
// QuicTraceLogVerbose(
            ListenerIndicateStopComplete,
            "[list][%p] Indicating STOP_COMPLETE",
            Listener);
// arg2 = arg2 = Listener = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ListenerIndicateStopComplete
#define _clog_3_ARGS_TRACE_ListenerIndicateStopComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ListenerIndicateStopComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerIndicateNewConnection
// [list][%p] Indicating NEW_CONNECTION %p
// QuicTraceLogVerbose(
        ListenerIndicateNewConnection,
        "[list][%p] Indicating NEW_CONNECTION %p",
        Listener,
        Connection);
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Connection = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ListenerIndicateNewConnection
#define _clog_4_ARGS_TRACE_ListenerIndicateNewConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerIndicateNewConnection , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerCibirIdSet
// [list][%p] CIBIR ID set (len %hhu, offset %hhu)
// QuicTraceLogVerbose(
            ListenerCibirIdSet,
            "[list][%p] CIBIR ID set (len %hhu, offset %hhu)",
            Listener,
            Listener->CibirId[0],
            Listener->CibirId[1]);
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Listener->CibirId[0] = arg3
// arg4 = arg4 = Listener->CibirId[1] = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ListenerCibirIdSet
#define _clog_5_ARGS_TRACE_ListenerCibirIdSet(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LISTENER_C, ListenerCibirIdSet , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CibirIdSet
// [conn][%p] CIBIR ID set (len %hhu, offset %hhu)
// QuicTraceLogConnInfo(
            CibirIdSet,
            Connection,
            "CIBIR ID set (len %hhu, offset %hhu)",
            Connection->CibirId[0],
            Connection->CibirId[1]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->CibirId[0] = arg3
// arg4 = arg4 = Connection->CibirId[1] = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CibirIdSet
#define _clog_5_ARGS_TRACE_CibirIdSet(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_LISTENER_C, CibirIdSet , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_LISTENER_OPEN,
        RegistrationHandle);
// arg2 = arg2 = QUIC_TRACE_API_LISTENER_OPEN = arg2
// arg3 = arg3 = RegistrationHandle = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ApiEnter
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ApiEnter , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "listener",
            sizeof(QUIC_LISTENER));
// arg2 = arg2 = "listener" = arg2
// arg3 = arg3 = sizeof(QUIC_LISTENER) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerCreated
// [list][%p] Created, Registration=%p
// QuicTraceEvent(
        ListenerCreated,
        "[list][%p] Created, Registration=%p",
        Listener,
        Listener->Registration);
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Listener->Registration = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ListenerCreated
#define _clog_4_ARGS_TRACE_ListenerCreated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerCreated , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ApiExitStatus
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ApiExitStatus , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerDestroyed
// [list][%p] Destroyed
// QuicTraceEvent(
        ListenerDestroyed,
        "[list][%p] Destroyed",
        Listener);
// arg2 = arg2 = Listener = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ListenerDestroyed
#define _clog_3_ARGS_TRACE_ListenerDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ListenerDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_ApiExit
#define _clog_2_ARGS_TRACE_ApiExit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LISTENER_C, ApiExit );\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerErrorStatus
// [list][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "Get binding");
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Get binding" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ListenerErrorStatus
#define _clog_5_ARGS_TRACE_ListenerErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LISTENER_C, ListenerErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerError
// [list][%p] ERROR, %s.
// QuicTraceEvent(
            ListenerError,
            "[list][%p] ERROR, %s.",
            Listener,
            "Register with binding");
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = "Register with binding" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ListenerError
#define _clog_4_ARGS_TRACE_ListenerError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerStarted
// [list][%p] Started, Binding=%p, LocalAddr=%!ADDR!, ALPN=%!ALPN!
// QuicTraceEvent(
        ListenerStarted,
        "[list][%p] Started, Binding=%p, LocalAddr=%!ADDR!, ALPN=%!ALPN!",
        Listener,
        Listener->Binding,
        CASTED_CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Listener->AlpnListLength, Listener->AlpnList));
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Listener->Binding = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Listener->LocalAddress), &Listener->LocalAddress) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(Listener->AlpnListLength, Listener->AlpnList) = arg5
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_ListenerStarted
#define _clog_8_ARGS_TRACE_ListenerStarted(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len, arg5, arg5_len)\
tracepoint(CLOG_LISTENER_C, ListenerStarted , arg2, arg3, arg4_len, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerStopped
// [list][%p] Stopped
// QuicTraceEvent(
        ListenerStopped,
        "[list][%p] Stopped",
        Listener);
// arg2 = arg2 = Listener = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ListenerStopped
#define _clog_3_ARGS_TRACE_ListenerStopped(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LISTENER_C, ListenerStopped , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerRundown
// [list][%p] Rundown, Registration=%p
// QuicTraceEvent(
        ListenerRundown,
        "[list][%p] Rundown, Registration=%p",
        Listener,
        Listener->Registration);
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Listener->Registration = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ListenerRundown
#define _clog_4_ARGS_TRACE_ListenerRundown(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ListenerRundown , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Connection rejected by registration (overloaded)");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Connection rejected by registration (overloaded)" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LISTENER_C, ConnError , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_listener.c.clog.h.c"
#endif
