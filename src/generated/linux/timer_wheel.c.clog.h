#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TIMER_WHEEL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "timer_wheel.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_TIMER_WHEEL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TIMER_WHEEL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "timer_wheel.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for TimerWheelResize
// [time][%p] Resizing timer wheel (new slot count = %u).
// QuicTraceLogVerbose(
        TimerWheelResize,
        "[time][%p] Resizing timer wheel (new slot count = %u).",
        TimerWheel,
        NewSlotCount);
// arg2 = arg2 = TimerWheel = arg2
// arg3 = arg3 = NewSlotCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_TimerWheelResize
#define _clog_4_ARGS_TRACE_TimerWheelResize(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TIMER_WHEEL_C, TimerWheelResize , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TimerWheelNextExpirationNull
// [time][%p] Next Expiration = {NULL}.
// QuicTraceLogVerbose(
            TimerWheelNextExpirationNull,
            "[time][%p] Next Expiration = {NULL}.",
            TimerWheel);
// arg2 = arg2 = TimerWheel = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TimerWheelNextExpirationNull
#define _clog_3_ARGS_TRACE_TimerWheelNextExpirationNull(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TIMER_WHEEL_C, TimerWheelNextExpirationNull , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TimerWheelNextExpiration
// [time][%p] Next Expiration = {%llu, %p}.
// QuicTraceLogVerbose(
            TimerWheelNextExpiration,
            "[time][%p] Next Expiration = {%llu, %p}.",
            TimerWheel,
            TimerWheel->NextExpirationTime,
            TimerWheel->NextConnection);
// arg2 = arg2 = TimerWheel = arg2
// arg3 = arg3 = TimerWheel->NextExpirationTime = arg3
// arg4 = arg4 = TimerWheel->NextConnection = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_TimerWheelNextExpiration
#define _clog_5_ARGS_TRACE_TimerWheelNextExpiration(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TIMER_WHEEL_C, TimerWheelNextExpiration , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TimerWheelRemoveConnection
// [time][%p] Removing Connection %p.
// QuicTraceLogVerbose(
            TimerWheelRemoveConnection,
            "[time][%p] Removing Connection %p.",
            TimerWheel,
            Connection);
// arg2 = arg2 = TimerWheel = arg2
// arg3 = arg3 = Connection = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_TimerWheelRemoveConnection
#define _clog_4_ARGS_TRACE_TimerWheelRemoveConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TIMER_WHEEL_C, TimerWheelRemoveConnection , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TimerWheelUpdateConnection
// [time][%p] Updating Connection %p.
// QuicTraceLogVerbose(
            TimerWheelUpdateConnection,
            "[time][%p] Updating Connection %p.",
            TimerWheel,
            Connection);
// arg2 = arg2 = TimerWheel = arg2
// arg3 = arg3 = Connection = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_TimerWheelUpdateConnection
#define _clog_4_ARGS_TRACE_TimerWheelUpdateConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TIMER_WHEEL_C, TimerWheelUpdateConnection , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StillInTimerWheel
// [conn][%p] Still in timer wheel! Connection was likely leaked!
// QuicTraceLogConnWarning(
                    StillInTimerWheel,
                    Connection,
                    "Still in timer wheel! Connection was likely leaked!");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_StillInTimerWheel
#define _clog_3_ARGS_TRACE_StillInTimerWheel(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TIMER_WHEEL_C, StillInTimerWheel , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "timerwheel slots",
            QUIC_TIMER_WHEEL_INITIAL_SLOT_COUNT * sizeof(CXPLAT_LIST_ENTRY));
// arg2 = arg2 = "timerwheel slots" = arg2
// arg3 = arg3 = QUIC_TIMER_WHEEL_INITIAL_SLOT_COUNT * sizeof(CXPLAT_LIST_ENTRY) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TIMER_WHEEL_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_timer_wheel.c.clog.h.c"
#endif
