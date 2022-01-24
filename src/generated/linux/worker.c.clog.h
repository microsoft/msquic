#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_WORKER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "worker.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_WORKER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_WORKER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "worker.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for IndicateIdealProcChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED
// QuicTraceLogConnVerbose(
            IndicateIdealProcChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicateIdealProcChanged
#define _clog_3_ARGS_TRACE_IndicateIdealProcChanged(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_WORKER_C, IndicateIdealProcChanged , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AbandonOnLibShutdown
// [conn][%p] Abandoning on shutdown
// QuicTraceLogConnVerbose(
                AbandonOnLibShutdown,
                Connection,
                "Abandoning on shutdown");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_AbandonOnLibShutdown
#define _clog_3_ARGS_TRACE_AbandonOnLibShutdown(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_WORKER_C, AbandonOnLibShutdown , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerCreated
// [wrkr][%p] Created, IdealProc=%hu Owner=%p
// QuicTraceEvent(
        WorkerCreated,
        "[wrkr][%p] Created, IdealProc=%hu Owner=%p",
        Worker,
        IdealProcessor,
        Owner);
// arg2 = arg2 = Worker = arg2
// arg3 = arg3 = IdealProcessor = arg3
// arg4 = arg4 = Owner = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_WorkerCreated
#define _clog_5_ARGS_TRACE_WorkerCreated(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_WORKER_C, WorkerCreated , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerErrorStatus
// [wrkr][%p] ERROR, %u, %s.
// QuicTraceEvent(
            WorkerErrorStatus,
            "[wrkr][%p] ERROR, %u, %s.",
            Worker,
            Status,
            "CxPlatThreadCreate");
// arg2 = arg2 = Worker = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "CxPlatThreadCreate" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_WorkerErrorStatus
#define _clog_5_ARGS_TRACE_WorkerErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_WORKER_C, WorkerErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerCleanup
// [wrkr][%p] Cleaning up
// QuicTraceEvent(
        WorkerCleanup,
        "[wrkr][%p] Cleaning up",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_WorkerCleanup
#define _clog_3_ARGS_TRACE_WorkerCleanup(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_WORKER_C, WorkerCleanup , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerDestroyed
// [wrkr][%p] Destroyed
// QuicTraceEvent(
        WorkerDestroyed,
        "[wrkr][%p] Destroyed",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_WorkerDestroyed
#define _clog_3_ARGS_TRACE_WorkerDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_WORKER_C, WorkerDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnAssignWorker
// [conn][%p] Assigned worker: %p
// QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Worker);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Worker = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnAssignWorker
#define _clog_4_ARGS_TRACE_ConnAssignWorker(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_WORKER_C, ConnAssignWorker , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnScheduleState
// [conn][%p] Scheduling: %u
// QuicTraceEvent(
            ConnScheduleState,
            "[conn][%p] Scheduling: %u",
            Connection,
            QUIC_SCHEDULE_QUEUED);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = QUIC_SCHEDULE_QUEUED = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnScheduleState
#define _clog_4_ARGS_TRACE_ConnScheduleState(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_WORKER_C, ConnScheduleState , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerQueueDelayUpdated
// [wrkr][%p] QueueDelay = %u
// QuicTraceEvent(
        WorkerQueueDelayUpdated,
        "[wrkr][%p] QueueDelay = %u",
        Worker,
        Worker->AverageQueueDelay);
// arg2 = arg2 = Worker = arg2
// arg3 = arg3 = Worker->AverageQueueDelay = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_WorkerQueueDelayUpdated
#define _clog_4_ARGS_TRACE_WorkerQueueDelayUpdated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_WORKER_C, WorkerQueueDelayUpdated , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerActivityStateUpdated
// [wrkr][%p] IsActive = %hhu, Arg = %u
// QuicTraceEvent(
            WorkerActivityStateUpdated,
            "[wrkr][%p] IsActive = %hhu, Arg = %u",
            Worker,
            Worker->IsActive,
            1);
// arg2 = arg2 = Worker = arg2
// arg3 = arg3 = Worker->IsActive = arg3
// arg4 = arg4 = 1 = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_WorkerActivityStateUpdated
#define _clog_5_ARGS_TRACE_WorkerActivityStateUpdated(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_WORKER_C, WorkerActivityStateUpdated , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerStart
// [wrkr][%p] Start
// QuicTraceEvent(
        WorkerStart,
        "[wrkr][%p] Start",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_WorkerStart
#define _clog_3_ARGS_TRACE_WorkerStart(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_WORKER_C, WorkerStart , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WorkerStop
// [wrkr][%p] Stop
// QuicTraceEvent(
        WorkerStop,
        "[wrkr][%p] Stop",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_WorkerStop
#define _clog_3_ARGS_TRACE_WorkerStop(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_WORKER_C, WorkerStop , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_WORKER_POOL",
            sizeof(QUIC_WORKER_POOL) + WorkerCount * sizeof(QUIC_WORKER));
// arg2 = arg2 = "QUIC_WORKER_POOL" = arg2
// arg3 = arg3 = sizeof(QUIC_WORKER_POOL) + WorkerCount * sizeof(QUIC_WORKER) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_WORKER_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_worker.c.clog.h.c"
#endif
