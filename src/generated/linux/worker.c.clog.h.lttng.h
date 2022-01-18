


/*----------------------------------------------------------
// Decoder Ring for IndicateIdealProcChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED
// QuicTraceLogConnVerbose(
            IndicateIdealProcChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_WORKER_C, IndicateIdealProcChanged,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AbandonOnLibShutdown
// [conn][%p] Abandoning on shutdown
// QuicTraceLogConnVerbose(
                AbandonOnLibShutdown,
                Connection,
                "Abandoning on shutdown");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_WORKER_C, AbandonOnLibShutdown,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerCreated,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer_hex(uint64_t, arg4, arg4)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WorkerCleanup
// [wrkr][%p] Cleaning up
// QuicTraceEvent(
        WorkerCleanup,
        "[wrkr][%p] Cleaning up",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerCleanup,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WorkerDestroyed
// [wrkr][%p] Destroyed
// QuicTraceEvent(
        WorkerDestroyed,
        "[wrkr][%p] Destroyed",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, ConnAssignWorker,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, ConnScheduleState,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerQueueDelayUpdated,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerActivityStateUpdated,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WorkerStart
// [wrkr][%p] Start
// QuicTraceEvent(
        WorkerStart,
        "[wrkr][%p] Start",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerStart,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WorkerStop
// [wrkr][%p] Stop
// QuicTraceEvent(
        WorkerStop,
        "[wrkr][%p] Stop",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_WORKER_C, WorkerStop,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



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
TRACEPOINT_EVENT(CLOG_WORKER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
