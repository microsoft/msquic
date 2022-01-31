


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
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, TimerWheelResize,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TimerWheelNextExpirationNull
// [time][%p] Next Expiration = {NULL}.
// QuicTraceLogVerbose(
            TimerWheelNextExpirationNull,
            "[time][%p] Next Expiration = {NULL}.",
            TimerWheel);
// arg2 = arg2 = TimerWheel = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, TimerWheelNextExpirationNull,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



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
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, TimerWheelNextExpiration,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer_hex(uint64_t, arg4, arg4)
    )
)



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
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, TimerWheelRemoveConnection,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, TimerWheelUpdateConnection,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StillInTimerWheel
// [conn][%p] Still in timer wheel! Connection was likely leaked!
// QuicTraceLogConnWarning(
                    StillInTimerWheel,
                    Connection,
                    "Still in timer wheel! Connection was likely leaked!");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, StillInTimerWheel,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



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
TRACEPOINT_EVENT(CLOG_TIMER_WHEEL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
