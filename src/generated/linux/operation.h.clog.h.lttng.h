


/*----------------------------------------------------------
// Decoder Ring for ConnExecApiOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecApiOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->API_CALL.Context->Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Oper->API_CALL.Context->Type = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_OPERATION_H, ConnExecApiOper,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnExecTimerOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->TIMER_EXPIRED.Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Oper->TIMER_EXPIRED.Type = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_OPERATION_H, ConnExecTimerOper,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnExecOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Oper->Type = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_OPERATION_H, ConnExecOper,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)
