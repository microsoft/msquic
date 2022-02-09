


/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_OPEN,
        RegistrationHandle);
// arg2 = arg2 = QUIC_TRACE_API_CONNECTION_OPEN = arg2
// arg3 = arg3 = RegistrationHandle = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, ApiEnter,
    TP_ARGS(
        unsigned int, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, ApiExitStatus,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiWaitOperation
// [ api] Waiting on operation
// QuicTraceEvent(
            ApiWaitOperation,
            "[ api] Waiting on operation");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, ApiWaitOperation,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, ApiExit,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server name",
                ServerNameLength + 1);
// arg2 = arg2 = "Server name" = arg2
// arg3 = arg3 = ServerNameLength + 1 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamError
// [strm][%p] ERROR, %s.
// QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Send request total length exceeds max");
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = "Send request total length exceeds max" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, StreamError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamAppSend
// [strm][%p] App queuing send [%llu bytes, %u buffers, 0x%x flags]
// QuicTraceEvent(
        StreamAppSend,
        "[strm][%p] App queuing send [%llu bytes, %u buffers, 0x%x flags]",
        Stream,
        TotalLength,
        BufferCount,
        Flags);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = TotalLength = arg3
// arg4 = arg4 = BufferCount = arg4
// arg5 = arg5 = Flags = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, StreamAppSend,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiError
// [ api] Error %u
// QuicTraceEvent(
            ApiError,
            "[ api] Error %u",
            (uint32_t)QUIC_STATUS_INVALID_STATE);
// arg2 = arg2 = (uint32_t)QUIC_STATUS_INVALID_STATE = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, ApiError,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Send request total length exceeds max");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Send request total length exceeds max" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
