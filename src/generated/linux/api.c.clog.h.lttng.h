


/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_OPEN,
        RegistrationHandle);
// arg2 = arg2 = QUIC_TRACE_API_CONNECTION_OPEN
// arg3 = arg3 = RegistrationHandle
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
// arg2 = arg2 = Status
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
// arg2 = arg2 = "Server name"
// arg3 = arg3 = ServerNameLength + 1
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
// arg2 = arg2 = Stream
// arg3 = arg3 = "Send request total length exceeds max"
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
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Param level does not match param value");
// arg2 = arg2 = "Param level does not match param value"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_API_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
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
// arg2 = arg2 = Connection
// arg3 = arg3 = "Send request total length exceeds max"
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

