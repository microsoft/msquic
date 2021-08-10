


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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerIndicateNewConnection,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ApiEnter,
    TP_ARGS(
        unsigned int, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerCreated,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ApiExitStatus,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ListenerDestroyed
// [list][%p] Destroyed
// QuicTraceEvent(
        ListenerDestroyed,
        "[list][%p] Destroyed",
        Listener);
// arg2 = arg2 = Listener
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LISTENER_C, ApiExit,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerErrorStatus,
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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerStarted,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ListenerStopped
// [list][%p] Stopped
// QuicTraceEvent(
                ListenerStopped,
                "[list][%p] Stopped",
                Listener);
// arg2 = arg2 = Listener
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerStopped,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerRundown,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
