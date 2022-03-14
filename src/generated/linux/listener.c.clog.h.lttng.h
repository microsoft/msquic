


/*----------------------------------------------------------
// Decoder Ring for ListenerIndicateStopComplete
// [list][%p] Indicating STOP_COMPLETE
// QuicTraceLogVerbose(
            ListenerIndicateStopComplete,
            "[list][%p] Indicating STOP_COMPLETE",
            Listener);
// arg2 = arg2 = Listener = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerIndicateStopComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerCibirIdSet,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



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
TRACEPOINT_EVENT(CLOG_LISTENER_C, CibirIdSet,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
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
// arg2 = arg2 = QUIC_TRACE_API_LISTENER_OPEN = arg2
// arg3 = arg3 = RegistrationHandle = arg3
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
// arg2 = arg2 = "listener" = arg2
// arg3 = arg3 = sizeof(QUIC_LISTENER) = arg3
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
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Listener->Registration = arg3
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
// arg2 = arg2 = Status = arg2
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
// arg2 = arg2 = Listener = arg2
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
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Get binding" = arg4
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
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = "Register with binding" = arg3
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
TRACEPOINT_EVENT(CLOG_LISTENER_C, ListenerStarted,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        unsigned int, arg5_len,
        const void *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ListenerStopped
// [list][%p] Stopped
// QuicTraceEvent(
        ListenerStopped,
        "[list][%p] Stopped",
        Listener);
// arg2 = arg2 = Listener = arg2
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
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Listener->Registration = arg3
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
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Connection rejected by registration (overloaded)" = arg3
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
