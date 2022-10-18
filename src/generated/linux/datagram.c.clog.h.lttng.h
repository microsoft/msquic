


/*----------------------------------------------------------
// Decoder Ring for DatagramSendStateChanged
// [conn][%p] Indicating DATAGRAM_SEND_STATE_CHANGED to %u
// QuicTraceLogConnVerbose(
        DatagramSendStateChanged,
        Connection,
        "Indicating DATAGRAM_SEND_STATE_CHANGED to %u",
        (uint32_t)State);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint32_t)State = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, DatagramSendStateChanged,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatagramSendShutdown
// [conn][%p] Datagram send shutdown
// QuicTraceLogConnVerbose(
        DatagramSendShutdown,
        Connection,
        "Datagram send shutdown");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, DatagramSendShutdown,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateDatagramStateChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED [SendEnabled=%hhu] [MaxSendLength=%hu]
// QuicTraceLogConnVerbose(
            IndicateDatagramStateChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED [SendEnabled=%hhu] [MaxSendLength=%hu]",
            Event.DATAGRAM_STATE_CHANGED.SendEnabled,
            Event.DATAGRAM_STATE_CHANGED.MaxSendLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.DATAGRAM_STATE_CHANGED.SendEnabled = arg3
// arg4 = arg4 = Event.DATAGRAM_STATE_CHANGED.MaxSendLength = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, IndicateDatagramStateChanged,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatagramSendQueued
// [conn][%p] Datagram [%p] queued with %llu bytes (flags 0x%x)
// QuicTraceLogConnVerbose(
            DatagramSendQueued,
            Connection,
            "Datagram [%p] queued with %llu bytes (flags 0x%x)",
            SendRequest,
            SendRequest->TotalLength,
            SendRequest->Flags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = SendRequest = arg3
// arg4 = arg4 = SendRequest->TotalLength = arg4
// arg5 = arg5 = SendRequest->Flags = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, DatagramSendQueued,
    TP_ARGS(
        const void *, arg1,
        const void *, arg3,
        unsigned long long, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateDatagramReceived
// [conn][%p] Indicating DATAGRAM_RECEIVED [len=%hu]
// QuicTraceLogConnVerbose(
        IndicateDatagramReceived,
        Connection,
        "Indicating DATAGRAM_RECEIVED [len=%hu]",
        (uint16_t)Frame.Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Frame.Length = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, IndicateDatagramReceived,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Datagram send while disabled");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Datagram send while disabled" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DATAGRAM_SEND operation",
                0);
// arg2 = arg2 = "DATAGRAM_SEND operation" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAGRAM_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
