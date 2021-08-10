


/*----------------------------------------------------------
// Decoder Ring for StubTlsCertValidationDisabled
// [conn][%p] Certificate validation disabled!
// QuicTraceLogConnWarning(
                    StubTlsCertValidationDisabled,
                    TlsContext->Connection,
                    "Certificate validation disabled!");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsCertValidationDisabled,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
                StubTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsHandshakeComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsProducedData
// [conn][%p] Produced %hu bytes
// QuicTraceLogConnInfo(
                StubTlsProducedData,
                TlsContext->Connection,
                "Produced %hu bytes",
                (State->BufferLength - PrevBufferLength));
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (State->BufferLength - PrevBufferLength)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsProducedData,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsConsumedData
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnInfo(
            StubTlsConsumedData,
            TlsContext->Connection,
            "Consumed %u bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsConsumedData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        StubTlsContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsContextCreated,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsUsing0Rtt
// [conn][%p] Using 0-RTT ticket.
// QuicTraceLogConnVerbose(
            StubTlsUsing0Rtt,
            TlsContext->Connection,
            "Using 0-RTT ticket.");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsUsing0Rtt,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            StubTlsContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsContextCleaningUp,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsRecvNewSessionTicket
// [conn][%p] Received new ticket. ticket_len:%u for %s
// QuicTraceLogConnVerbose(
            StubTlsRecvNewSessionTicket,
            TlsContext->Connection,
            "Received new ticket. ticket_len:%u for %s",
            ServerMessageLength,
            TlsContext->SNI);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = ServerMessageLength
// arg4 = arg4 = TlsContext->SNI
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsRecvNewSessionTicket,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StubTlsProcessData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
            StubTlsProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, StubTlsProcessData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS",
            sizeof(QUIC_TLS));
// arg2 = arg2 = "QUIC_TLS"
// arg3 = arg3 = sizeof(QUIC_TLS)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "SNI Too Long");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SNI Too Long"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, TlsError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ClientMessage->Type,
                "Invalid message");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ClientMessage->Type
// arg4 = arg4 = "Invalid message"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_STUB_C, TlsErrorStatus,
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
