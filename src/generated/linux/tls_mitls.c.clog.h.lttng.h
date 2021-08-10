


/*----------------------------------------------------------
// Decoder Ring for miTlsInitialize
// [ tls] Initializing miTLS library
// QuicTraceLogVerbose(
        miTlsInitialize,
        "[ tls] Initializing miTLS library");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsInitialize,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsUninitialize
// [ tls] Cleaning up miTLS library
// QuicTraceLogVerbose(
        miTlsUninitialize,
        "[ tls] Cleaning up miTLS library");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsUninitialize,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsLogSecret
// [ tls] %s[%u]: %s
// QuicTraceLogVerbose(
        miTlsLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
// arg2 = arg2 = Prefix
// arg3 = arg3 = Length
// arg4 = arg4 = SecretStr
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsLogSecret,
    TP_ARGS(
        const char *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProcessFailed
// [conn][%p] FFI_mitls_quic_process failed, tls_error %hu, %s
// QuicTraceLogConnError(
                miTlsFfiProcessFailed,
                TlsContext->Connection,
                "FFI_mitls_quic_process failed, tls_error %hu, %s",
                Context.tls_error,
                Context.tls_error_desc);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Context.tls_error
// arg4 = arg4 = Context.tls_error_desc
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsFfiProcessFailed,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiGetHelloSummaryFailed
// [conn][%p] FFI_mitls_get_hello_summary failed, cookie_len: %zu, ticket_len: %zu
// QuicTraceLogConnError(
                            miTlsFfiGetHelloSummaryFailed,
                            TlsContext->Connection,
                            "FFI_mitls_get_hello_summary failed, cookie_len: %zu, ticket_len: %zu",
                            CookieLen,
                            TicketLen);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = CookieLen
// arg4 = arg4 = TicketLen
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsFfiGetHelloSummaryFailed,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsCertValidationDisabled
// [conn][%p] Certificate validation disabled!
// QuicTraceLogConnWarning(
            miTlsCertValidationDisabled,
            TlsContext->Connection,
            "Certificate validation disabled!");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsCertValidationDisabled,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsCertSelected
// [conn][%p] Server certificate selected. SNI: %s; Algorithm: 0x%4.4x
// QuicTraceLogConnInfo(
        miTlsCertSelected,
        TlsContext->Connection,
        "Server certificate selected. SNI: %s; Algorithm: 0x%4.4x",
        TlsContext->SNI,
        *SelectedSignature);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsContext->SNI
// arg4 = arg4 = *SelectedSignature
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsCertSelected,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsUsing0Rtt
// [conn][%p] Using 0-RTT ticket.
// QuicTraceLogConnVerbose(
                    miTlsUsing0Rtt,
                    TlsContext->Connection,
                    "Using 0-RTT ticket.");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsUsing0Rtt,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsProcess
// [conn][%p] Processing %u bytes
// QuicTraceLogConnVerbose(
                miTlsProcess,
                TlsContext->Connection,
                "Processing %u bytes",
                *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsProcess,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsSend0RttTicket
// [conn][%p] Sending 0-RTT ticket
// QuicTraceLogConnVerbose(
            miTlsSend0RttTicket,
            TlsContext->Connection,
            "Sending 0-RTT ticket");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsSend0RttTicket,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProces
// [conn][%p] FFI_mitls_quic_process processing %u input bytes
// QuicTraceLogConnVerbose(
            miTlsFfiProces,
            TlsContext->Connection,
            "FFI_mitls_quic_process processing %u input bytes",
            (uint32_t)Context.input_len);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Context.input_len
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsFfiProces,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProcessResult
// [conn][%p] FFI_mitls_quic_process read %u bytes and has %u bytes ready to send
// QuicTraceLogConnVerbose(
            miTlsFfiProcessResult,
            TlsContext->Connection,
            "FFI_mitls_quic_process read %u bytes and has %u bytes ready to send",
            (uint32_t)Context.consumed_bytes,
            (uint32_t)Context.output_len);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Context.consumed_bytes
// arg4 = arg4 = (uint32_t)Context.output_len
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsFfiProcessResult,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnVerbose(
                miTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsHandshakeComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataRejected
// [conn][%p] Early data rejected
// QuicTraceLogConnVerbose(
                miTlsEarlyDataRejected,
                TlsContext->Connection,
                "Early data rejected");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsEarlyDataRejected,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataAccepted
// [conn][%p] Early data accepted
// QuicTraceLogConnVerbose(
                        miTlsEarlyDataAccepted,
                        TlsContext->Connection,
                        "Early data accepted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsEarlyDataAccepted,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataNotAttempted
// [conn][%p] Early data not attempted
// QuicTraceLogConnVerbose(
                            miTlsEarlyDataNotAttempted,
                            TlsContext->Connection,
                            "Early data not attempted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsEarlyDataNotAttempted,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataAttempted
// [conn][%p] Early data attempted
// QuicTraceLogConnVerbose(
                        miTlsEarlyDataAttempted,
                        TlsContext->Connection,
                        "Early data attempted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsEarlyDataAttempted,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsKeySchedule
// [conn][%p] Key schedule = %hu
// QuicTraceLogConnVerbose(
                miTlsKeySchedule,
                TlsContext->Connection,
                "Key schedule = %hu",
                TlsContext->TlsKeySchedule);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsContext->TlsKeySchedule
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsKeySchedule,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTls0RttReadKeyExported
// [conn][%p] 0-RTT read key exported
// QuicTraceLogConnVerbose(
                        miTls0RttReadKeyExported,
                        TlsContext->Connection,
                        "0-RTT read key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTls0RttReadKeyExported,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeReadKeyExported
// [conn][%p] Handshake read key exported
// QuicTraceLogConnVerbose(
                        miTlsHandshakeReadKeyExported,
                        TlsContext->Connection,
                        "Handshake read key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsHandshakeReadKeyExported,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTls1RttReadKeyExported
// [conn][%p] 1-RTT read key exported
// QuicTraceLogConnVerbose(
                        miTls1RttReadKeyExported,
                        TlsContext->Connection,
                        "1-RTT read key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTls1RttReadKeyExported,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTls0RttWriteKeyExported
// [conn][%p] 0-RTT write key exported
// QuicTraceLogConnVerbose(
                        miTls0RttWriteKeyExported,
                        TlsContext->Connection,
                        "0-RTT write key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTls0RttWriteKeyExported,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeWriteKeyExported
// [conn][%p] Handshake write key exported
// QuicTraceLogConnVerbose(
                        miTlsHandshakeWriteKeyExported,
                        TlsContext->Connection,
                        "Handshake write key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsHandshakeWriteKeyExported,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTls1RttWriteKeyExported
// [conn][%p] 1-RTT write key exported
// QuicTraceLogConnVerbose(
                        miTls1RttWriteKeyExported,
                        TlsContext->Connection,
                        "1-RTT write key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTls1RttWriteKeyExported,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeWriteOffsetSet
// [conn][%p] Handshake write offset = %u
// QuicTraceLogConnVerbose(
                    miTlsHandshakeWriteOffsetSet,
                    TlsContext->Connection,
                    "Handshake write offset = %u",
                    State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffsetHandshake
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsHandshakeWriteOffsetSet,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTls1RttWriteOffsetSet
// [conn][%p] 1-RTT write offset = %u
// QuicTraceLogConnVerbose(
                    miTls1RttWriteOffsetSet,
                    TlsContext->Connection,
                    "1-RTT write offset = %u",
                    State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffset1Rtt
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTls1RttWriteOffsetSet,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProcesComplete
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnVerbose(
        miTlsFfiProcesComplete,
        TlsContext->Connection,
        "Consumed %u bytes",
        BufferOffset);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = BufferOffset
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsFfiProcesComplete,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertSelect
// [conn][%p] OnCertSelect
// QuicTraceLogConnVerbose(
        miTlsOnCertSelect,
        TlsContext->Connection,
        "OnCertSelect");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsOnCertSelect,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsOnNegotiate
// [conn][%p] OnNegotiate
// QuicTraceLogConnVerbose(
        miTlsOnNegotiate,
        TlsContext->Connection,
        "OnNegotiate");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsOnNegotiate,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsProcessServerAlpn
// [conn][%p] Processing server ALPN (Length=%u)
// QuicTraceLogConnVerbose(
            miTlsProcessServerAlpn,
            TlsContext->Connection,
            "Processing server ALPN (Length=%u)",
            (uint32_t)ExtensionDataLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)ExtensionDataLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsProcessServerAlpn,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertFormat
// [conn][%p] OnCertFormat
// QuicTraceLogConnVerbose(
        miTlsOnCertFormat,
        TlsContext->Connection,
        "OnCertFormat");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsOnCertFormat,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertSign
// [conn][%p] OnCertSign
// QuicTraceLogConnVerbose(
        miTlsOnCertSign,
        TlsContext->Connection,
        "OnCertSign");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsOnCertSign,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertVerify
// [conn][%p] OnCertVerify
// QuicTraceLogConnVerbose(
        miTlsOnCertVerify,
        TlsContext->Connection,
        "OnCertVerify");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsOnCertVerify,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for miTlsRecvNewSessionTicket
// [conn][%p] Received new ticket. ticket_len:%u session_len:%u for %s
// QuicTraceLogConnVerbose(
        miTlsRecvNewSessionTicket,
        TlsContext->Connection,
        "Received new ticket. ticket_len:%u session_len:%u for %s",
        (uint32_t)Ticket->ticket_len,
        (uint32_t)Ticket->session_len,
        ServerNameIndication);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Ticket->ticket_len
// arg4 = arg4 = (uint32_t)Ticket->session_len
// arg5 = arg5 = ServerNameIndication
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, miTlsRecvNewSessionTicket,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        const char *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_string(arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsMessage
// [ tls][%p] %s
// QuicTraceEvent(
        TlsMessage,
        "[ tls][%p] %s",
        TlsGetValue(miTlsCurrentConnectionIndex),
        Msg);
// arg2 = arg2 = TlsGetValue(miTlsCurrentConnectionIndex)
// arg3 = arg3 = Msg
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, TlsMessage,
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
            "FFI_mitls_init failed");
// arg2 = arg2 = "FFI_mitls_init failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS) + sizeof(uint16_t) + Config->AlpnBufferLength);
// arg2 = arg2 = "CXPLAT_TLS"
// arg3 = arg3 = sizeof(CXPLAT_TLS) + sizeof(uint16_t) + Config->AlpnBufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, AllocFailure,
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
TRACEPOINT_EVENT(CLOG_TLS_MITLS_C, TlsError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
