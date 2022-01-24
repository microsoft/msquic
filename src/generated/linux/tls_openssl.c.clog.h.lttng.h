


/*----------------------------------------------------------
// Decoder Ring for OpenSslAlert
// [conn][%p] Send alert = %u (Level = %u)
// QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = Alert = arg3
// arg4 = arg4 = (uint32_t)Level = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslAlert,
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
// Decoder Ring for OpenSslQuicDataErrorStr
// [conn][%p] SSL_provide_quic_data failed: %s
// QuicTraceLogConnError(
                OpenSslQuicDataErrorStr,
                TlsContext->Connection,
                "SSL_provide_quic_data failed: %s",
                ERR_error_string(ERR_get_error(), buf));
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = ERR_error_string(ERR_get_error(), buf) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslQuicDataErrorStr,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeErrorStr
// [conn][%p] TLS handshake error: %s, file:%s:%d
// QuicTraceLogConnError(
                    OpenSslHandshakeErrorStr,
                    TlsContext->Connection,
                    "TLS handshake error: %s, file:%s:%d",
                    buf,
                    (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file),
                    line);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = buf = arg3
// arg4 = arg4 = (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file) = arg4
// arg5 = arg5 = line = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslHandshakeErrorStr,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3,
        const char *, arg4,
        int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
        ctf_string(arg4, arg4)
        ctf_integer(int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeError
// [conn][%p] TLS handshake error: %d
// QuicTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = Err = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslHandshakeError,
    TP_ARGS(
        const void *, arg1,
        int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslAlpnNegotiationFailure
// [conn][%p] Failed to negotiate ALPN
// QuicTraceLogConnError(
                    OpenSslAlpnNegotiationFailure,
                    TlsContext->Connection,
                    "Failed to negotiate ALPN");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslAlpnNegotiationFailure,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslInvalidAlpnLength
// [conn][%p] Invalid negotiated ALPN length
// QuicTraceLogConnError(
                    OpenSslInvalidAlpnLength,
                    TlsContext->Connection,
                    "Invalid negotiated ALPN length");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslInvalidAlpnLength,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslNoMatchingAlpn
// [conn][%p] Failed to find a matching ALPN
// QuicTraceLogConnError(
                    OpenSslNoMatchingAlpn,
                    TlsContext->Connection,
                    "Failed to find a matching ALPN");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslNoMatchingAlpn,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslMissingTransportParameters
// [conn][%p] No transport parameters received
// QuicTraceLogConnError(
                    OpenSslMissingTransportParameters,
                    TlsContext->Connection,
                    "No transport parameters received");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslMissingTransportParameters,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeDataStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                TlsState->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = TlsState->BufferOffsetHandshake = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslHandshakeDataStart,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSsl1RttDataStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                TlsState->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = TlsState->BufferOffset1Rtt = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSsl1RttDataStart,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslOnRecvTicket
// [conn][%p] Received session ticket, %u bytes
// QuicTraceLogConnInfo(
                    OpenSslOnRecvTicket,
                    TlsContext->Connection,
                    "Received session ticket, %u bytes",
                    (uint32_t)Length);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)Length = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslOnRecvTicket,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslOnSetTicket
// [conn][%p] Setting session ticket, %u bytes
// QuicTraceLogConnInfo(
                OpenSslOnSetTicket,
                TlsContext->Connection,
                "Setting session ticket, %u bytes",
                Config->ResumptionTicketLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = Config->ResumptionTicketLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslOnSetTicket,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeComplete
// [conn][%p] TLS Handshake complete
// QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "TLS Handshake complete");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslHandshakeComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeResumed
// [conn][%p] TLS Handshake resumed
// QuicTraceLogConnInfo(
                OpenSslHandshakeResumed,
                TlsContext->Connection,
                "TLS Handshake resumed");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslHandshakeResumed,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslNewEncryptionSecrets
// [conn][%p] New encryption secrets (Level = %u)
// QuicTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)Level = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslNewEncryptionSecrets,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslAddHandshakeData
// [conn][%p] Sending %llu handshake bytes (Level = %u)
// QuicTraceLogConnVerbose(
        OpenSslAddHandshakeData,
        TlsContext->Connection,
        "Sending %llu handshake bytes (Level = %u)",
        (uint64_t)Length,
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint64_t)Length = arg3
// arg4 = arg4 = (uint32_t)Level = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslAddHandshakeData,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslTickedDecrypted
// [conn][%p] Session ticket decrypted, status %u
// QuicTraceLogConnVerbose(
        OpenSslTickedDecrypted,
        TlsContext->Connection,
        "Session ticket decrypted, status %u",
        (uint32_t)status);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslTickedDecrypted,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslRecvTicketData
// [conn][%p] Received ticket data, %u bytes
// QuicTraceLogConnVerbose(
            OpenSslRecvTicketData,
            TlsContext->Connection,
            "Received ticket data, %u bytes",
            (uint32_t)Length);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)Length = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslRecvTicketData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslContextCreated,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslContextCleaningUp,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslSendTicketData
// [conn][%p] Sending ticket data, %u bytes
// QuicTraceLogConnVerbose(
            OpenSslSendTicketData,
            TlsContext->Connection,
            "Sending ticket data, %u bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslSendTicketData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslProcessData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
            OpenSslProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslProcessData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "No certificate passed");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = "No certificate passed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, TlsError,
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
                    "i2d_X509 failed");
// arg2 = arg2 = "i2d_X509 failed" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, LibraryError,
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
                "New crypto buffer",
                NewBufferAllocLength);
// arg2 = arg2 = "New crypto buffer" = arg2
// arg3 = arg3 = NewBufferAllocLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "PEM_write_bio_SSL_SESSION failed");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = ERR_get_error() = arg3
// arg4 = arg4 = "PEM_write_bio_SSL_SESSION failed" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, TlsErrorStatus,
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
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CredConfig->AllowedCipherSuites,
            "No valid cipher suites presented");
// arg2 = arg2 = CredConfig->AllowedCipherSuites = arg2
// arg3 = arg3 = "No valid cipher suites presented" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
