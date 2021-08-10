


/*----------------------------------------------------------
// Decoder Ring for OpenSslLogSecret
// [ tls] %s[%u]: %s
// QuicTraceLogVerbose(
        OpenSslLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
// arg2 = arg2 = Prefix
// arg3 = arg3 = Length
// arg4 = arg4 = SecretStr
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslLogSecret,
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
// Decoder Ring for OpenSslAlert
// [conn][%p] Send alert = %u (Level = %u)
// QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Alert
// arg4 = arg4 = Level
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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = ERR_error_string(ERR_get_error(), buf)
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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = buf
// arg4 = arg4 = (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file)
// arg5 = arg5 = line
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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Err
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
// arg1 = arg1 = TlsContext->Connection
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
// arg1 = arg1 = TlsContext->Connection
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
// arg1 = arg1 = TlsContext->Connection
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
// arg1 = arg1 = TlsContext->Connection
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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsState->BufferOffsetHandshake
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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsState->BufferOffset1Rtt
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
// Decoder Ring for OpenSslHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslHandshakeComplete,
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
        Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Level
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
        Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint64_t)Length
// arg4 = arg4 = Level
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
// Decoder Ring for OpenSslContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection
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
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSslContextCleaningUp,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSsslIgnoringTicket
// [conn][%p] Ignoring %u ticket bytes
// QuicTraceLogConnVerbose(
            OpenSsslIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, OpenSsslIgnoringTicket,
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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
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
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "OPENSSL_init_ssl failed");
// arg2 = arg2 = "OPENSSL_init_ssl failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_OPENSSL_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Internal certificate validation failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Internal certificate validation failed"
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
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto buffer",
                NewBufferAllocLength);
// arg2 = arg2 = "New crypto buffer"
// arg3 = arg3 = NewBufferAllocLength
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
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_new failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_new failed"
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
