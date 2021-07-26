


/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "i2d_X509 failed");
// arg2 = arg2 = "i2d_X509 failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_OPENSSL_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertGetCertificateChain failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertGetCertificateChain failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_OPENSSL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSA Key",
            KeyLength);
// arg2 = arg2 = "RSA Key"
// arg3 = arg3 = KeyLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_OPENSSL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
