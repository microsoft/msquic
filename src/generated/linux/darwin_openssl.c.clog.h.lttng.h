


/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "i2d_X509 failed");
// arg2 = arg2 = "i2d_X509 failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DARWIN_OPENSSL_C, LibraryError,
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
            Status,
            "SecTrustCreateWithCertificates failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "SecTrustCreateWithCertificates failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DARWIN_OPENSSL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
