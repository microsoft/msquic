


/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CFDataCreateWithBytesNoCopy failed");
// arg2 = arg2 = "CFDataCreateWithBytesNoCopy failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERTIFICATES_DARWIN_C, LibraryError,
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
TRACEPOINT_EVENT(CLOG_CERTIFICATES_DARWIN_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
