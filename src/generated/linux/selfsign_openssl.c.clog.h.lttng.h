


/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_new failed");
// arg2 = arg2 = "EVP_PKEY_new failed" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_OPENSSL_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
