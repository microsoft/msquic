


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            cipher_name);
// arg2 = arg2 = ERR_get_error() = arg2
// arg3 = arg3 = cipher_name = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_OPENSSL_C, LibraryErrorStatus,
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
            "EVP_MAC_CTX_new",
            0);
// arg2 = arg2 = "EVP_MAC_CTX_new" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_OPENSSL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_CTX_set_params failed");
// arg2 = arg2 = "EVP_MAC_CTX_set_params failed" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_OPENSSL_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
