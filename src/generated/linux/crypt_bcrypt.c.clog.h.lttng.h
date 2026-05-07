


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA256 algorithm");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "Open HMAC_SHA256 algorithm" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_BCRYPT_C, LibraryErrorStatus,
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
            "CXPLAT_HP_KEY",
            AllocLength);
// arg2 = arg2 = "CXPLAT_HP_KEY" = arg2
// arg3 = arg3 = AllocLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_BCRYPT_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
