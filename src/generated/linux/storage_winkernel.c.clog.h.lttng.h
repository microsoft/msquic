


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "UnicodeString from UTF8",
            sizeof(UNICODE_STRING) + UnicodeLength);
// arg2 = arg2 = "UnicodeString from UTF8" = arg2
// arg3 = arg3 = sizeof(UNICODE_STRING) + UnicodeLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STORAGE_WINKERNEL_C, AllocFailure,
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
            Status,
            "RtlUTF8ToUnicodeN failed");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "RtlUTF8ToUnicodeN failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STORAGE_WINKERNEL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
