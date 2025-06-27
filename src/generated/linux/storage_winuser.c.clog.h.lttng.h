


/*----------------------------------------------------------
// Decoder Ring for StorageOpenKey
// [ reg] Opening %s
// QuicTraceLogVerbose(
        StorageOpenKey,
        "[ reg] Opening %s",
        FullKeyName);
// arg2 = arg2 = FullKeyName = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STORAGE_WINUSER_C, StorageOpenKey,
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
                "RegCreateKeyExA failed");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "RegCreateKeyExA failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STORAGE_WINUSER_C, LibraryErrorStatus,
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
            "RegEnumValueA ValueName",
            AllocatedLength);
// arg2 = arg2 = "RegEnumValueA ValueName" = arg2
// arg3 = arg3 = AllocatedLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STORAGE_WINUSER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
