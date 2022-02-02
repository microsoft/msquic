


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
