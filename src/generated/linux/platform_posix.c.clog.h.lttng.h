


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "pthread_attr_init failed");
// arg2 = arg2 = errno
// arg3 = arg3 = "pthread_attr_init failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_POSIX_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "pthread_attr_setaffinity_np failed");
// arg2 = arg2 = "pthread_attr_setaffinity_np failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_POSIX_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Custom thread context",
            sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT));
// arg2 = arg2 = "Custom thread context"
// arg3 = arg3 = sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_POSIX_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryAssert
// [ lib] ASSERT, %u:%s - %s.
// QuicTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
// arg2 = arg2 = (uint32_t)Line
// arg3 = arg3 = File
// arg4 = arg4 = Expr
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_POSIX_C, LibraryAssert,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
