


/*----------------------------------------------------------
// Decoder Ring for RegistrationVerifierEnabled
// [ reg][%p] Verifing enabled!
// QuicTraceLogInfo(
            RegistrationVerifierEnabled,
            "[ reg][%p] Verifing enabled!",
            Registration);
// arg2 = arg2 = Registration = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, RegistrationVerifierEnabled,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_REGISTRATION_OPEN,
        NULL);
// arg2 = arg2 = QUIC_TRACE_API_REGISTRATION_OPEN = arg2
// arg3 = arg3 = NULL = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, ApiEnter,
    TP_ARGS(
        unsigned int, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Status,
                    "CxPlatDataPathInitialize");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatDataPathInitialize" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DataPathInitialized
// [data] Initialized, DatapathFeatures=%u
// QuicTraceEvent(
                DataPathInitialized,
                "[data] Initialized, DatapathFeatures=%u",
                CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));
// arg2 = arg2 = CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath) = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, DataPathInitialized,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "registration",
            sizeof(QUIC_REGISTRATION) + AppNameLength + 1);
// arg2 = arg2 = "registration" = arg2
// arg3 = arg3 = sizeof(QUIC_REGISTRATION) + AppNameLength + 1 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RegistrationCreated
// [ reg][%p] Created, AppName=%s
// QuicTraceEvent(
        RegistrationCreated,
        "[ reg][%p] Created, AppName=%s",
        Registration,
        Registration->AppName);
// arg2 = arg2 = Registration = arg2
// arg3 = arg3 = Registration->AppName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, RegistrationCreated,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, ApiExitStatus,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RegistrationCleanup
// [ reg][%p] Cleaning up
// QuicTraceEvent(
            RegistrationCleanup,
            "[ reg][%p] Cleaning up",
            Registration);
// arg2 = arg2 = Registration = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, RegistrationCleanup,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
            ApiExit,
            "[ api] Exit");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, ApiExit,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for RegistrationRundown
// [ reg][%p] Rundown, AppName=%s
// QuicTraceEvent(
        RegistrationRundown,
        "[ reg][%p] Rundown, AppName=%s",
        Registration,
        Registration->AppName);
// arg2 = arg2 = Registration = arg2
// arg3 = arg3 = Registration->AppName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_REGISTRATION_C, RegistrationRundown,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
