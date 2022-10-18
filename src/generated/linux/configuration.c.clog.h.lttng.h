


/*----------------------------------------------------------
// Decoder Ring for ConfigurationOpenStorageFailed
// [cnfg][%p] Failed to open settings, 0x%x
// QuicTraceLogWarning(
                ConfigurationOpenStorageFailed,
                "[cnfg][%p] Failed to open settings, 0x%x",
                Configuration,
                Status);
// arg2 = arg2 = Configuration = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationOpenStorageFailed,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationOpenAppStorageFailed
// [cnfg][%p] Failed to open app specific settings, 0x%x
// QuicTraceLogWarning(
                ConfigurationOpenAppStorageFailed,
                "[cnfg][%p] Failed to open app specific settings, 0x%x",
                Configuration,
                Status);
// arg2 = arg2 = Configuration = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationOpenAppStorageFailed,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationSettingsUpdated
// [cnfg][%p] Settings %p Updated
// QuicTraceLogInfo(
        ConfigurationSettingsUpdated,
        "[cnfg][%p] Settings %p Updated",
        Configuration,
        &Configuration->Settings);
// arg2 = arg2 = Configuration = arg2
// arg3 = arg3 = &Configuration->Settings = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationSettingsUpdated,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationSetSettings
// [cnfg][%p] Setting new settings
// QuicTraceLogInfo(
            ConfigurationSetSettings,
            "[cnfg][%p] Setting new settings",
            Configuration);
// arg2 = arg2 = Configuration = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationSetSettings,
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
        QUIC_TRACE_API_CONFIGURATION_OPEN,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_CONFIGURATION_OPEN = arg2
// arg3 = arg3 = Handle = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ApiEnter,
    TP_ARGS(
        unsigned int, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_CONFIGURATION" ,
            sizeof(QUIC_CONFIGURATION));
// arg2 = arg2 = "QUIC_CONFIGURATION" = arg2
// arg3 = arg3 = sizeof(QUIC_CONFIGURATION) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationCreated
// [cnfg][%p] Created, Registration=%p
// QuicTraceEvent(
        ConfigurationCreated,
        "[cnfg][%p] Created, Registration=%p",
        Configuration,
        Registration);
// arg2 = arg2 = Configuration = arg2
// arg3 = arg3 = Registration = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationCreated,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
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
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ApiExitStatus,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationCleanup
// [cnfg][%p] Cleaning up
// QuicTraceEvent(
        ConfigurationCleanup,
        "[cnfg][%p] Cleaning up",
        Configuration);
// arg2 = arg2 = Configuration = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationCleanup,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationDestroyed
// [cnfg][%p] Destroyed
// QuicTraceEvent(
        ConfigurationDestroyed,
        "[cnfg][%p] Destroyed",
        Configuration);
// arg2 = arg2 = Configuration = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationDestroyed,
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
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ApiExit,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConfigurationRundown
// [cnfg][%p] Rundown, Registration=%p
// QuicTraceEvent(
        ConfigurationRundown,
        "[cnfg][%p] Rundown, Registration=%p",
        Configuration,
        Configuration->Registration);
// arg2 = arg2 = Configuration = arg2
// arg3 = arg3 = Configuration->Registration = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONFIGURATION_C, ConfigurationRundown,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)
