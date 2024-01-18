


/*----------------------------------------------------------
// Decoder Ring for WindowsUserLoaded
// [ dll] Loaded
// QuicTraceLogInfo(
        WindowsUserLoaded,
        "[ dll] Loaded");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserLoaded,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsUserUnloaded
// [ dll] Unloaded
// QuicTraceLogInfo(
        WindowsUserUnloaded,
        "[ dll] Unloaded");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserUnloaded,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsUserProcessorStateV3
// [ dll] Processors: (%u active, %u max), Groups: (%hu active, %hu max)
// QuicTraceLogInfo(
        WindowsUserProcessorStateV3,
        "[ dll] Processors: (%u active, %u max), Groups: (%hu active, %hu max)",
        ActiveProcessorCount,
        MaxProcessorCount,
        Info->Group.ActiveGroupCount,
        Info->Group.MaximumGroupCount);
// arg2 = arg2 = ActiveProcessorCount = arg2
// arg3 = arg3 = MaxProcessorCount = arg3
// arg4 = arg4 = Info->Group.ActiveGroupCount = arg4
// arg5 = arg5 = Info->Group.MaximumGroupCount = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserProcessorStateV3,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3,
        unsigned short, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ProcessorInfoV2
// [ dll] Proc[%u] Group[%hu] Index[%u] Active=%hhu
// QuicTraceLogInfo(
                    ProcessorInfoV2,
                    "[ dll] Proc[%u] Group[%hu] Index[%u] Active=%hhu",
                    Proc,
                    (uint16_t)Group,
                    CxPlatProcessorInfo[Proc].Index,
                    (uint8_t)!!(CxPlatProcessorGroupInfo[Group].Mask & (1ULL << CxPlatProcessorInfo[Proc].Index)));
// arg2 = arg2 = Proc = arg2
// arg3 = arg3 = (uint16_t)Group = arg3
// arg4 = arg4 = CxPlatProcessorInfo[Proc].Index = arg4
// arg5 = arg5 = (uint8_t)!!(CxPlatProcessorGroupInfo[Group].Mask & (1ULL << CxPlatProcessorInfo[Proc].Index)) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, ProcessorInfoV2,
    TP_ARGS(
        unsigned int, arg2,
        unsigned short, arg3,
        unsigned int, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsUserInitialized2
// [ dll] Initialized (AvailMem = %llu bytes, TimerResolution = [%u, %u])
// QuicTraceLogInfo(
        WindowsUserInitialized2,
        "[ dll] Initialized (AvailMem = %llu bytes, TimerResolution = [%u, %u])",
        CxPlatTotalMemory,
        CxPlatTimerCapabilities.wPeriodMin,
        CxPlatTimerCapabilities.wPeriodMax);
// arg2 = arg2 = CxPlatTotalMemory = arg2
// arg3 = arg3 = CxPlatTimerCapabilities.wPeriodMin = arg3
// arg4 = arg4 = CxPlatTimerCapabilities.wPeriodMax = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserInitialized2,
    TP_ARGS(
        unsigned long long, arg2,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsUserInitialized
// [ dll] Initialized (AvailMem = %llu bytes)
// QuicTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        CxPlatTotalMemory);
// arg2 = arg2 = CxPlatTotalMemory = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserInitialized,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsUserUninitialized
// [ dll] Uninitialized
// QuicTraceLogInfo(
        WindowsUserUninitialized,
        "[ dll] Uninitialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserUninitialized,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group count");
// arg2 = arg2 = "Failed to determine processor group count" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, LibraryError,
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
            ActiveProcessorCount,
            "Invalid active processor count");
// arg2 = arg2 = ActiveProcessorCount = arg2
// arg3 = arg3 = "Invalid active processor count" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, LibraryErrorStatus,
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
            "CxPlatProcessorInfo",
            ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO));
// arg2 = arg2 = "CxPlatProcessorInfo" = arg2
// arg3 = arg3 = ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, AllocFailure,
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
// arg2 = arg2 = (uint32_t)Line = arg2
// arg3 = arg3 = File = arg3
// arg4 = arg4 = Expr = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, LibraryAssert,
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
