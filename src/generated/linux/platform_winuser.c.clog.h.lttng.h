


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
// Decoder Ring for WindowsUserProcessorState
// [ dll] Processors:%u, Groups:%u, NUMA Nodes:%u
// QuicTraceLogInfo(
        WindowsUserProcessorState,
        "[ dll] Processors:%u, Groups:%u, NUMA Nodes:%u",
        ActiveProcessorCount, ProcessorGroupCount, NumaNodeCount);
// arg2 = arg2 = ActiveProcessorCount
// arg3 = arg3 = ProcessorGroupCount
// arg4 = arg4 = NumaNodeCount
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, WindowsUserProcessorState,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ProcessorInfo
// [ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]
// QuicTraceLogInfo(
                        ProcessorInfo,
                        "[ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]",
                        Index,
                        QuicProcessorInfo[Index].Group,
                        QuicProcessorInfo[Index].Index,
                        QuicProcessorInfo[Index].NumaNode);
// arg2 = arg2 = Index
// arg3 = arg3 = QuicProcessorInfo[Index].Group
// arg4 = arg4 = QuicProcessorInfo[Index].Index
// arg5 = arg5 = QuicProcessorInfo[Index].NumaNode
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINUSER_C, ProcessorInfo,
    TP_ARGS(
        unsigned int, arg2,
        unsigned short, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsUserInitialized
// [ dll] Initialized (AvailMem = %llu bytes)
// QuicTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        QuicTotalMemory);
// arg2 = arg2 = QuicTotalMemory
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
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QuicProcessorInfo",
            ActiveProcessorCount * sizeof(QUIC_PROCESSOR_INFO));
// arg2 = arg2 = "QuicProcessorInfo"
// arg3 = arg3 = ActiveProcessorCount * sizeof(QUIC_PROCESSOR_INFO)
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
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX size");
// arg2 = arg2 = "Failed to determine PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX size"
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
            GetLastError(),
            "GetLogicalProcessorInformationEx failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "GetLogicalProcessorInformationEx failed"
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
