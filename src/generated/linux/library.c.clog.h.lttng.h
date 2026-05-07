


/*----------------------------------------------------------
// Decoder Ring for LibraryStorageOpenFailed
// [ lib] Failed to open global settings, 0x%x
// QuicTraceLogWarning(
            LibraryStorageOpenFailed,
            "[ lib] Failed to open global settings, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryStorageOpenFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryTestDatapathHooksSet
// [ lib] Updated test datapath hooks
// QuicTraceLogWarning(
            LibraryTestDatapathHooksSet,
            "[ lib] Updated test datapath hooks");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryTestDatapathHooksSet,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySettingsUpdated
// [ lib] Settings %p Updated
// QuicTraceLogInfo(
        LibrarySettingsUpdated,
        "[ lib] Settings %p Updated",
        &MsQuicLib.Settings);
// arg2 = arg2 = &MsQuicLib.Settings = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySettingsUpdated,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryVerifierEnabledPerRegistration
// [ lib] Verifing enabled, per-registration!
// QuicTraceLogInfo(
            LibraryVerifierEnabledPerRegistration,
            "[ lib] Verifing enabled, per-registration!");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryVerifierEnabledPerRegistration,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryVerifierEnabled
// [ lib] Verifing enabled for all!
// QuicTraceLogInfo(
            LibraryVerifierEnabled,
            "[ lib] Verifing enabled for all!");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryVerifierEnabled,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryCidLengthSet
// [ lib] CID Length = %hhu
// QuicTraceLogInfo(
        LibraryCidLengthSet,
        "[ lib] CID Length = %hhu",
        MsQuicLib.CidTotalLength);
// arg2 = arg2 = MsQuicLib.CidTotalLength = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryCidLengthSet,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryRetryMemoryLimitSet
// [ lib] Updated retry memory limit = %hu
// QuicTraceLogInfo(
            LibraryRetryMemoryLimitSet,
            "[ lib] Updated retry memory limit = %hu",
            MsQuicLib.Settings.RetryMemoryLimit);
// arg2 = arg2 = MsQuicLib.Settings.RetryMemoryLimit = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryRetryMemoryLimitSet,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryLoadBalancingModeSet
// [ lib] Updated load balancing mode = %hu
// QuicTraceLogInfo(
            LibraryLoadBalancingModeSet,
            "[ lib] Updated load balancing mode = %hu",
            MsQuicLib.Settings.LoadBalancingMode);
// arg2 = arg2 = MsQuicLib.Settings.LoadBalancingMode = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryLoadBalancingModeSet,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySetSettings
// [ lib] Setting new settings
// QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySetSettings,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryExecutionConfigSet
// [ lib] Setting execution config
// QuicTraceLogInfo(
            LibraryExecutionConfigSet,
            "[ lib] Setting execution config");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryExecutionConfigSet,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryDscpRecvEnabledSet
// [ lib] Setting Dscp on recv = %u
// QuicTraceLogInfo(
            LibraryDscpRecvEnabledSet,
            "[ lib] Setting Dscp on recv = %u", MsQuicLib.EnableDscpOnRecv);
// arg2 = arg2 = MsQuicLib.EnableDscpOnRecv = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryDscpRecvEnabledSet,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryInUse
// [ lib] Now in use.
// QuicTraceLogInfo(
                LibraryInUse,
                "[ lib] Now in use.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryInUse,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryNotInUse
// [ lib] No longer in use.
// QuicTraceLogInfo(
                LibraryNotInUse,
                "[ lib] No longer in use.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryNotInUse,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryRetryKeyUpdated
// [ lib] Stateless Retry Key updated. Algorithm: %d, RotationMs: %u
// QuicTraceLogInfo(
        LibraryRetryKeyUpdated,
        "[ lib] Stateless Retry Key updated. Algorithm: %d, RotationMs: %u",
        Config->Algorithm,
        Config->RotationMs);
// arg2 = arg2 = Config->Algorithm = arg2
// arg3 = arg3 = Config->RotationMs = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryRetryKeyUpdated,
    TP_ARGS(
        int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenVersionNull
// [ api] MsQuicOpenVersion, NULL
// QuicTraceLogVerbose(
            LibraryMsQuicOpenVersionNull,
            "[ api] MsQuicOpenVersion, NULL");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryMsQuicOpenVersionNull,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenVersionEntry
// [ api] MsQuicOpenVersion
// QuicTraceLogVerbose(
        LibraryMsQuicOpenVersionEntry,
        "[ api] MsQuicOpenVersion");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryMsQuicOpenVersionEntry,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenVersionExit
// [ api] MsQuicOpenVersion, status=0x%x
// QuicTraceLogVerbose(
        LibraryMsQuicOpenVersionExit,
        "[ api] MsQuicOpenVersion, status=0x%x",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryMsQuicOpenVersionExit,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicClose
// [ api] MsQuicClose
// QuicTraceLogVerbose(
            LibraryMsQuicClose,
            "[ api] MsQuicClose");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryMsQuicClose,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryLoadBalancingModeSetAfterInUse
// [ lib] Tried to change load balancing mode after library in use!
// QuicTraceLogError(
                LibraryLoadBalancingModeSetAfterInUse,
                "[ lib] Tried to change load balancing mode after library in use!");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryLoadBalancingModeSetAfterInUse,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeySecretNull
// [ lib] Invalid retry key secret: NULL.
// QuicTraceLogError(
            LibrarySetRetryKeySecretNull,
            "[ lib] Invalid retry key secret: NULL.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySetRetryKeySecretNull,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeyAlgorithmInvalid
// [ lib] Invalid retry key algorithm: %d.
// QuicTraceLogError(
            LibrarySetRetryKeyAlgorithmInvalid,
            "[ lib] Invalid retry key algorithm: %d.",
            Config->Algorithm);
// arg2 = arg2 = Config->Algorithm = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySetRetryKeyAlgorithmInvalid,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeyRotationInvalid
// [ lib] Invalid retry key rotation ms: %u.
// QuicTraceLogError(
            LibrarySetRetryKeyRotationInvalid,
            "[ lib] Invalid retry key rotation ms: %u.",
            Config->RotationMs);
// arg2 = arg2 = Config->RotationMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySetRetryKeyRotationInvalid,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeySecretLengthInvalid
// [ lib] Invalid retry key secret length: %u. Expected %u.
// QuicTraceLogError(
            LibrarySetRetryKeySecretLengthInvalid,
            "[ lib] Invalid retry key secret length: %u. Expected %u.",
            Config->SecretLength,
            AlgSecretLen);
// arg2 = arg2 = Config->SecretLength = arg2
// arg3 = arg3 = AlgSecretLen = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySetRetryKeySecretLengthInvalid,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Library Partitions",
            PartitionsSize);
// arg2 = arg2 = "Library Partitions" = arg2
// arg3 = arg3 = PartitionsSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfCountersRundown
// [ lib] Perf counters Rundown, Counters=%!CID!
// QuicTraceEvent(
        PerfCountersRundown,
        "[ lib] Perf counters Rundown, Counters=%!CID!",
        CASTED_CLOG_BYTEARRAY16(sizeof(PerfCounterSamples), PerfCounterSamples));
// arg2 = arg2 = CASTED_CLOG_BYTEARRAY16(sizeof(PerfCounterSamples), PerfCounterSamples) = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, PerfCountersRundown,
    TP_ARGS(
        unsigned int, arg2_len,
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2_len, arg2_len)
        ctf_sequence(char, arg2, arg2, unsigned int, arg2_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryInitializedV3
// [ lib] Initialized
// QuicTraceEvent(
        LibraryInitializedV3,
        "[ lib] Initialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryInitializedV3,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryVersion
// [ lib] Version %u.%u.%u.%u
// QuicTraceEvent(
        LibraryVersion,
        "[ lib] Version %u.%u.%u.%u",
        MsQuicLib.Version[0],
        MsQuicLib.Version[1],
        MsQuicLib.Version[2],
        MsQuicLib.Version[3]);
// arg2 = arg2 = MsQuicLib.Version[0] = arg2
// arg3 = arg3 = MsQuicLib.Version[1] = arg3
// arg4 = arg4 = MsQuicLib.Version[2] = arg4
// arg5 = arg5 = MsQuicLib.Version[3] = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryVersion,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryUninitialized
// [ lib] Uninitialized
// QuicTraceEvent(
        LibraryUninitialized,
        "[ lib] Uninitialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryUninitialized,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryAddRef
// [ lib] AddRef
// QuicTraceEvent(
        LibraryAddRef,
        "[ lib] AddRef");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryAddRef,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryRelease
// [ lib] Release
// QuicTraceEvent(
        LibraryRelease,
        "[ lib] Release");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryRelease,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for DataPathInitialized
// [data] Initialized, DatapathFeatures=%u
// QuicTraceEvent(
            DataPathInitialized,
            "[data] Initialized, DatapathFeatures=%u",
            QuicLibraryGetDatapathFeatures());
// arg2 = arg2 = QuicLibraryGetDatapathFeatures() = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, DataPathInitialized,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Only v2 is supported in MsQuicOpenVersion");
// arg2 = arg2 = "Only v2 is supported in MsQuicOpenVersion" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingError
// [bind][%p] ERROR, %s.
// QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                Binding,
                "Binding already in use");
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = "Binding already in use" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, BindingError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryServerInit
// [ lib] Shared server state initializing
// QuicTraceEvent(
            LibraryServerInit,
            "[ lib] Shared server state initializing");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryServerInit,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryRundownV2
// [ lib] Rundown, PartitionCount=%u
// QuicTraceEvent(
            LibraryRundownV2,
            "[ lib] Rundown, PartitionCount=%u",
            MsQuicLib.PartitionCount);
// arg2 = arg2 = MsQuicLib.PartitionCount = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibraryRundownV2,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DataPathRundown
// [data] Rundown, DatapathFeatures=%u
// QuicTraceEvent(
                DataPathRundown,
                "[data] Rundown, DatapathFeatures=%u",
                QuicLibraryGetDatapathFeatures());
// arg2 = arg2 = QuicLibraryGetDatapathFeatures() = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, DataPathRundown,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibrarySendRetryStateUpdated
// [ lib] New SendRetryEnabled state, %hhu
// QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            MsQuicLib.SendRetryEnabled);
// arg2 = arg2 = MsQuicLib.SendRetryEnabled = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, LibrarySendRetryStateUpdated,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_EXECUTION_CREATE,
        NULL);
// arg2 = arg2 = QUIC_TRACE_API_EXECUTION_CREATE = arg2
// arg3 = arg3 = NULL = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, ApiEnter,
    TP_ARGS(
        unsigned int, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, (uint64_t)arg3)
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
TRACEPOINT_EVENT(CLOG_LIBRARY_C, ApiExitStatus,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LIBRARY_C, ApiExit,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)
