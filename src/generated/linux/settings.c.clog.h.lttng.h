


/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendBufferingEnabled
// [sett] SendBufferingEnabled   = %hhu
// QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
// arg2 = arg2 = Settings->SendBufferingEnabled = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpSendBufferingEnabled,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpPacingEnabled
// [sett] PacingEnabled          = %hhu
// QuicTraceLogVerbose(SettingDumpPacingEnabled,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
// arg2 = arg2 = Settings->PacingEnabled = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpPacingEnabled,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMigrationEnabled
// [sett] MigrationEnabled       = %hhu
// QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
// arg2 = arg2 = Settings->MigrationEnabled = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMigrationEnabled,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpDatagramReceiveEnabled
// [sett] DatagramReceiveEnabled = %hhu
// QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
// arg2 = arg2 = Settings->DatagramReceiveEnabled = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpDatagramReceiveEnabled,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxOperationsPerDrain
// [sett] MaxOperationsPerDrain  = %hhu
// QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,   "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
// arg2 = arg2 = Settings->MaxOperationsPerDrain = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaxOperationsPerDrain,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpRetryMemoryLimit
// [sett] RetryMemoryLimit       = %hu
// QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,        "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
// arg2 = arg2 = Settings->RetryMemoryLimit = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpRetryMemoryLimit,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpLoadBalancingMode
// [sett] LoadBalancingMode      = %hu
// QuicTraceLogVerbose(SettingDumpLoadBalancingMode,       "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
// arg2 = arg2 = Settings->LoadBalancingMode = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpLoadBalancingMode,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxStatelessOperations
// [sett] MaxStatelessOperations = %u
// QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,  "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
// arg2 = arg2 = Settings->MaxStatelessOperations = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaxStatelessOperations,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxWorkerQueueDelayUs
// [sett] MaxWorkerQueueDelayUs  = %u
// QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,   "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
// arg2 = arg2 = Settings->MaxWorkerQueueDelayUs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaxWorkerQueueDelayUs,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialWindowPackets
// [sett] InitialWindowPackets   = %u
// QuicTraceLogVerbose(SettingDumpInitialWindowPackets,    "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
// arg2 = arg2 = Settings->InitialWindowPackets = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpInitialWindowPackets,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendIdleTimeoutMs
// [sett] SendIdleTimeoutMs      = %u
// QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,       "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
// arg2 = arg2 = Settings->SendIdleTimeoutMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpSendIdleTimeoutMs,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialRttMs
// [sett] InitialRttMs           = %u
// QuicTraceLogVerbose(SettingDumpInitialRttMs,            "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
// arg2 = arg2 = Settings->InitialRttMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpInitialRttMs,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxAckDelayMs
// [sett] MaxAckDelayMs          = %u
// QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,           "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
// arg2 = arg2 = Settings->MaxAckDelayMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaxAckDelayMs,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpDisconnectTimeoutMs
// [sett] DisconnectTimeoutMs    = %u
// QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,     "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
// arg2 = arg2 = Settings->DisconnectTimeoutMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpDisconnectTimeoutMs,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpKeepAliveIntervalMs
// [sett] KeepAliveIntervalMs    = %u
// QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,     "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
// arg2 = arg2 = Settings->KeepAliveIntervalMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpKeepAliveIntervalMs,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpIdleTimeoutMs
// [sett] IdleTimeoutMs          = %llu
// QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,           "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
// arg2 = arg2 = Settings->IdleTimeoutMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpIdleTimeoutMs,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpHandshakeIdleTimeoutMs
// [sett] HandshakeIdleTimeoutMs = %llu
// QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,  "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
// arg2 = arg2 = Settings->HandshakeIdleTimeoutMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpHandshakeIdleTimeoutMs,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpBidiStreamCount
// [sett] PeerBidiStreamCount    = %hu
// QuicTraceLogVerbose(SettingDumpBidiStreamCount,         "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
// arg2 = arg2 = Settings->PeerBidiStreamCount = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpBidiStreamCount,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpUnidiStreamCount
// [sett] PeerUnidiStreamCount   = %hu
// QuicTraceLogVerbose(SettingDumpUnidiStreamCount,        "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
// arg2 = arg2 = Settings->PeerUnidiStreamCount = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpUnidiStreamCount,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsClientMaxSendBuffer
// [sett] TlsClientMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,  "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
// arg2 = arg2 = Settings->TlsClientMaxSendBuffer = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpTlsClientMaxSendBuffer,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsServerMaxSendBuffer
// [sett] TlsServerMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,  "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
// arg2 = arg2 = Settings->TlsServerMaxSendBuffer = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpTlsServerMaxSendBuffer,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvWindowDefault
// [sett] StreamRecvWindowDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault, "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
// arg2 = arg2 = Settings->StreamRecvWindowDefault = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpStreamRecvWindowDefault,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvBufferDefault
// [sett] StreamRecvBufferDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault, "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
// arg2 = arg2 = Settings->StreamRecvBufferDefault = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpStreamRecvBufferDefault,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpConnFlowControlWindow
// [sett] ConnFlowControlWindow  = %u
// QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,   "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
// arg2 = arg2 = Settings->ConnFlowControlWindow = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpConnFlowControlWindow,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxBytesPerKey
// [sett] MaxBytesPerKey         = %llu
// QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,          "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
// arg2 = arg2 = Settings->MaxBytesPerKey = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaxBytesPerKey,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpServerResumptionLevel
// [sett] ServerResumptionLevel  = %hhu
// QuicTraceLogVerbose(SettingDumpServerResumptionLevel,   "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
// arg2 = arg2 = Settings->ServerResumptionLevel = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpServerResumptionLevel,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpVersionNegoExtEnabled
// [sett] Version Negotiation Ext Enabled = %hhu
// QuicTraceLogVerbose(SettingDumpVersionNegoExtEnabled,   "[sett] Version Negotiation Ext Enabled = %hhu", Settings->VersionNegotiationExtEnabled);
// arg2 = arg2 = Settings->VersionNegotiationExtEnabled = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpVersionNegoExtEnabled,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMinimumMtu
// [sett] MinimumMtu             = %hu
// QuicTraceLogVerbose(SettingDumpMinimumMtu,              "[sett] MinimumMtu             = %hu", Settings->MinimumMtu);
// arg2 = arg2 = Settings->MinimumMtu = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMinimumMtu,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaximumMtu
// [sett] MaximumMtu             = %hu
// QuicTraceLogVerbose(SettingDumpMaximumMtu,              "[sett] MaximumMtu             = %hu", Settings->MaximumMtu);
// arg2 = arg2 = Settings->MaximumMtu = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaximumMtu,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMtuCompleteTimeout
// [sett] MtuCompleteTimeout     = %llu
// QuicTraceLogVerbose(SettingDumpMtuCompleteTimeout,      "[sett] MtuCompleteTimeout     = %llu", Settings->MtuDiscoverySearchCompleteTimeoutUs);
// arg2 = arg2 = Settings->MtuDiscoverySearchCompleteTimeoutUs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMtuCompleteTimeout,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMtuMissingProbeCount
// [sett] MtuMissingProbeCount   = %hhu
// QuicTraceLogVerbose(SettingDumpMtuMissingProbeCount,    "[sett] MtuMissingProbeCount   = %hhu", Settings->MtuDiscoveryMissingProbeCount);
// arg2 = arg2 = Settings->MtuDiscoveryMissingProbeCount = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMtuMissingProbeCount,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxBindingStatelessOper
// [sett] MaxBindingStatelessOper= %hu
// QuicTraceLogVerbose(SettingDumpMaxBindingStatelessOper, "[sett] MaxBindingStatelessOper= %hu", Settings->MaxBindingStatelessOperations);
// arg2 = arg2 = Settings->MaxBindingStatelessOperations = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpMaxBindingStatelessOper,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStatelessOperExpirMs
// [sett] StatelessOperExpirMs   = %hu
// QuicTraceLogVerbose(SettingDumpStatelessOperExpirMs,    "[sett] StatelessOperExpirMs   = %hu", Settings->StatelessOperationExpirationMs);
// arg2 = arg2 = Settings->StatelessOperationExpirationMs = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpStatelessOperExpirMs,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingCongestionControlAlgorithm
// [sett] CongestionControlAlgorithm = %hu
// QuicTraceLogVerbose(SettingCongestionControlAlgorithm,  "[sett] CongestionControlAlgorithm = %hu", Settings->CongestionControlAlgorithm);
// arg2 = arg2 = Settings->CongestionControlAlgorithm = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingCongestionControlAlgorithm,
    TP_ARGS(
        unsigned short, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpAcceptedVersionsLength
// [sett] AcceptedVersionslength = %u
// QuicTraceLogVerbose(SettingDumpAcceptedVersionsLength,      "[sett] AcceptedVersionslength = %u", Settings->VersionSettings->AcceptableVersionsLength);
// arg2 = arg2 = Settings->VersionSettings->AcceptableVersionsLength = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpAcceptedVersionsLength,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpOfferedVersionsLength
// [sett] OfferedVersionslength  = %u
// QuicTraceLogVerbose(SettingDumpOfferedVersionsLength,       "[sett] OfferedVersionslength  = %u", Settings->VersionSettings->OfferedVersionsLength);
// arg2 = arg2 = Settings->VersionSettings->OfferedVersionsLength = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpOfferedVersionsLength,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpAcceptableVersions
// [sett] AcceptableVersions[%u]  = 0x%x
// QuicTraceLogVerbose(SettingDumpAcceptableVersions,      "[sett] AcceptableVersions[%u]  = 0x%x", i, Settings->VersionSettings->AcceptableVersions[i]);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Settings->VersionSettings->AcceptableVersions[i] = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpAcceptableVersions,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpOfferedVersions
// [sett] OfferedVersions[%u]     = 0x%x
// QuicTraceLogVerbose(SettingDumpOfferedVersions,         "[sett] OfferedVersions[%u]     = 0x%x", i, Settings->VersionSettings->OfferedVersions[i]);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Settings->VersionSettings->OfferedVersions[i] = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpOfferedVersions,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingDumpFullyDeployedVersions
// [sett] FullyDeployedVersion[%u]= 0x%x
// QuicTraceLogVerbose(SettingDumpFullyDeployedVersions,   "[sett] FullyDeployedVersion[%u]= 0x%x", i, Settings->VersionSettings->FullyDeployedVersions[i]);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Settings->VersionSettings->FullyDeployedVersions[i] = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpFullyDeployedVersions,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingsInvalidAcceptableVersion
// Invalid AcceptableVersion supplied to settings! 0x%x at position %d
// QuicTraceLogError(
                SettingsInvalidAcceptableVersion,
                "Invalid AcceptableVersion supplied to settings! 0x%x at position %d",
                Settings->AcceptableVersions[i],
                (int32_t)i);
// arg2 = arg2 = Settings->AcceptableVersions[i] = arg2
// arg3 = arg3 = (int32_t)i = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingsInvalidAcceptableVersion,
    TP_ARGS(
        unsigned int, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingsInvalidOfferedVersion
// Invalid OfferedVersion supplied to settings! 0x%x at position %d
// QuicTraceLogError(
                SettingsInvalidOfferedVersion,
                "Invalid OfferedVersion supplied to settings! 0x%x at position %d",
                Settings->OfferedVersions[i],
                (int32_t)i);
// arg2 = arg2 = Settings->OfferedVersions[i] = arg2
// arg3 = arg3 = (int32_t)i = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingsInvalidOfferedVersion,
    TP_ARGS(
        unsigned int, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SettingsInvalidFullyDeployedVersion
// Invalid FullyDeployedVersion supplied to settings! 0x%x at position %d
// QuicTraceLogError(
                SettingsInvalidFullyDeployedVersion,
                "Invalid FullyDeployedVersion supplied to settings! 0x%x at position %d",
                Settings->FullyDeployedVersions[i],
                (int32_t)i);
// arg2 = arg2 = Settings->FullyDeployedVersions[i] = arg2
// arg3 = arg3 = (int32_t)i = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingsInvalidFullyDeployedVersion,
    TP_ARGS(
        unsigned int, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "VersionSettings",
            AllocSize);
// arg2 = arg2 = "VersionSettings" = arg2
// arg3 = arg3 = AllocSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
