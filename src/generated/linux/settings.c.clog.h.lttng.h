


/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendBufferingEnabled
// [sett] SendBufferingEnabled   = %hhu
// QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
// arg2 = arg2 = Settings->SendBufferingEnabled
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
// arg2 = arg2 = Settings->PacingEnabled
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
// arg2 = arg2 = Settings->MigrationEnabled
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
// arg2 = arg2 = Settings->DatagramReceiveEnabled
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
// arg2 = arg2 = Settings->MaxOperationsPerDrain
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
// arg2 = arg2 = Settings->RetryMemoryLimit
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
// arg2 = arg2 = Settings->LoadBalancingMode
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
// arg2 = arg2 = Settings->MaxStatelessOperations
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
// arg2 = arg2 = Settings->MaxWorkerQueueDelayUs
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
// arg2 = arg2 = Settings->InitialWindowPackets
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
// arg2 = arg2 = Settings->SendIdleTimeoutMs
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
// arg2 = arg2 = Settings->InitialRttMs
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
// arg2 = arg2 = Settings->MaxAckDelayMs
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
// arg2 = arg2 = Settings->DisconnectTimeoutMs
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
// arg2 = arg2 = Settings->KeepAliveIntervalMs
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
// arg2 = arg2 = Settings->IdleTimeoutMs
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
// arg2 = arg2 = Settings->HandshakeIdleTimeoutMs
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
// arg2 = arg2 = Settings->PeerBidiStreamCount
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
// arg2 = arg2 = Settings->PeerUnidiStreamCount
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
// arg2 = arg2 = Settings->TlsClientMaxSendBuffer
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
// arg2 = arg2 = Settings->TlsServerMaxSendBuffer
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
// arg2 = arg2 = Settings->StreamRecvWindowDefault
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
// arg2 = arg2 = Settings->StreamRecvBufferDefault
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
// arg2 = arg2 = Settings->ConnFlowControlWindow
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
// arg2 = arg2 = Settings->MaxBytesPerKey
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
// arg2 = arg2 = Settings->ServerResumptionLevel
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SETTINGS_C, SettingDumpServerResumptionLevel,
    TP_ARGS(
        unsigned char, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
    )
)
