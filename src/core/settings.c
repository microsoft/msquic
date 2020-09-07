/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Storage for all configurable values.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "settings.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsSetDefault(
    _Inout_ QUIC_SETTINGS* Settings
    )
{
    if (!Settings->IsSet.PacingEnabled) {
        Settings->PacingEnabled = QUIC_DEFAULT_SEND_PACING;
    }
    if (!Settings->IsSet.MigrationEnabled) {
        Settings->MigrationEnabled = QUIC_DEFAULT_MIGRATION_ENABLED;
    }
    if (!Settings->IsSet.DatagramReceiveEnabled) {
        Settings->DatagramReceiveEnabled = QUIC_DEFAULT_DATAGRAM_RECEIVE_ENABLED;
    }
    if (!Settings->IsSet.MaxPartitionCount) {
        Settings->MaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
    }
    if (!Settings->IsSet.MaxOperationsPerDrain) {
        Settings->MaxOperationsPerDrain = QUIC_MAX_OPERATIONS_PER_DRAIN;
    }
    if (!Settings->IsSet.RetryMemoryLimit) {
        Settings->RetryMemoryLimit = QUIC_DEFAULT_RETRY_MEMORY_FRACTION;
    }
    if (!Settings->IsSet.LoadBalancingMode) {
        Settings->LoadBalancingMode = QUIC_DEFAULT_LOAD_BALANCING_MODE;
    }
    if (!Settings->IsSet.MaxWorkerQueueDelayUs) {
        Settings->MaxWorkerQueueDelayUs = MS_TO_US(QUIC_MAX_WORKER_QUEUE_DELAY);
    }
    if (!Settings->IsSet.MaxStatelessOperations) {
        Settings->MaxStatelessOperations = QUIC_MAX_STATELESS_OPERATIONS;
    }
    if (!Settings->IsSet.InitialWindowPackets) {
        Settings->InitialWindowPackets = QUIC_INITIAL_WINDOW_PACKETS;
    }
    if (!Settings->IsSet.SendIdleTimeoutMs) {
        Settings->SendIdleTimeoutMs = QUIC_DEFAULT_SEND_IDLE_TIMEOUT_MS;
    }
    if (!Settings->IsSet.InitialRttMs) {
        Settings->InitialRttMs = QUIC_INITIAL_RTT;
    }
    if (!Settings->IsSet.MaxAckDelayMs) {
        Settings->MaxAckDelayMs = QUIC_TP_MAX_ACK_DELAY_DEFAULT;
    }
    if (!Settings->IsSet.DisconnectTimeoutMs) {
        Settings->DisconnectTimeoutMs = QUIC_DEFAULT_DISCONNECT_TIMEOUT;
    }
    if (!Settings->IsSet.KeepAliveIntervalMs) {
        Settings->KeepAliveIntervalMs = QUIC_DEFAULT_KEEP_ALIVE_INTERVAL;
    }
    if (!Settings->IsSet.IdleTimeoutMs) {
        Settings->IdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
    }
    if (!Settings->IsSet.HandshakeIdleTimeoutMs) {
        Settings->HandshakeIdleTimeoutMs = QUIC_DEFAULT_HANDSHAKE_IDLE_TIMEOUT;
    }
    if (!Settings->IsSet.PeerBidiStreamCount) {
        Settings->PeerBidiStreamCount = 0;
    }
    if (!Settings->IsSet.PeerUnidiStreamCount) {
        Settings->PeerUnidiStreamCount = 0;
    }
    if (!Settings->IsSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = QUIC_MAX_TLS_CLIENT_SEND_BUFFER;
    }
    if (!Settings->IsSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = QUIC_MAX_TLS_SERVER_SEND_BUFFER;
    }
    if (!Settings->IsSet.StreamRecvWindowDefault) {
        Settings->StreamRecvWindowDefault = QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE;
    }
    if (!Settings->IsSet.StreamRecvBufferDefault) {
        Settings->StreamRecvBufferDefault = QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE;
    }
    if (!Settings->IsSet.ConnFlowControlWindow) {
        Settings->ConnFlowControlWindow = QUIC_DEFAULT_CONN_FLOW_CONTROL_WINDOW;
    }
    if (!Settings->IsSet.MaxBytesPerKey) {
        Settings->MaxBytesPerKey = QUIC_DEFAULT_MAX_BYTES_PER_KEY;
    }
    if (!Settings->IsSet.ServerResumptionLevel) {
        Settings->ServerResumptionLevel = QUIC_DEFAULT_SERVER_RESUMPTION_LEVEL;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCopy(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ const QUIC_SETTINGS* ParentSettings
    )
{
    if (!Settings->IsSet.PacingEnabled) {
        Settings->PacingEnabled = ParentSettings->PacingEnabled;
    }
    if (!Settings->IsSet.MigrationEnabled) {
        Settings->MigrationEnabled = ParentSettings->MigrationEnabled;
    }
    if (!Settings->IsSet.DatagramReceiveEnabled) {
        Settings->DatagramReceiveEnabled = ParentSettings->DatagramReceiveEnabled;
    }
    if (!Settings->IsSet.MaxPartitionCount) {
        Settings->MaxPartitionCount = ParentSettings->MaxPartitionCount;
    }
    if (!Settings->IsSet.MaxOperationsPerDrain) {
        Settings->MaxOperationsPerDrain = ParentSettings->MaxOperationsPerDrain;
    }
    if (!Settings->IsSet.RetryMemoryLimit) {
        Settings->RetryMemoryLimit = ParentSettings->RetryMemoryLimit;
    }
    if (!Settings->IsSet.LoadBalancingMode) {
        Settings->LoadBalancingMode = ParentSettings->LoadBalancingMode;
    }
    if (!Settings->IsSet.MaxWorkerQueueDelayUs) {
        Settings->MaxWorkerQueueDelayUs = ParentSettings->MaxWorkerQueueDelayUs;
    }
    if (!Settings->IsSet.MaxStatelessOperations) {
        Settings->MaxStatelessOperations = ParentSettings->MaxStatelessOperations;
    }
    if (!Settings->IsSet.InitialWindowPackets) {
        Settings->InitialWindowPackets = ParentSettings->InitialWindowPackets;
    }
    if (!Settings->IsSet.SendIdleTimeoutMs) {
        Settings->SendIdleTimeoutMs = ParentSettings->SendIdleTimeoutMs;
    }
    if (!Settings->IsSet.InitialRttMs) {
        Settings->InitialRttMs = ParentSettings->InitialRttMs;
    }
    if (!Settings->IsSet.MaxAckDelayMs) {
        Settings->MaxAckDelayMs = ParentSettings->MaxAckDelayMs;
    }
    if (!Settings->IsSet.DisconnectTimeoutMs) {
        Settings->DisconnectTimeoutMs = ParentSettings->DisconnectTimeoutMs;
    }
    if (!Settings->IsSet.KeepAliveIntervalMs) {
        Settings->KeepAliveIntervalMs = ParentSettings->KeepAliveIntervalMs;
    }
    if (!Settings->IsSet.IdleTimeoutMs) {
        Settings->IdleTimeoutMs = ParentSettings->IdleTimeoutMs;
    }
    if (!Settings->IsSet.HandshakeIdleTimeoutMs) {
        Settings->HandshakeIdleTimeoutMs = ParentSettings->HandshakeIdleTimeoutMs;
    }
    if (!Settings->IsSet.PeerBidiStreamCount) {
        Settings->PeerBidiStreamCount = ParentSettings->PeerBidiStreamCount;
    }
    if (!Settings->IsSet.PeerUnidiStreamCount) {
        Settings->PeerUnidiStreamCount = ParentSettings->PeerUnidiStreamCount;
    }
    if (!Settings->IsSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = ParentSettings->TlsClientMaxSendBuffer;
    }
    if (!Settings->IsSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = ParentSettings->TlsClientMaxSendBuffer;
    }
    if (!Settings->IsSet.StreamRecvWindowDefault) {
        Settings->StreamRecvWindowDefault = ParentSettings->StreamRecvWindowDefault;
    }
    if (!Settings->IsSet.StreamRecvBufferDefault) {
        Settings->StreamRecvBufferDefault = ParentSettings->StreamRecvBufferDefault;
    }
    if (!Settings->IsSet.ConnFlowControlWindow) {
        Settings->ConnFlowControlWindow = ParentSettings->ConnFlowControlWindow;
    }
    if (!Settings->IsSet.MaxBytesPerKey) {
        Settings->MaxBytesPerKey = ParentSettings->MaxBytesPerKey;
    }
    if (!Settings->IsSet.ServerResumptionLevel) {
        Settings->ServerResumptionLevel = ParentSettings->ServerResumptionLevel;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSettingApply(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey), UINT32_MAX)
        uint32_t NewSessionSize,
    _In_reads_bytes_(NewSessionSize)
        const QUIC_SETTINGS* NewSettings
    )
{
    // TODO - Input validation
    UNREFERENCED_PARAMETER(NewSessionSize); // TODO - Use to validate new settings
    if (NewSettings->IsSet.PacingEnabled) {
        Settings->PacingEnabled = NewSettings->PacingEnabled;
        Settings->IsSet.PacingEnabled = TRUE;
    }
    if (NewSettings->IsSet.MigrationEnabled) {
        Settings->MigrationEnabled = NewSettings->MigrationEnabled;
        Settings->IsSet.MigrationEnabled = TRUE;
    }
    if (NewSettings->IsSet.DatagramReceiveEnabled) {
        Settings->DatagramReceiveEnabled = NewSettings->DatagramReceiveEnabled;
        Settings->IsSet.DatagramReceiveEnabled = TRUE;
    }
    if (NewSettings->IsSet.MaxPartitionCount) {
        Settings->MaxPartitionCount = NewSettings->MaxPartitionCount;
        Settings->IsSet.MaxPartitionCount = TRUE;
    }
    if (NewSettings->IsSet.MaxOperationsPerDrain) {
        Settings->MaxOperationsPerDrain = NewSettings->MaxOperationsPerDrain;
        Settings->IsSet.MaxOperationsPerDrain = TRUE;
    }
    if (NewSettings->IsSet.RetryMemoryLimit) {
        Settings->RetryMemoryLimit = NewSettings->RetryMemoryLimit;
        Settings->IsSet.RetryMemoryLimit = TRUE;
    }
    if (NewSettings->IsSet.LoadBalancingMode) {
        if (NewSettings->LoadBalancingMode > QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            return FALSE;
        }
        Settings->LoadBalancingMode = NewSettings->LoadBalancingMode;
        Settings->IsSet.LoadBalancingMode = TRUE;
    }
    if (NewSettings->IsSet.MaxWorkerQueueDelayUs) {
        Settings->MaxWorkerQueueDelayUs = NewSettings->MaxWorkerQueueDelayUs;
        Settings->IsSet.MaxWorkerQueueDelayUs = TRUE;
    }
    if (NewSettings->IsSet.MaxStatelessOperations) {
        Settings->MaxStatelessOperations = NewSettings->MaxStatelessOperations;
        Settings->IsSet.MaxStatelessOperations = TRUE;
    }
    if (NewSettings->IsSet.InitialWindowPackets) {
        Settings->InitialWindowPackets = NewSettings->InitialWindowPackets;
        Settings->IsSet.InitialWindowPackets = TRUE;
    }
    if (NewSettings->IsSet.SendIdleTimeoutMs) {
        Settings->SendIdleTimeoutMs = NewSettings->SendIdleTimeoutMs;
        Settings->IsSet.SendIdleTimeoutMs = TRUE;
    }
    if (NewSettings->IsSet.InitialRttMs) {
        Settings->InitialRttMs = NewSettings->InitialRttMs;
        Settings->IsSet.InitialRttMs = TRUE;
    }
    if (NewSettings->IsSet.MaxAckDelayMs) {
        if (NewSettings->MaxAckDelayMs > QUIC_TP_MAX_ACK_DELAY_MAX) {
            return FALSE;
        }
        Settings->MaxAckDelayMs = NewSettings->MaxAckDelayMs;
        Settings->IsSet.MaxAckDelayMs = TRUE;
    }
    if (NewSettings->IsSet.DisconnectTimeoutMs) {
        if (NewSettings->DisconnectTimeoutMs > QUIC_MAX_DISCONNECT_TIMEOUT) {
            return FALSE;
        }
        Settings->DisconnectTimeoutMs = NewSettings->DisconnectTimeoutMs;
        Settings->IsSet.DisconnectTimeoutMs = TRUE;
    }
    if (NewSettings->IsSet.KeepAliveIntervalMs) {
        Settings->KeepAliveIntervalMs = NewSettings->KeepAliveIntervalMs;
        Settings->IsSet.KeepAliveIntervalMs = TRUE;
    }
    if (NewSettings->IsSet.IdleTimeoutMs) {
        if (NewSettings->IdleTimeoutMs > QUIC_VAR_INT_MAX) {
            return FALSE;
        }
        Settings->IdleTimeoutMs = NewSettings->IdleTimeoutMs;
        Settings->IsSet.IdleTimeoutMs = TRUE;
    }
    if (NewSettings->IsSet.HandshakeIdleTimeoutMs) {
        if (NewSettings->HandshakeIdleTimeoutMs > QUIC_VAR_INT_MAX) {
            return FALSE;
        }
        Settings->HandshakeIdleTimeoutMs = NewSettings->HandshakeIdleTimeoutMs;
        Settings->IsSet.HandshakeIdleTimeoutMs = TRUE;
    }
    if (NewSettings->IsSet.PeerBidiStreamCount) {
        Settings->PeerBidiStreamCount = NewSettings->PeerBidiStreamCount;
        Settings->IsSet.PeerBidiStreamCount = TRUE;
    }
    if (NewSettings->IsSet.PeerUnidiStreamCount) {
        Settings->PeerUnidiStreamCount = NewSettings->PeerUnidiStreamCount;
        Settings->IsSet.PeerUnidiStreamCount = TRUE;
    }
    if (NewSettings->IsSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = NewSettings->TlsClientMaxSendBuffer;
        Settings->IsSet.TlsClientMaxSendBuffer = TRUE;
    }
    if (NewSettings->IsSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = NewSettings->TlsClientMaxSendBuffer;
        Settings->IsSet.TlsClientMaxSendBuffer = TRUE;
    }
    if (NewSettings->IsSet.StreamRecvWindowDefault) {
        Settings->StreamRecvWindowDefault = NewSettings->StreamRecvWindowDefault;
        Settings->IsSet.StreamRecvWindowDefault = TRUE;
    }
    if (NewSettings->IsSet.StreamRecvBufferDefault) {
        if (NewSettings->StreamRecvBufferDefault < QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE) {
            return FALSE;
        }
        Settings->StreamRecvBufferDefault = NewSettings->StreamRecvBufferDefault;
        Settings->IsSet.StreamRecvBufferDefault = TRUE;
    }
    if (NewSettings->IsSet.ConnFlowControlWindow) {
        Settings->ConnFlowControlWindow = NewSettings->ConnFlowControlWindow;
        Settings->IsSet.ConnFlowControlWindow = TRUE;
    }
    if (NewSettings->IsSet.MaxBytesPerKey) {
        if (NewSettings->MaxBytesPerKey > QUIC_DEFAULT_MAX_BYTES_PER_KEY) {
            return FALSE;
        }
        Settings->MaxBytesPerKey = NewSettings->MaxBytesPerKey;
        Settings->IsSet.MaxBytesPerKey = TRUE;
    }
    if (NewSettings->IsSet.ServerResumptionLevel) {
        if (NewSettings->ServerResumptionLevel > QUIC_SERVER_RESUME_AND_ZERORTT) {
            return FALSE;
        }
        Settings->ServerResumptionLevel = NewSettings->ServerResumptionLevel;
        Settings->IsSet.ServerResumptionLevel = TRUE;
    }
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ QUIC_STORAGE* Storage
    )
{
    uint32_t Value;
    union {
        uint32_t Half;
        uint64_t Full;
        uint8_t Array[sizeof(uint64_t)];
    } MultiValue;
    uint32_t ValueLen;

    if (!Settings->IsSet.PacingEnabled) {
        Value = QUIC_DEFAULT_SEND_PACING;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_PACING_DEFAULT,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->PacingEnabled = !!Value;
    }

    if (!Settings->IsSet.MigrationEnabled) {
        Value = QUIC_DEFAULT_MIGRATION_ENABLED;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MIGRATION_ENABLED,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->MigrationEnabled = !!Value;
    }

    if (!Settings->IsSet.DatagramReceiveEnabled) {
        Value = QUIC_DEFAULT_DATAGRAM_RECEIVE_ENABLED;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_DATAGRAM_RECEIVE_ENABLED,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->DatagramReceiveEnabled = !!Value;
    }

    if (!Settings->IsSet.MaxPartitionCount) {
        Value = QUIC_MAX_PARTITION_COUNT;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_PARTITION_COUNT,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value <= UINT8_MAX) {
            Settings->MaxPartitionCount = (uint8_t)Value;
        }
    }

    if (!Settings->IsSet.MaxOperationsPerDrain) {
        Value = QUIC_MAX_OPERATIONS_PER_DRAIN;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_OPERATIONS_PER_DRAIN,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value <= UINT8_MAX) {
            Settings->MaxOperationsPerDrain = (uint8_t)Value;
        }
    }

    if (!Settings->IsSet.RetryMemoryLimit) {
        Value = QUIC_DEFAULT_RETRY_MEMORY_FRACTION;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_RETRY_MEMORY_FRACTION,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value <= UINT16_MAX) {
            Settings->RetryMemoryLimit = (uint16_t)Value;
        }
    }

    if (!Settings->IsSet.LoadBalancingMode &&
        !MsQuicLib.InUse) {
        Value = QUIC_DEFAULT_LOAD_BALANCING_MODE;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_LOAD_BALANCING_MODE,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value <= QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            Settings->LoadBalancingMode = (uint16_t)Value;
        }
    }

    if (!Settings->IsSet.MaxWorkerQueueDelayUs) {
        Value = QUIC_MAX_WORKER_QUEUE_DELAY;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_WORKER_QUEUE_DELAY,
            (uint8_t*)&Value,                               // Read as ms
            &ValueLen);
        Settings->MaxWorkerQueueDelayUs = MS_TO_US(Value);  // Convert to us
    }

    if (!Settings->IsSet.MaxStatelessOperations) {
        ValueLen = sizeof(Settings->MaxStatelessOperations);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_STATELESS_OPERATIONS,
            (uint8_t*)&Settings->MaxStatelessOperations,
            &ValueLen);
    }

    if (!Settings->IsSet.InitialWindowPackets) {
        ValueLen = sizeof(Settings->InitialWindowPackets);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_INITIAL_WINDOW_PACKETS,
            (uint8_t*)&Settings->InitialWindowPackets,
            &ValueLen);
    }

    if (!Settings->IsSet.SendIdleTimeoutMs) {
        ValueLen = sizeof(Settings->SendIdleTimeoutMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_IDLE_TIMEOUT_MS,
            (uint8_t*)&Settings->SendIdleTimeoutMs,
            &ValueLen);
    }

    if (!Settings->IsSet.InitialRttMs) {
        ValueLen = sizeof(Settings->InitialRttMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_INITIAL_RTT,
            (uint8_t*)&Settings->InitialRttMs,
            &ValueLen);
    }

    if (!Settings->IsSet.MaxAckDelayMs) {
        ValueLen = sizeof(Settings->MaxAckDelayMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_ACK_DELAY,
            (uint8_t*)&Settings->MaxAckDelayMs,
            &ValueLen);
        if (Settings->MaxAckDelayMs > QUIC_TP_MAX_ACK_DELAY_MAX) {
            Settings->MaxAckDelayMs = QUIC_TP_MAX_ACK_DELAY_DEFAULT;
        }
    }

    if (!Settings->IsSet.DisconnectTimeoutMs) {
        ValueLen = sizeof(Settings->DisconnectTimeoutMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_DISCONNECT_TIMEOUT,
            (uint8_t*)&Settings->DisconnectTimeoutMs,
            &ValueLen);
        if (Settings->DisconnectTimeoutMs > QUIC_MAX_DISCONNECT_TIMEOUT) {
            Settings->DisconnectTimeoutMs = QUIC_MAX_DISCONNECT_TIMEOUT;
        }
    }

    if (!Settings->IsSet.KeepAliveIntervalMs) {
        ValueLen = sizeof(Settings->KeepAliveIntervalMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_KEEP_ALIVE_INTERVAL,
            (uint8_t*)&Settings->KeepAliveIntervalMs,
            &ValueLen);
    }

    if (!Settings->IsSet.IdleTimeoutMs) {
        QUIC_STATIC_ASSERT(sizeof(MultiValue) == sizeof(Settings->IdleTimeoutMs), "These must be the same size");
        ValueLen = sizeof(MultiValue);
        if (QUIC_SUCCEEDED(
            QuicStorageReadValue(
                Storage,
                QUIC_SETTING_IDLE_TIMEOUT,
                MultiValue.Array,
                &ValueLen))) {
            if (ValueLen == sizeof(uint32_t)) {
                Settings->IdleTimeoutMs = MultiValue.Half;
            } else {
                Settings->IdleTimeoutMs = MultiValue.Full;
            }
            if (Settings->IdleTimeoutMs > QUIC_VAR_INT_MAX) {
                Settings->IdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
            }
        }
    }

    if (!Settings->IsSet.HandshakeIdleTimeoutMs) {
        QUIC_STATIC_ASSERT(sizeof(MultiValue) == sizeof(Settings->HandshakeIdleTimeoutMs), "These must be the same size");
        ValueLen = sizeof(MultiValue);
        if (QUIC_SUCCEEDED(
            QuicStorageReadValue(
                Storage,
                QUIC_SETTING_HANDSHAKE_IDLE_TIMEOUT,
                MultiValue.Array,
                &ValueLen))) {
            if (ValueLen == sizeof(uint32_t)) {
                Settings->HandshakeIdleTimeoutMs = MultiValue.Half;
            } else {
                Settings->HandshakeIdleTimeoutMs = MultiValue.Full;
            }
            if (Settings->HandshakeIdleTimeoutMs > QUIC_VAR_INT_MAX) {
                Settings->HandshakeIdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
            }
        }
    }

    if (!Settings->IsSet.TlsClientMaxSendBuffer) {
        ValueLen = sizeof(Settings->TlsClientMaxSendBuffer);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_TLS_CLIENT_SEND_BUFFER,
            (uint8_t*)&Settings->TlsClientMaxSendBuffer,
            &ValueLen);
    }

    if (!Settings->IsSet.TlsServerMaxSendBuffer) {
        ValueLen = sizeof(Settings->TlsServerMaxSendBuffer);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_TLS_SERVER_SEND_BUFFER,
            (uint8_t*)&Settings->TlsServerMaxSendBuffer,
            &ValueLen);
    }

    if (!Settings->IsSet.StreamRecvWindowDefault) {
        ValueLen = sizeof(Settings->StreamRecvWindowDefault);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_STREAM_FC_WINDOW_SIZE,
            (uint8_t*)&Settings->StreamRecvWindowDefault,
            &ValueLen);
    }

    if (!Settings->IsSet.StreamRecvBufferDefault) {
        ValueLen = sizeof(Settings->StreamRecvBufferDefault);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_STREAM_RECV_BUFFER_SIZE,
            (uint8_t*)&Settings->StreamRecvBufferDefault,
            &ValueLen);
        if (!IS_POWER_OF_TWO(Settings->StreamRecvBufferDefault) ||
            Settings->StreamRecvBufferDefault < QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE) {
            Settings->StreamRecvBufferDefault = QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE;
        }
    }

    if (!Settings->IsSet.ConnFlowControlWindow) {
        ValueLen = sizeof(Settings->ConnFlowControlWindow);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_CONN_FLOW_CONTROL_WINDOW,
            (uint8_t*)&Settings->ConnFlowControlWindow,
            &ValueLen);
    }

    if (!Settings->IsSet.MaxBytesPerKey) {
        ValueLen = sizeof(Settings->MaxBytesPerKey);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_BYTES_PER_KEY_PHASE,
            (uint8_t*)&Settings->MaxBytesPerKey,
            &ValueLen);
        if (Settings->MaxBytesPerKey > QUIC_DEFAULT_MAX_BYTES_PER_KEY) {
            Settings->MaxBytesPerKey = QUIC_DEFAULT_MAX_BYTES_PER_KEY;
        }
    }

    if (!Settings->IsSet.ServerResumptionLevel) {
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_SERVER_RESUMPTION_LEVEL,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value > QUIC_SERVER_RESUME_AND_ZERORTT) {
            Value = QUIC_SERVER_RESUME_AND_ZERORTT;
        }
        Settings->ServerResumptionLevel = (uint8_t)Value;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDump(
    _In_ const QUIC_SETTINGS* Settings
    )
{
    QuicTraceLogVerbose(SettingDumpPacingDefault,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
    QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
    QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
    QuicTraceLogVerbose(SettingDumpMaxPartitionCount,       "[sett] MaxPartitionCount      = %hhu", Settings->MaxPartitionCount);
    QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,   "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
    QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,        "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
    QuicTraceLogVerbose(SettingDumpLoadBalancingMode,       "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
    QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,  "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
    QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,   "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
    QuicTraceLogVerbose(SettingDumpInitialWindowPackets,    "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
    QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,       "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
    QuicTraceLogVerbose(SettingDumpInitialRttMs,            "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
    QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,           "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
    QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,     "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
    QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,     "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
    QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,           "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
    QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,  "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
    QuicTraceLogVerbose(SettingDumpBidiStreamCount,         "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
    QuicTraceLogVerbose(SettingDumpUnidiStreamCount,        "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
    QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,  "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
    QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,  "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
    QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault, "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
    QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault, "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
    QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,   "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
    QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,          "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
    QuicTraceLogVerbose(SettingDumpServerResumptionLevel,   "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
}
