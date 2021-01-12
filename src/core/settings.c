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
    if (!Settings->IsSet.SendBufferingEnabled) {
        Settings->SendBufferingEnabled = QUIC_DEFAULT_SEND_BUFFERING_ENABLE;
    }
    if (!Settings->IsSet.PacingEnabled) {
        Settings->PacingEnabled = QUIC_DEFAULT_SEND_PACING;
    }
    if (!Settings->IsSet.MigrationEnabled) {
        Settings->MigrationEnabled = QUIC_DEFAULT_MIGRATION_ENABLED;
    }
    if (!Settings->IsSet.DatagramReceiveEnabled) {
        Settings->DatagramReceiveEnabled = QUIC_DEFAULT_DATAGRAM_RECEIVE_ENABLED;
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
    _Inout_ QUIC_SETTINGS* Destination,
    _In_ const QUIC_SETTINGS* Source
    )
{
    if (!Destination->IsSet.SendBufferingEnabled) {
        Destination->SendBufferingEnabled = Source->SendBufferingEnabled;
    }
    if (!Destination->IsSet.PacingEnabled) {
        Destination->PacingEnabled = Source->PacingEnabled;
    }
    if (!Destination->IsSet.MigrationEnabled) {
        Destination->MigrationEnabled = Source->MigrationEnabled;
    }
    if (!Destination->IsSet.DatagramReceiveEnabled) {
        Destination->DatagramReceiveEnabled = Source->DatagramReceiveEnabled;
    }
    if (!Destination->IsSet.MaxOperationsPerDrain) {
        Destination->MaxOperationsPerDrain = Source->MaxOperationsPerDrain;
    }
    if (!Destination->IsSet.RetryMemoryLimit) {
        Destination->RetryMemoryLimit = Source->RetryMemoryLimit;
    }
    if (!Destination->IsSet.LoadBalancingMode) {
        Destination->LoadBalancingMode = Source->LoadBalancingMode;
    }
    if (!Destination->IsSet.MaxWorkerQueueDelayUs) {
        Destination->MaxWorkerQueueDelayUs = Source->MaxWorkerQueueDelayUs;
    }
    if (!Destination->IsSet.MaxStatelessOperations) {
        Destination->MaxStatelessOperations = Source->MaxStatelessOperations;
    }
    if (!Destination->IsSet.InitialWindowPackets) {
        Destination->InitialWindowPackets = Source->InitialWindowPackets;
    }
    if (!Destination->IsSet.SendIdleTimeoutMs) {
        Destination->SendIdleTimeoutMs = Source->SendIdleTimeoutMs;
    }
    if (!Destination->IsSet.InitialRttMs) {
        Destination->InitialRttMs = Source->InitialRttMs;
    }
    if (!Destination->IsSet.MaxAckDelayMs) {
        Destination->MaxAckDelayMs = Source->MaxAckDelayMs;
    }
    if (!Destination->IsSet.DisconnectTimeoutMs) {
        Destination->DisconnectTimeoutMs = Source->DisconnectTimeoutMs;
    }
    if (!Destination->IsSet.KeepAliveIntervalMs) {
        Destination->KeepAliveIntervalMs = Source->KeepAliveIntervalMs;
    }
    if (!Destination->IsSet.IdleTimeoutMs) {
        Destination->IdleTimeoutMs = Source->IdleTimeoutMs;
    }
    if (!Destination->IsSet.HandshakeIdleTimeoutMs) {
        Destination->HandshakeIdleTimeoutMs = Source->HandshakeIdleTimeoutMs;
    }
    if (!Destination->IsSet.PeerBidiStreamCount) {
        Destination->PeerBidiStreamCount = Source->PeerBidiStreamCount;
    }
    if (!Destination->IsSet.PeerUnidiStreamCount) {
        Destination->PeerUnidiStreamCount = Source->PeerUnidiStreamCount;
    }
    if (!Destination->IsSet.TlsClientMaxSendBuffer) {
        Destination->TlsClientMaxSendBuffer = Source->TlsClientMaxSendBuffer;
    }
    if (!Destination->IsSet.TlsClientMaxSendBuffer) {
        Destination->TlsClientMaxSendBuffer = Source->TlsClientMaxSendBuffer;
    }
    if (!Destination->IsSet.StreamRecvWindowDefault) {
        Destination->StreamRecvWindowDefault = Source->StreamRecvWindowDefault;
    }
    if (!Destination->IsSet.StreamRecvBufferDefault) {
        Destination->StreamRecvBufferDefault = Source->StreamRecvBufferDefault;
    }
    if (!Destination->IsSet.ConnFlowControlWindow) {
        Destination->ConnFlowControlWindow = Source->ConnFlowControlWindow;
    }
    if (!Destination->IsSet.MaxBytesPerKey) {
        Destination->MaxBytesPerKey = Source->MaxBytesPerKey;
    }
    if (!Destination->IsSet.ServerResumptionLevel) {
        Destination->ServerResumptionLevel = Source->ServerResumptionLevel;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSettingApply(
    _Inout_ QUIC_SETTINGS* Destination,
    _In_ BOOLEAN OverWrite,
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey), UINT32_MAX)
        uint32_t NewSettingsSize,
    _In_reads_bytes_(NewSettingsSize)
        const QUIC_SETTINGS* Source
    )
{
    // TODO - Input validation
    UNREFERENCED_PARAMETER(NewSettingsSize); // TODO - Use to validate new settings

    if (Source->IsSet.SendBufferingEnabled && (!Destination->IsSet.SendBufferingEnabled || OverWrite)) {
        Destination->SendBufferingEnabled = Source->SendBufferingEnabled;
        Destination->IsSet.SendBufferingEnabled = TRUE;
    }
    if (Source->IsSet.PacingEnabled && (!Destination->IsSet.PacingEnabled || OverWrite)) {
        Destination->PacingEnabled = Source->PacingEnabled;
        Destination->IsSet.PacingEnabled = TRUE;
    }
    if (Source->IsSet.MigrationEnabled && (!Destination->IsSet.MigrationEnabled || OverWrite)) {
        Destination->MigrationEnabled = Source->MigrationEnabled;
        Destination->IsSet.MigrationEnabled = TRUE;
    }
    if (Source->IsSet.DatagramReceiveEnabled && (!Destination->IsSet.DatagramReceiveEnabled || OverWrite)) {
        Destination->DatagramReceiveEnabled = Source->DatagramReceiveEnabled;
        Destination->IsSet.DatagramReceiveEnabled = TRUE;
    }
    if (Source->IsSet.MaxOperationsPerDrain && (!Destination->IsSet.MaxOperationsPerDrain || OverWrite)) {
        Destination->MaxOperationsPerDrain = Source->MaxOperationsPerDrain;
        Destination->IsSet.MaxOperationsPerDrain = TRUE;
    }
    if (Source->IsSet.RetryMemoryLimit && (!Destination->IsSet.RetryMemoryLimit || OverWrite)) {
        Destination->RetryMemoryLimit = Source->RetryMemoryLimit;
        Destination->IsSet.RetryMemoryLimit = TRUE;
    }
    if (Source->IsSet.LoadBalancingMode && (!Destination->IsSet.LoadBalancingMode || OverWrite)) {
        if (Source->LoadBalancingMode > QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            return FALSE;
        }
        Destination->LoadBalancingMode = Source->LoadBalancingMode;
        Destination->IsSet.LoadBalancingMode = TRUE;
    }
    if (Source->IsSet.MaxWorkerQueueDelayUs && (!Destination->IsSet.MaxWorkerQueueDelayUs || OverWrite)) {
        Destination->MaxWorkerQueueDelayUs = Source->MaxWorkerQueueDelayUs;
        Destination->IsSet.MaxWorkerQueueDelayUs = TRUE;
    }
    if (Source->IsSet.MaxStatelessOperations && (!Destination->IsSet.MaxStatelessOperations || OverWrite)) {
        Destination->MaxStatelessOperations = Source->MaxStatelessOperations;
        Destination->IsSet.MaxStatelessOperations = TRUE;
    }
    if (Source->IsSet.InitialWindowPackets && (!Destination->IsSet.InitialWindowPackets || OverWrite)) {
        Destination->InitialWindowPackets = Source->InitialWindowPackets;
        Destination->IsSet.InitialWindowPackets = TRUE;
    }
    if (Source->IsSet.SendIdleTimeoutMs && (!Destination->IsSet.SendIdleTimeoutMs || OverWrite)) {
        Destination->SendIdleTimeoutMs = Source->SendIdleTimeoutMs;
        Destination->IsSet.SendIdleTimeoutMs = TRUE;
    }
    if (Source->IsSet.InitialRttMs && (!Destination->IsSet.InitialRttMs || OverWrite)) {
        Destination->InitialRttMs = Source->InitialRttMs;
        Destination->IsSet.InitialRttMs = TRUE;
    }
    if (Source->IsSet.MaxAckDelayMs && (!Destination->IsSet.MaxAckDelayMs || OverWrite)) {
        if (Source->MaxAckDelayMs > QUIC_TP_MAX_ACK_DELAY_MAX) {
            return FALSE;
        }
        Destination->MaxAckDelayMs = Source->MaxAckDelayMs;
        Destination->IsSet.MaxAckDelayMs = TRUE;
    }
    if (Source->IsSet.DisconnectTimeoutMs && (!Destination->IsSet.DisconnectTimeoutMs || OverWrite)) {
        if (Source->DisconnectTimeoutMs > QUIC_MAX_DISCONNECT_TIMEOUT) {
            return FALSE;
        }
        Destination->DisconnectTimeoutMs = Source->DisconnectTimeoutMs;
        Destination->IsSet.DisconnectTimeoutMs = TRUE;
    }
    if (Source->IsSet.KeepAliveIntervalMs && (!Destination->IsSet.KeepAliveIntervalMs || OverWrite)) {
        Destination->KeepAliveIntervalMs = Source->KeepAliveIntervalMs;
        Destination->IsSet.KeepAliveIntervalMs = TRUE;
    }
    if (Source->IsSet.IdleTimeoutMs && (!Destination->IsSet.IdleTimeoutMs || OverWrite)) {
        if (Source->IdleTimeoutMs > QUIC_VAR_INT_MAX) {
            return FALSE;
        }
        Destination->IdleTimeoutMs = Source->IdleTimeoutMs;
        Destination->IsSet.IdleTimeoutMs = TRUE;
    }
    if (Source->IsSet.HandshakeIdleTimeoutMs && (!Destination->IsSet.HandshakeIdleTimeoutMs || OverWrite)) {
        if (Source->HandshakeIdleTimeoutMs > QUIC_VAR_INT_MAX) {
            return FALSE;
        }
        Destination->HandshakeIdleTimeoutMs = Source->HandshakeIdleTimeoutMs;
        Destination->IsSet.HandshakeIdleTimeoutMs = TRUE;
    }
    if (Source->IsSet.PeerBidiStreamCount && (!Destination->IsSet.PeerBidiStreamCount || OverWrite)) {
        Destination->PeerBidiStreamCount = Source->PeerBidiStreamCount;
        Destination->IsSet.PeerBidiStreamCount = TRUE;
    }
    if (Source->IsSet.PeerUnidiStreamCount && (!Destination->IsSet.PeerUnidiStreamCount || OverWrite)) {
        Destination->PeerUnidiStreamCount = Source->PeerUnidiStreamCount;
        Destination->IsSet.PeerUnidiStreamCount = TRUE;
    }
    if (Source->IsSet.TlsClientMaxSendBuffer && (!Destination->IsSet.TlsClientMaxSendBuffer || OverWrite)) {
        Destination->TlsClientMaxSendBuffer = Source->TlsClientMaxSendBuffer;
        Destination->IsSet.TlsClientMaxSendBuffer = TRUE;
    }
    if (Source->IsSet.TlsClientMaxSendBuffer && (!Destination->IsSet.TlsClientMaxSendBuffer || OverWrite)) {
        Destination->TlsClientMaxSendBuffer = Source->TlsClientMaxSendBuffer;
        Destination->IsSet.TlsClientMaxSendBuffer = TRUE;
    }
    if (Source->IsSet.StreamRecvWindowDefault && (!Destination->IsSet.StreamRecvWindowDefault || OverWrite)) {
        Destination->StreamRecvWindowDefault = Source->StreamRecvWindowDefault;
        Destination->IsSet.StreamRecvWindowDefault = TRUE;
    }
    if (Source->IsSet.StreamRecvBufferDefault && (!Destination->IsSet.StreamRecvBufferDefault || OverWrite)) {
        if (Source->StreamRecvBufferDefault < QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE) {
            return FALSE;
        }
        Destination->StreamRecvBufferDefault = Source->StreamRecvBufferDefault;
        Destination->IsSet.StreamRecvBufferDefault = TRUE;
    }
    if (Source->IsSet.ConnFlowControlWindow && (!Destination->IsSet.ConnFlowControlWindow || OverWrite)) {
        Destination->ConnFlowControlWindow = Source->ConnFlowControlWindow;
        Destination->IsSet.ConnFlowControlWindow = TRUE;
    }
    if (Source->IsSet.MaxBytesPerKey && (!Destination->IsSet.MaxBytesPerKey || OverWrite)) {
        if (Source->MaxBytesPerKey > QUIC_DEFAULT_MAX_BYTES_PER_KEY) {
            return FALSE;
        }
        Destination->MaxBytesPerKey = Source->MaxBytesPerKey;
        Destination->IsSet.MaxBytesPerKey = TRUE;
    }
    if (Source->IsSet.ServerResumptionLevel && (!Destination->IsSet.ServerResumptionLevel || OverWrite)) {
        if (Source->ServerResumptionLevel > QUIC_SERVER_RESUME_AND_ZERORTT) {
            return FALSE;
        }
        Destination->ServerResumptionLevel = Source->ServerResumptionLevel;
        Destination->IsSet.ServerResumptionLevel = TRUE;
    }
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ CXPLAT_STORAGE* Storage
    )
{
    uint32_t Value;
    union {
        uint32_t Half;
        uint64_t Full;
        uint8_t Array[sizeof(uint64_t)];
    } MultiValue;
    uint32_t ValueLen;

    if (!Settings->IsSet.SendBufferingEnabled) {
        Value = QUIC_DEFAULT_SEND_BUFFERING_ENABLE;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_BUFFERING_DEFAULT,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->SendBufferingEnabled = !!Value;
    }

    if (!Settings->IsSet.PacingEnabled) {
        Value = QUIC_DEFAULT_SEND_PACING;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_PACING_DEFAULT,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->PacingEnabled = !!Value;
    }

    if (!Settings->IsSet.MigrationEnabled) {
        Value = QUIC_DEFAULT_MIGRATION_ENABLED;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MIGRATION_ENABLED,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->MigrationEnabled = !!Value;
    }

    if (!Settings->IsSet.DatagramReceiveEnabled) {
        Value = QUIC_DEFAULT_DATAGRAM_RECEIVE_ENABLED;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_DATAGRAM_RECEIVE_ENABLED,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->DatagramReceiveEnabled = !!Value;
    }

    if (!Settings->IsSet.MaxOperationsPerDrain) {
        Value = QUIC_MAX_OPERATIONS_PER_DRAIN;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_WORKER_QUEUE_DELAY,
            (uint8_t*)&Value,                               // Read as ms
            &ValueLen);
        Settings->MaxWorkerQueueDelayUs = MS_TO_US(Value);  // Convert to us
    }

    if (!Settings->IsSet.MaxStatelessOperations) {
        ValueLen = sizeof(Settings->MaxStatelessOperations);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_STATELESS_OPERATIONS,
            (uint8_t*)&Settings->MaxStatelessOperations,
            &ValueLen);
    }

    if (!Settings->IsSet.InitialWindowPackets) {
        ValueLen = sizeof(Settings->InitialWindowPackets);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_INITIAL_WINDOW_PACKETS,
            (uint8_t*)&Settings->InitialWindowPackets,
            &ValueLen);
    }

    if (!Settings->IsSet.SendIdleTimeoutMs) {
        ValueLen = sizeof(Settings->SendIdleTimeoutMs);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_IDLE_TIMEOUT_MS,
            (uint8_t*)&Settings->SendIdleTimeoutMs,
            &ValueLen);
    }

    if (!Settings->IsSet.InitialRttMs) {
        ValueLen = sizeof(Settings->InitialRttMs);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_INITIAL_RTT,
            (uint8_t*)&Settings->InitialRttMs,
            &ValueLen);
    }

    if (!Settings->IsSet.MaxAckDelayMs) {
        ValueLen = sizeof(Settings->MaxAckDelayMs);
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_KEEP_ALIVE_INTERVAL,
            (uint8_t*)&Settings->KeepAliveIntervalMs,
            &ValueLen);
    }

    if (!Settings->IsSet.IdleTimeoutMs) {
        CXPLAT_STATIC_ASSERT(sizeof(MultiValue) == sizeof(Settings->IdleTimeoutMs), "These must be the same size");
        ValueLen = sizeof(MultiValue);
        if (QUIC_SUCCEEDED(
            CxPlatStorageReadValue(
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
        CXPLAT_STATIC_ASSERT(sizeof(MultiValue) == sizeof(Settings->HandshakeIdleTimeoutMs), "These must be the same size");
        ValueLen = sizeof(MultiValue);
        if (QUIC_SUCCEEDED(
            CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_TLS_CLIENT_SEND_BUFFER,
            (uint8_t*)&Settings->TlsClientMaxSendBuffer,
            &ValueLen);
    }

    if (!Settings->IsSet.TlsServerMaxSendBuffer) {
        ValueLen = sizeof(Settings->TlsServerMaxSendBuffer);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_TLS_SERVER_SEND_BUFFER,
            (uint8_t*)&Settings->TlsServerMaxSendBuffer,
            &ValueLen);
    }

    if (!Settings->IsSet.StreamRecvWindowDefault) {
        ValueLen = sizeof(Settings->StreamRecvWindowDefault);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_STREAM_FC_WINDOW_SIZE,
            (uint8_t*)&Settings->StreamRecvWindowDefault,
            &ValueLen);
    }

    if (!Settings->IsSet.StreamRecvBufferDefault) {
        ValueLen = sizeof(Settings->StreamRecvBufferDefault);
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_CONN_FLOW_CONTROL_WINDOW,
            (uint8_t*)&Settings->ConnFlowControlWindow,
            &ValueLen);
    }

    if (!Settings->IsSet.MaxBytesPerKey) {
        ValueLen = sizeof(Settings->MaxBytesPerKey);
        CxPlatStorageReadValue(
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
        CxPlatStorageReadValue(
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
    QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
    QuicTraceLogVerbose(SettingDumpPacingEnabled,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
    QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
    QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDumpNew(
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey), UINT32_MAX)
        uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_SETTINGS* Settings
    )
{
    UNREFERENCED_PARAMETER(SettingsSize); // TODO - Use when reading settings

    if (Settings->IsSet.SendBufferingEnabled) {
        QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
    }
    if (Settings->IsSet.PacingEnabled) {
        QuicTraceLogVerbose(SettingDumpPacingEnabled,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
    }
    if (Settings->IsSet.MigrationEnabled) {
        QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
    }
    if (Settings->IsSet.DatagramReceiveEnabled) {
        QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
    }
    if (Settings->IsSet.MaxOperationsPerDrain) {
        QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,   "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
    }
    if (Settings->IsSet.RetryMemoryLimit) {
        QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,        "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
    }
    if (Settings->IsSet.LoadBalancingMode) {
        QuicTraceLogVerbose(SettingDumpLoadBalancingMode,       "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
    }
    if (Settings->IsSet.MaxStatelessOperations) {
        QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,  "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
    }
    if (Settings->IsSet.MaxWorkerQueueDelayUs) {
        QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,   "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
    }
    if (Settings->IsSet.InitialWindowPackets) {
        QuicTraceLogVerbose(SettingDumpInitialWindowPackets,    "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
    }
    if (Settings->IsSet.SendIdleTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,       "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
    }
    if (Settings->IsSet.InitialRttMs) {
        QuicTraceLogVerbose(SettingDumpInitialRttMs,            "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
    }
    if (Settings->IsSet.MaxAckDelayMs) {
        QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,           "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
    }
    if (Settings->IsSet.DisconnectTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,     "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
    }
    if (Settings->IsSet.KeepAliveIntervalMs) {
        QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,     "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
    }
    if (Settings->IsSet.IdleTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,           "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
    }
    if (Settings->IsSet.HandshakeIdleTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,  "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
    }
    if (Settings->IsSet.PeerBidiStreamCount) {
        QuicTraceLogVerbose(SettingDumpBidiStreamCount,         "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
    }
    if (Settings->IsSet.PeerUnidiStreamCount) {
        QuicTraceLogVerbose(SettingDumpUnidiStreamCount,        "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
    }
    if (Settings->IsSet.TlsClientMaxSendBuffer) {
        QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,  "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
    }
    if (Settings->IsSet.TlsServerMaxSendBuffer) {
        QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,  "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
    }
    if (Settings->IsSet.StreamRecvWindowDefault) {
        QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault, "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
    }
    if (Settings->IsSet.StreamRecvBufferDefault) {
        QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault, "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
    }
    if (Settings->IsSet.ConnFlowControlWindow) {
        QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,   "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
    }
    if (Settings->IsSet.MaxBytesPerKey) {
        QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,          "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
    }
    if (Settings->IsSet.ServerResumptionLevel) {
        QuicTraceLogVerbose(SettingDumpServerResumptionLevel,   "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
    }
}
