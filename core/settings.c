/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Storage for all configurable values.

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "settings.tmh"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsSetDefault(
    _Inout_ QUIC_SETTINGS* Settings
    )
{
    if (!Settings->AppSet.PacingDefault) {
        Settings->PacingDefault = QUIC_DEFAULT_SEND_PACING;
    }
    if (!Settings->AppSet.MaxPartitionCount) {
        Settings->MaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
    }
    if (!Settings->AppSet.MaxOperationsPerDrain) {
        Settings->MaxOperationsPerDrain = QUIC_MAX_OPERATIONS_PER_DRAIN;
    }
    if (!Settings->AppSet.RetryMemoryLimit) {
        Settings->RetryMemoryLimit = QUIC_DEFAULT_RETRY_MEMORY_FRACTION;
    }
    if (!Settings->AppSet.MaxWorkerQueueDelayUs) {
        Settings->MaxWorkerQueueDelayUs = MS_TO_US(QUIC_MAX_WORKER_QUEUE_DELAY);
    }
    if (!Settings->AppSet.MaxStatelessOperations) {
        Settings->MaxStatelessOperations = QUIC_MAX_STATELESS_OPERATIONS;
    }
    if (!Settings->AppSet.InitialWindowPackets) {
        Settings->InitialWindowPackets = QUIC_INITIAL_WINDOW_PACKETS;
    }
    if (!Settings->AppSet.SendIdleTimeoutMs) {
        Settings->SendIdleTimeoutMs = QUIC_DEFAULT_SEND_IDLE_TIMEOUT_MS;
    }
    if (!Settings->AppSet.InitialRttMs) {
        Settings->InitialRttMs = QUIC_INITIAL_RTT;
    }
    if (!Settings->AppSet.MaxAckDelayMs) {
        Settings->MaxAckDelayMs = QUIC_TP_MAX_ACK_DELAY_DEFAULT;
    }
    if (!Settings->AppSet.DisconnectTimeoutMs) {
        Settings->DisconnectTimeoutMs = QUIC_DEFAULT_DISCONNECT_TIMEOUT;
    }
    if (!Settings->AppSet.KeepAliveIntervalMs) {
        Settings->KeepAliveIntervalMs = QUIC_DEFAULT_KEEP_ALIVE_INTERVAL;
    }
    if (!Settings->AppSet.IdleTimeoutMs) {
        Settings->IdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
    }
    if (!Settings->AppSet.BidiStreamCount) {
        Settings->BidiStreamCount = 0;
    }
    if (!Settings->AppSet.UnidiStreamCount) {
        Settings->UnidiStreamCount = 0;
    }
    if (!Settings->AppSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = QUIC_MAX_TLS_CLIENT_SEND_BUFFER;
    }
    if (!Settings->AppSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = QUIC_MAX_TLS_SERVER_SEND_BUFFER;
    }
    if (!Settings->AppSet.StreamRecvWindowDefault) {
        Settings->StreamRecvWindowDefault = QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE;
    }
    if (!Settings->AppSet.StreamRecvBufferDefault) {
        Settings->StreamRecvBufferDefault = QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE;
    }
    if (!Settings->AppSet.ConnFlowControlWindow) {
        Settings->ConnFlowControlWindow = QUIC_DEFAULT_CONN_FLOW_CONTROL_WINDOW;
    }
    if (!Settings->AppSet.MaxBytesPerKey) {
        Settings->MaxBytesPerKey = QUIC_DEFAULT_MAX_BYTES_PER_KEY;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCopy(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ const QUIC_SETTINGS* ParentSettings
    )
{
    if (!Settings->AppSet.PacingDefault) {
        Settings->PacingDefault = ParentSettings->PacingDefault;
    }
    if (!Settings->AppSet.MaxPartitionCount) {
        Settings->MaxPartitionCount = ParentSettings->MaxPartitionCount;
    }
    if (!Settings->AppSet.MaxOperationsPerDrain) {
        Settings->MaxOperationsPerDrain = ParentSettings->MaxOperationsPerDrain;
    }
    if (!Settings->AppSet.RetryMemoryLimit) {
        Settings->RetryMemoryLimit = ParentSettings->RetryMemoryLimit;
    }
    if (!Settings->AppSet.MaxWorkerQueueDelayUs) {
        Settings->MaxWorkerQueueDelayUs = ParentSettings->MaxWorkerQueueDelayUs;
    }
    if (!Settings->AppSet.MaxStatelessOperations) {
        Settings->MaxStatelessOperations = ParentSettings->MaxStatelessOperations;
    }
    if (!Settings->AppSet.InitialWindowPackets) {
        Settings->InitialWindowPackets = ParentSettings->InitialWindowPackets;
    }
    if (!Settings->AppSet.SendIdleTimeoutMs) {
        Settings->SendIdleTimeoutMs = ParentSettings->SendIdleTimeoutMs;
    }
    if (!Settings->AppSet.InitialRttMs) {
        Settings->InitialRttMs = ParentSettings->InitialRttMs;
    }
    if (!Settings->AppSet.MaxAckDelayMs) {
        Settings->MaxAckDelayMs = ParentSettings->MaxAckDelayMs;
    }
    if (!Settings->AppSet.DisconnectTimeoutMs) {
        Settings->DisconnectTimeoutMs = ParentSettings->DisconnectTimeoutMs;
    }
    if (!Settings->AppSet.KeepAliveIntervalMs) {
        Settings->KeepAliveIntervalMs = ParentSettings->KeepAliveIntervalMs;
    }
    if (!Settings->AppSet.IdleTimeoutMs) {
        Settings->IdleTimeoutMs = ParentSettings->IdleTimeoutMs;
    }
    if (!Settings->AppSet.BidiStreamCount) {
        Settings->BidiStreamCount = ParentSettings->BidiStreamCount;
    }
    if (!Settings->AppSet.UnidiStreamCount) {
        Settings->UnidiStreamCount = ParentSettings->UnidiStreamCount;
    }
    if (!Settings->AppSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = ParentSettings->TlsClientMaxSendBuffer;
    }
    if (!Settings->AppSet.TlsClientMaxSendBuffer) {
        Settings->TlsClientMaxSendBuffer = ParentSettings->TlsClientMaxSendBuffer;
    }
    if (!Settings->AppSet.StreamRecvWindowDefault) {
        Settings->StreamRecvWindowDefault = ParentSettings->StreamRecvWindowDefault;
    }
    if (!Settings->AppSet.StreamRecvBufferDefault) {
        Settings->StreamRecvBufferDefault = ParentSettings->StreamRecvBufferDefault;
    }
    if (!Settings->AppSet.ConnFlowControlWindow) {
        Settings->ConnFlowControlWindow = ParentSettings->ConnFlowControlWindow;
    }
    if (!Settings->AppSet.MaxBytesPerKey) {
        Settings->MaxBytesPerKey = ParentSettings->MaxBytesPerKey;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ QUIC_STORAGE* Storage
    )
{
    uint32_t Value;
    uint32_t ValueLen;

    if (!Settings->AppSet.PacingDefault) {
        Value = QUIC_DEFAULT_SEND_PACING;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_PACING_DEFAULT,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->PacingDefault = !!Value;
    }

    if (!Settings->AppSet.MaxPartitionCount) {
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

    if (!Settings->AppSet.MaxOperationsPerDrain) {
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

    if (!Settings->AppSet.RetryMemoryLimit) {
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

    if (!Settings->AppSet.MaxWorkerQueueDelayUs) {
        Value = QUIC_MAX_WORKER_QUEUE_DELAY;
        ValueLen = sizeof(Value);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_WORKER_QUEUE_DELAY,
            (uint8_t*)&Value,                               // Read as ms
            &ValueLen);
        Settings->MaxWorkerQueueDelayUs = MS_TO_US(Value);  // Convert to us
    }

    if (!Settings->AppSet.MaxStatelessOperations) {
        ValueLen = sizeof(Settings->MaxStatelessOperations);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_STATELESS_OPERATIONS,
            (uint8_t*)&Settings->MaxStatelessOperations,
            &ValueLen);
    }

    if (!Settings->AppSet.InitialWindowPackets) {
        ValueLen = sizeof(Settings->InitialWindowPackets);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_INITIAL_WINDOW_PACKETS,
            (uint8_t*)&Settings->InitialWindowPackets,
            &ValueLen);
    }

    if (!Settings->AppSet.SendIdleTimeoutMs) {
        ValueLen = sizeof(Settings->SendIdleTimeoutMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_SEND_IDLE_TIMEOUT_MS,
            (uint8_t*)&Settings->SendIdleTimeoutMs,
            &ValueLen);
    }

    if (!Settings->AppSet.InitialRttMs) {
        ValueLen = sizeof(Settings->InitialRttMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_INITIAL_RTT,
            (uint8_t*)&Settings->InitialRttMs,
            &ValueLen);
    }

    if (!Settings->AppSet.MaxAckDelayMs) {
        ValueLen = sizeof(Settings->MaxAckDelayMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_ACK_DELAY,
            (uint8_t*)&Settings->MaxAckDelayMs,
            &ValueLen);
        if (Settings->MaxAckDelayMs > QUIC_TP_MAX_MAX_ACK_DELAY) {
            Settings->MaxAckDelayMs = QUIC_TP_MAX_ACK_DELAY_DEFAULT;
        }
    }

    if (!Settings->AppSet.DisconnectTimeoutMs) {
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

    if (!Settings->AppSet.KeepAliveIntervalMs) {
        ValueLen = sizeof(Settings->KeepAliveIntervalMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_KEEP_ALIVE_INTERVAL,
            (uint8_t*)&Settings->KeepAliveIntervalMs,
            &ValueLen);
    }

    if (!Settings->AppSet.IdleTimeoutMs) {
        ValueLen = sizeof(Settings->IdleTimeoutMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_IDLE_TIMEOUT,
            (uint8_t*)&Settings->IdleTimeoutMs,
            &ValueLen);
        if (ValueLen == sizeof(uint32_t)) {
            Settings->IdleTimeoutMs = *(uint32_t*)&Settings->IdleTimeoutMs;
        }
        if (Settings->IdleTimeoutMs > QUIC_VAR_INT_MAX) {
            Settings->IdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
        }
    }

    if (!Settings->AppSet.TlsClientMaxSendBuffer) {
        ValueLen = sizeof(Settings->TlsClientMaxSendBuffer);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_TLS_CLIENT_SEND_BUFFER,
            (uint8_t*)&Settings->TlsClientMaxSendBuffer,
            &ValueLen);
    }

    if (!Settings->AppSet.TlsServerMaxSendBuffer) {
        ValueLen = sizeof(Settings->TlsServerMaxSendBuffer);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_TLS_SERVER_SEND_BUFFER,
            (uint8_t*)&Settings->TlsServerMaxSendBuffer,
            &ValueLen);
    }

    if (!Settings->AppSet.StreamRecvWindowDefault) {
        ValueLen = sizeof(Settings->StreamRecvWindowDefault);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_STREAM_FC_WINDOW_SIZE,
            (uint8_t*)&Settings->StreamRecvWindowDefault,
            &ValueLen);
    }

    if (!Settings->AppSet.StreamRecvBufferDefault) {
        ValueLen = sizeof(Settings->StreamRecvBufferDefault);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_STREAM_RECV_BUFFER_SIZE,
            (uint8_t*)&Settings->StreamRecvBufferDefault,
            &ValueLen);
    }

    if (!Settings->AppSet.ConnFlowControlWindow) {
        ValueLen = sizeof(Settings->ConnFlowControlWindow);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_CONN_FLOW_CONTROL_WINDOW,
            (uint8_t*)&Settings->ConnFlowControlWindow,
            &ValueLen);
    }

    if (!Settings->AppSet.MaxBytesPerKey) {
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
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDump(
    _In_ const QUIC_SETTINGS* Settings
    )
{
    LogVerbose("[sett] PacingDefault          = %hu", (uint16_t)Settings->PacingDefault);
    LogVerbose("[sett] MaxPartitionCount      = %hu", (uint16_t)Settings->MaxPartitionCount);
    LogVerbose("[sett] MaxOperationsPerDrain  = %hu", (uint16_t)Settings->MaxOperationsPerDrain);
    LogVerbose("[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
    LogVerbose("[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
    LogVerbose("[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
    LogVerbose("[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
    LogVerbose("[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
    LogVerbose("[sett] InitialRttMs           = %u", Settings->InitialRttMs);
    LogVerbose("[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
    LogVerbose("[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
    LogVerbose("[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
    LogVerbose("[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
    LogVerbose("[sett] BidiStreamCount        = %hu", Settings->BidiStreamCount);
    LogVerbose("[sett] UnidiStreamCount       = %hu", Settings->UnidiStreamCount);
    LogVerbose("[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
    LogVerbose("[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
    LogVerbose("[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
    LogVerbose("[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
    LogVerbose("[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
    LogVerbose("[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
}
