/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Storage for all configurable values.

--*/

#include "precomp.h"

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
; //<-- WPP line was here
#include "settings.c.clog"

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
    if (!Settings->AppSet.HandshakeIdleTimeoutMs) {
        Settings->HandshakeIdleTimeoutMs = QUIC_DEFAULT_HANDSHAKE_IDLE_TIMEOUT;
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
    if (!Settings->AppSet.HandshakeIdleTimeoutMs) {
        Settings->HandshakeIdleTimeoutMs = ParentSettings->HandshakeIdleTimeoutMs;
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
        union {
            uint32_t Half;
            uint64_t Full;
            uint8_t Array[sizeof(uint64_t)];
        } TempIdleTimeoutMs;
        QUIC_STATIC_ASSERT(sizeof(TempIdleTimeoutMs) == sizeof(Settings->IdleTimeoutMs), "These must be the same size");
        ValueLen = sizeof(TempIdleTimeoutMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_IDLE_TIMEOUT,
            TempIdleTimeoutMs.Array,
            &ValueLen);
        if (ValueLen == sizeof(uint32_t)) {
            Settings->IdleTimeoutMs = TempIdleTimeoutMs.Half;
        } else {
            Settings->IdleTimeoutMs = TempIdleTimeoutMs.Full;
        }
        if (Settings->IdleTimeoutMs > QUIC_VAR_INT_MAX) {
            Settings->IdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
        }
    }

    if (!Settings->AppSet.HandshakeIdleTimeoutMs) {
        union {
            uint32_t Half;
            uint64_t Full;
            uint8_t Array[sizeof(uint64_t)];
        } TempHandshakeIdleTimeoutMs;
        QUIC_STATIC_ASSERT(sizeof(TempHandshakeIdleTimeoutMs) == sizeof(Settings->HandshakeIdleTimeoutMs), "These must be the same size");
        ValueLen = sizeof(TempHandshakeIdleTimeoutMs);
        QuicStorageReadValue(
            Storage,
            QUIC_SETTING_HANDSHAKE_IDLE_TIMEOUT,
            TempHandshakeIdleTimeoutMs.Array,
            &ValueLen);
        if (ValueLen == sizeof(uint32_t)) {
            Settings->HandshakeIdleTimeoutMs = TempHandshakeIdleTimeoutMs.Half;
        } else {
            Settings->HandshakeIdleTimeoutMs = TempHandshakeIdleTimeoutMs.Full;
        }
        if (Settings->HandshakeIdleTimeoutMs > QUIC_VAR_INT_MAX) {
            Settings->HandshakeIdleTimeoutMs = QUIC_DEFAULT_IDLE_TIMEOUT;
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
    QuicTraceLogVerbose(FN_settings6f5c7b4d47f2bc7a9a87c47495e915e4, "[sett] PacingDefault          = %hu",  (uint16_t)Settings->PacingDefault);
    QuicTraceLogVerbose(FN_settingsd554fffdc6a34a822c77617a980a7725, "[sett] MaxPartitionCount      = %hu",  (uint16_t)Settings->MaxPartitionCount);
    QuicTraceLogVerbose(FN_settingscf1a37abdccf8f36fdbf32977e7fb7df, "[sett] MaxOperationsPerDrain  = %hu",  (uint16_t)Settings->MaxOperationsPerDrain);
    QuicTraceLogVerbose(FN_settings00fc7276f8b662d358928e0cfa29d043, "[sett] RetryMemoryLimit       = %hu",  Settings->RetryMemoryLimit);
    QuicTraceLogVerbose(FN_settings67321e2160737fdc324fb42093dae824, "[sett] MaxStatelessOperations = %u",  Settings->MaxStatelessOperations);
    QuicTraceLogVerbose(FN_settings51f359ba6d2ceb8234f9cb01656763be, "[sett] MaxWorkerQueueDelayUs  = %u",  Settings->MaxWorkerQueueDelayUs);
    QuicTraceLogVerbose(FN_settingsb6cd3a0efb5f8db608f7fa16f6957ce0, "[sett] InitialWindowPackets   = %u",  Settings->InitialWindowPackets);
    QuicTraceLogVerbose(FN_settingsb89c8661c5b265e52f8c7e86e8087bb9, "[sett] SendIdleTimeoutMs      = %u",  Settings->SendIdleTimeoutMs);
    QuicTraceLogVerbose(FN_settingsdaa0f1e26a1af17445c7f77ce8551492, "[sett] InitialRttMs           = %u",  Settings->InitialRttMs);
    QuicTraceLogVerbose(FN_settingse675344097e6f9bb84e4d03d8ff9be4d, "[sett] MaxAckDelayMs          = %u",  Settings->MaxAckDelayMs);
    QuicTraceLogVerbose(FN_settings9e7a532745dc4d5567af3a575f923bac, "[sett] DisconnectTimeoutMs    = %u",  Settings->DisconnectTimeoutMs);
    QuicTraceLogVerbose(FN_settings5d12e260586f0be6c4f808dffe30d4a7, "[sett] KeepAliveIntervalMs    = %u",  Settings->KeepAliveIntervalMs);
    QuicTraceLogVerbose(FN_settingsb475e10d0ff099b06516e8abcb4f19c7, "[sett] IdleTimeoutMs          = %llu",  Settings->IdleTimeoutMs);
    QuicTraceLogVerbose(FN_settings33c9f29607d015655c8702e9cc5d8abb, "[sett] BidiStreamCount        = %hu",  Settings->BidiStreamCount);
    QuicTraceLogVerbose(FN_settings999de952663364f4ed3605c26a59794d, "[sett] UnidiStreamCount       = %hu",  Settings->UnidiStreamCount);
    QuicTraceLogVerbose(FN_settings618acfc75c83815ce1c13227574b9897, "[sett] TlsClientMaxSendBuffer = %u",  Settings->TlsClientMaxSendBuffer);
    QuicTraceLogVerbose(FN_settings2ca7254aa7cbdd713e9eed68144800b6, "[sett] TlsServerMaxSendBuffer = %u",  Settings->TlsServerMaxSendBuffer);
    QuicTraceLogVerbose(FN_settings9dab7b65b7e848389e5cdb2edbed3210, "[sett] StreamRecvWindowDefault= %u",  Settings->StreamRecvWindowDefault);
    QuicTraceLogVerbose(FN_settings1bb0aabcd202e8b720f4bdaaf5435eb5, "[sett] StreamRecvBufferDefault= %u",  Settings->StreamRecvBufferDefault);
    QuicTraceLogVerbose(FN_settings449b02f5fe7c5e954963dbab7ca016aa, "[sett] ConnFlowControlWindow  = %u",  Settings->ConnFlowControlWindow);
    QuicTraceLogVerbose(FN_settings01739e9f48d20100fa4147ba2385f8eb, "[sett] MaxBytesPerKey         = %llu",  Settings->MaxBytesPerKey);
}
