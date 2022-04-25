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
QUIC_VERSION_SETTINGS*
QuicSettingsCopyVersionSettings(
    _In_ const QUIC_VERSION_SETTINGS* const Source,
    _In_ BOOLEAN CopyExternalToInternal
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsSetDefault(
    _Inout_ QUIC_SETTINGS_INTERNAL* Settings
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
        Settings->ServerResumptionLevel = (uint8_t)QUIC_DEFAULT_SERVER_RESUMPTION_LEVEL;
    }
    if (!Settings->IsSet.VersionNegotiationExtEnabled) {
        Settings->VersionNegotiationExtEnabled = QUIC_DEFAULT_VERSION_NEGOTIATION_EXT_ENABLED;
    }
    if (!Settings->IsSet.MinimumMtu) {
        Settings->MinimumMtu = QUIC_DPLPMUTD_DEFAULT_MIN_MTU;
    }
    if (!Settings->IsSet.MaximumMtu) {
        Settings->MaximumMtu = QUIC_DPLPMUTD_DEFAULT_MAX_MTU;
    }
    if (!Settings->IsSet.MtuDiscoveryMissingProbeCount) {
        Settings->MtuDiscoveryMissingProbeCount = QUIC_DPLPMTUD_MAX_PROBES;
    }
    if (!Settings->IsSet.MtuDiscoverySearchCompleteTimeoutUs) {
        Settings->MtuDiscoverySearchCompleteTimeoutUs = QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT;
    }
    if (!Settings->IsSet.MaxBindingStatelessOperations) {
        Settings->MaxBindingStatelessOperations = QUIC_MAX_BINDING_STATELESS_OPERATIONS;
    }
    if (!Settings->IsSet.StatelessOperationExpirationMs) {
        Settings->StatelessOperationExpirationMs = QUIC_STATELESS_OPERATION_EXPIRATION_MS;
    }
    if (!Settings->IsSet.CongestionControlAlgorithm) {
        Settings->CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_DEFAULT;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCopy(
    _Inout_ QUIC_SETTINGS_INTERNAL* Destination,
    _In_ const QUIC_SETTINGS_INTERNAL* Source
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
    if (!Destination->IsSet.VersionNegotiationExtEnabled) {
        Destination->VersionNegotiationExtEnabled = Source->VersionNegotiationExtEnabled;
    }
    if (!Destination->IsSet.VersionSettings) {
        if (Destination->VersionSettings) {
            CXPLAT_FREE(Destination->VersionSettings, QUIC_POOL_VERSION_SETTINGS);
            Destination->VersionSettings = NULL;
        }
        if (Source->VersionSettings != NULL) {
            Destination->VersionSettings =
                QuicSettingsCopyVersionSettings(Source->VersionSettings, FALSE);
        }
    }

    if (!Destination->IsSet.MinimumMtu && !Destination->IsSet.MaximumMtu) {
        Destination->MinimumMtu = Source->MinimumMtu;
        Destination->MaximumMtu = Source->MaximumMtu;
    } else if (Destination->IsSet.MinimumMtu && !Destination->IsSet.MaximumMtu) {
        if (Source->MaximumMtu > Destination->MinimumMtu) {
            Destination->MaximumMtu = Source->MaximumMtu;
        }
    } else if (Destination->IsSet.MaximumMtu && !Destination->IsSet.MinimumMtu) {
        if (Source->MinimumMtu < Destination->MaximumMtu) {
            Destination->MinimumMtu = Source->MinimumMtu;
        }
    }

    if (!Destination->IsSet.MtuDiscoveryMissingProbeCount) {
        Destination->MtuDiscoveryMissingProbeCount = Source->MtuDiscoveryMissingProbeCount;
    }
    if (!Destination->IsSet.MtuDiscoverySearchCompleteTimeoutUs) {
        Destination->MtuDiscoverySearchCompleteTimeoutUs = Source->MtuDiscoverySearchCompleteTimeoutUs;
    }
    if (!Destination->IsSet.MaxBindingStatelessOperations) {
        Destination->MaxBindingStatelessOperations = Source->MaxBindingStatelessOperations;
    }
    if (!Destination->IsSet.StatelessOperationExpirationMs) {
        Destination->StatelessOperationExpirationMs = Source->StatelessOperationExpirationMs;
    }
    if (!Destination->IsSet.CongestionControlAlgorithm) {
        Destination->CongestionControlAlgorithm = Source->CongestionControlAlgorithm;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_VERSION_SETTINGS*
QuicSettingsCopyVersionSettings(
    _In_ const QUIC_VERSION_SETTINGS* const Source,
    _In_ BOOLEAN CopyExternalToInternal
    )
{
    QUIC_VERSION_SETTINGS* Destination = NULL;
    size_t AllocSize =
        sizeof(*Destination) +
        (Source->AcceptableVersionsLength * sizeof(uint32_t)) +
        (Source->OfferedVersionsLength * sizeof(uint32_t)) +
        (Source->FullyDeployedVersionsLength * sizeof(uint32_t));
    Destination =
        CXPLAT_ALLOC_NONPAGED(
            AllocSize,
            QUIC_POOL_VERSION_SETTINGS);
    if (Destination == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "VersionSettings",
            AllocSize);
        return Destination;
    }
    Destination->AcceptableVersions = (uint32_t*)(Destination + 1);
    Destination->AcceptableVersionsLength = Source->AcceptableVersionsLength;
    CxPlatCopyMemory(
        Destination->AcceptableVersions,
        Source->AcceptableVersions,
        Destination->AcceptableVersionsLength * sizeof(uint32_t));

    Destination->OfferedVersions =
        Destination->AcceptableVersions + Destination->AcceptableVersionsLength;
    Destination->OfferedVersionsLength = Source->OfferedVersionsLength;
    CxPlatCopyMemory(
        Destination->OfferedVersions,
        Source->OfferedVersions,
        Destination->OfferedVersionsLength * sizeof(uint32_t));

    Destination->FullyDeployedVersions =
        Destination->OfferedVersions + Destination->OfferedVersionsLength;
    Destination->FullyDeployedVersionsLength = Source->FullyDeployedVersionsLength;
    CxPlatCopyMemory(
        Destination->FullyDeployedVersions,
        Source->FullyDeployedVersions,
        Destination->FullyDeployedVersionsLength * sizeof(uint32_t));

    if (CopyExternalToInternal) {
        //
        // This assumes the external is always in little-endian format
        //
        for (uint32_t i = 0; i < Destination->AcceptableVersionsLength; ++i) {
            Destination->AcceptableVersions[i] = CxPlatByteSwapUint32(Destination->AcceptableVersions[i]);
        }
        for (uint32_t i = 0; i < Destination->OfferedVersionsLength; ++i) {
            Destination->OfferedVersions[i] = CxPlatByteSwapUint32(Destination->OfferedVersions[i]);
        }
        for (uint32_t i = 0; i < Destination->FullyDeployedVersionsLength; ++i) {
            Destination->FullyDeployedVersions[i] = CxPlatByteSwapUint32(Destination->FullyDeployedVersions[i]);
        }
    }

    return Destination;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSettingApply(
    _Inout_ QUIC_SETTINGS_INTERNAL* Destination,
    _In_ BOOLEAN OverWrite,
    _In_ BOOLEAN AllowMtuChanges,
    _In_reads_bytes_(sizeof(QUIC_SETTINGS_INTERNAL))
        const QUIC_SETTINGS_INTERNAL* Source
    )
{
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
    if (Source->IsSet.VersionNegotiationExtEnabled && (!Destination->IsSet.VersionNegotiationExtEnabled || OverWrite)) {
        Destination->VersionNegotiationExtEnabled = Source->VersionNegotiationExtEnabled;
        Destination->IsSet.VersionNegotiationExtEnabled = TRUE;
    }

    if (Source->IsSet.VersionSettings) {
        if ((Destination->IsSet.VersionSettings && OverWrite) ||
            (!Destination->IsSet.VersionSettings && Destination->VersionSettings != NULL)) {
            CXPLAT_FREE(Destination->VersionSettings, QUIC_POOL_VERSION_SETTINGS);
            Destination->VersionSettings = NULL;
            Destination->IsSet.VersionSettings = FALSE;
        }
        if (!Destination->IsSet.VersionSettings && Source->VersionSettings != NULL) {
            Destination->VersionSettings =
                QuicSettingsCopyVersionSettings(Source->VersionSettings, FALSE);
            if (Destination->VersionSettings == NULL) {
                return FALSE;
            }

            Destination->IsSet.VersionSettings = TRUE;
        }
    }

    if (AllowMtuChanges) {
        uint16_t MinimumMtu =
            Destination->IsSet.MinimumMtu ? Destination->MinimumMtu : QUIC_DPLPMUTD_MIN_MTU;
        uint16_t MaximumMtu =
            Destination->IsSet.MaximumMtu ? Destination->MaximumMtu : CXPLAT_MAX_MTU;
        if (Source->IsSet.MinimumMtu && (!Destination->IsSet.MinimumMtu || OverWrite)) {
            MinimumMtu = Source->MinimumMtu;
            if (MinimumMtu < QUIC_DPLPMUTD_MIN_MTU) {
                MinimumMtu = QUIC_DPLPMUTD_MIN_MTU;
            } else if (MinimumMtu > CXPLAT_MAX_MTU) {
                MinimumMtu = CXPLAT_MAX_MTU;
            }
        }
        if (Source->IsSet.MaximumMtu && (!Destination->IsSet.MaximumMtu || OverWrite)) {
            MaximumMtu = Source->MaximumMtu;
            if (MaximumMtu < QUIC_DPLPMUTD_MIN_MTU) {
                MaximumMtu = QUIC_DPLPMUTD_MIN_MTU;
            } else if (MaximumMtu > CXPLAT_MAX_MTU) {
                MaximumMtu = CXPLAT_MAX_MTU;
            }
        }
        if (MinimumMtu > MaximumMtu) {
            return FALSE;
        }
        if (Source->IsSet.MinimumMtu) {
            Destination->IsSet.MinimumMtu = TRUE;
        }
        if (Source->IsSet.MaximumMtu) {
            Destination->IsSet.MaximumMtu = TRUE;
        }
        Destination->MinimumMtu = MinimumMtu;
        Destination->MaximumMtu = MaximumMtu;
    } else if (Source->IsSet.MinimumMtu || Source->IsSet.MaximumMtu) {
        return FALSE;
    }

    if (Source->IsSet.MtuDiscoverySearchCompleteTimeoutUs && (!Destination->IsSet.MtuDiscoverySearchCompleteTimeoutUs || OverWrite)) {
        Destination->MtuDiscoverySearchCompleteTimeoutUs = Source->MtuDiscoverySearchCompleteTimeoutUs;
        Destination->IsSet.MtuDiscoverySearchCompleteTimeoutUs = TRUE;
    }
    if (Source->IsSet.MtuDiscoveryMissingProbeCount && (!Destination->IsSet.MtuDiscoveryMissingProbeCount || OverWrite)) {
        Destination->MtuDiscoveryMissingProbeCount = Source->MtuDiscoveryMissingProbeCount;
        Destination->IsSet.MtuDiscoveryMissingProbeCount = TRUE;
    }

    if (Source->IsSet.MaxBindingStatelessOperations && (!Destination->IsSet.MaxBindingStatelessOperations || OverWrite)) {
        Destination->MaxBindingStatelessOperations = Source->MaxBindingStatelessOperations;
        Destination->IsSet.MaxBindingStatelessOperations = TRUE;
    }
    if (Source->IsSet.StatelessOperationExpirationMs && (!Destination->IsSet.StatelessOperationExpirationMs || OverWrite)) {
        Destination->StatelessOperationExpirationMs = Source->StatelessOperationExpirationMs;
        Destination->IsSet.StatelessOperationExpirationMs = TRUE;
    }

    if (Source->IsSet.CongestionControlAlgorithm && (!Destination->IsSet.CongestionControlAlgorithm || OverWrite)) {
        Destination->CongestionControlAlgorithm = Source->CongestionControlAlgorithm;
        Destination->IsSet.CongestionControlAlgorithm = TRUE;
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCleanup(
    _In_ QUIC_SETTINGS_INTERNAL* Settings
    )
{
    if (Settings->VersionSettings) {
        CXPLAT_FREE(Settings->VersionSettings, QUIC_POOL_VERSION_SETTINGS);
        Settings->VersionSettings = NULL;
        Settings->IsSet.VersionSettings = FALSE;
    }
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS_INTERNAL* Settings,
    _In_ CXPLAT_STORAGE* Storage
    )
{
    uint32_t Value;
    union {
        uint32_t Half;
        uint64_t Full;
        uint8_t Array[sizeof(uint64_t)];
    } MultiValue = {0};
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
        if (QUIC_SUCCEEDED(
            CxPlatStorageReadValue(
                Storage,
                QUIC_SETTING_SERVER_RESUMPTION_LEVEL,
                (uint8_t*)&Value,
                &ValueLen)) &&
            Value <= QUIC_SERVER_RESUME_AND_ZERORTT) {
            Settings->ServerResumptionLevel = (uint8_t)Value;
        }
    }

    if (!Settings->IsSet.VersionNegotiationExtEnabled) {
        Value = QUIC_DEFAULT_VERSION_NEGOTIATION_EXT_ENABLED;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_VERSION_NEGOTIATION_EXT_ENABLE,
            (uint8_t*)&Value,
            &ValueLen);
        Settings->VersionNegotiationExtEnabled = !!Value;
    }

    uint16_t MinimumMtu = Settings->MinimumMtu;
    uint16_t MaximumMtu = Settings->MaximumMtu;
    if (!Settings->IsSet.MinimumMtu) {
        ValueLen = sizeof(MinimumMtu);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MINIMUM_MTU,
            (uint8_t*)&MinimumMtu,
            &ValueLen);
    }
    if (!Settings->IsSet.MaximumMtu) {
        ValueLen = sizeof(MaximumMtu);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MAXIMUM_MTU,
            (uint8_t*)&MaximumMtu,
            &ValueLen);
    }
    if (MaximumMtu > CXPLAT_MAX_MTU) {
        MaximumMtu = CXPLAT_MAX_MTU;
    } else if (MaximumMtu < QUIC_DPLPMUTD_MIN_MTU) {
        MaximumMtu = QUIC_DPLPMUTD_MIN_MTU;
    }
    if (MinimumMtu > CXPLAT_MAX_MTU) {
        MinimumMtu = CXPLAT_MAX_MTU;
    } else if (MinimumMtu < QUIC_DPLPMUTD_MIN_MTU) {
        MinimumMtu = QUIC_DPLPMUTD_MIN_MTU;
    }
    if (MinimumMtu <= MaximumMtu) {
        Settings->MaximumMtu = MaximumMtu;
        Settings->MinimumMtu = MinimumMtu;
    }
    if (!Settings->IsSet.MtuDiscoveryMissingProbeCount) {
        ValueLen = sizeof(Settings->MtuDiscoveryMissingProbeCount);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MTU_MISSING_PROBE_COUNT,
            &Settings->MtuDiscoveryMissingProbeCount,
            &ValueLen);
    }
    if (!Settings->IsSet.MtuDiscoverySearchCompleteTimeoutUs) {
        ValueLen = sizeof(Settings->MtuDiscoverySearchCompleteTimeoutUs);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MTU_SEARCH_COMPLETE_TIMEOUT,
            (uint8_t*)&Settings->MtuDiscoverySearchCompleteTimeoutUs,
            &ValueLen);
    }
    if (!Settings->IsSet.MaxBindingStatelessOperations) {
        Value = QUIC_MAX_BINDING_STATELESS_OPERATIONS;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_MAX_BINDING_STATELESS_OPERATIONS,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value < UINT16_MAX) {
            Settings->MaxBindingStatelessOperations = (uint16_t)Value;
        }
    }
    if (!Settings->IsSet.StatelessOperationExpirationMs) {
        Value = QUIC_STATELESS_OPERATION_EXPIRATION_MS;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_STATELESS_OPERATION_EXPIRATION,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value < UINT16_MAX) {
            Settings->StatelessOperationExpirationMs = (uint16_t)Value;
        }
    }
    if (!Settings->IsSet.CongestionControlAlgorithm) {
        Value = QUIC_CONGESTION_CONTROL_ALGORITHM_DEFAULT;
        ValueLen = sizeof(Value);
        CxPlatStorageReadValue(
            Storage,
            QUIC_SETTING_CONGESTION_CONTROL_ALGORITHM,
            (uint8_t*)&Value,
            &ValueLen);
        if (Value < QUIC_CONGESTION_CONTROL_ALGORITHM_MAX) {
            Settings->CongestionControlAlgorithm = (QUIC_CONGESTION_CONTROL_ALGORITHM)Value;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDump(
    _In_reads_bytes_(sizeof(QUIC_SETTINGS_INTERNAL))
        const QUIC_SETTINGS_INTERNAL* Settings
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
    QuicTraceLogVerbose(SettingDumpVersionNegoExtEnabled,   "[sett] Version Negotiation Ext Enabled = %hhu", Settings->VersionNegotiationExtEnabled);
    QuicTraceLogVerbose(SettingDumpMinimumMtu,              "[sett] MinimumMtu             = %hu", Settings->MinimumMtu);
    QuicTraceLogVerbose(SettingDumpMaximumMtu,              "[sett] MaximumMtu             = %hu", Settings->MaximumMtu);
    QuicTraceLogVerbose(SettingDumpMtuCompleteTimeout,      "[sett] MtuCompleteTimeout     = %llu", Settings->MtuDiscoverySearchCompleteTimeoutUs);
    QuicTraceLogVerbose(SettingDumpMtuMissingProbeCount,    "[sett] MtuMissingProbeCount   = %hhu", Settings->MtuDiscoveryMissingProbeCount);
    QuicTraceLogVerbose(SettingDumpMaxBindingStatelessOper, "[sett] MaxBindingStatelessOper= %hu", Settings->MaxBindingStatelessOperations);
    QuicTraceLogVerbose(SettingDumpStatelessOperExpirMs,    "[sett] StatelessOperExpirMs   = %hu", Settings->StatelessOperationExpirationMs);
    QuicTraceLogVerbose(SettingCongestionControlAlgorithm,  "[sett] CongestionControlAlgorithm = %hu", Settings->CongestionControlAlgorithm);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDumpNew(
    _In_reads_bytes_(sizeof(QUIC_SETTINGS_INTERNAL))
        const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    if (Settings->IsSet.SendBufferingEnabled) {
        QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,        "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
    }
    if (Settings->IsSet.PacingEnabled) {
        QuicTraceLogVerbose(SettingDumpPacingEnabled,               "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
    }
    if (Settings->IsSet.MigrationEnabled) {
        QuicTraceLogVerbose(SettingDumpMigrationEnabled,            "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
    }
    if (Settings->IsSet.DatagramReceiveEnabled) {
        QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,      "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
    }
    if (Settings->IsSet.MaxOperationsPerDrain) {
        QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,       "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
    }
    if (Settings->IsSet.RetryMemoryLimit) {
        QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,            "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
    }
    if (Settings->IsSet.LoadBalancingMode) {
        QuicTraceLogVerbose(SettingDumpLoadBalancingMode,           "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
    }
    if (Settings->IsSet.MaxStatelessOperations) {
        QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,      "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
    }
    if (Settings->IsSet.MaxWorkerQueueDelayUs) {
        QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,       "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
    }
    if (Settings->IsSet.InitialWindowPackets) {
        QuicTraceLogVerbose(SettingDumpInitialWindowPackets,        "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
    }
    if (Settings->IsSet.SendIdleTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,           "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
    }
    if (Settings->IsSet.InitialRttMs) {
        QuicTraceLogVerbose(SettingDumpInitialRttMs,                "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
    }
    if (Settings->IsSet.MaxAckDelayMs) {
        QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,               "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
    }
    if (Settings->IsSet.DisconnectTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,         "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
    }
    if (Settings->IsSet.KeepAliveIntervalMs) {
        QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,         "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
    }
    if (Settings->IsSet.IdleTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,               "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
    }
    if (Settings->IsSet.HandshakeIdleTimeoutMs) {
        QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,      "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
    }
    if (Settings->IsSet.PeerBidiStreamCount) {
        QuicTraceLogVerbose(SettingDumpBidiStreamCount,             "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
    }
    if (Settings->IsSet.PeerUnidiStreamCount) {
        QuicTraceLogVerbose(SettingDumpUnidiStreamCount,            "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
    }
    if (Settings->IsSet.TlsClientMaxSendBuffer) {
        QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,      "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
    }
    if (Settings->IsSet.TlsServerMaxSendBuffer) {
        QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,      "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
    }
    if (Settings->IsSet.StreamRecvWindowDefault) {
        QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault,     "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
    }
    if (Settings->IsSet.StreamRecvBufferDefault) {
        QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault,     "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
    }
    if (Settings->IsSet.ConnFlowControlWindow) {
        QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,       "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
    }
    if (Settings->IsSet.MaxBytesPerKey) {
        QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,              "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
    }
    if (Settings->IsSet.ServerResumptionLevel) {
        QuicTraceLogVerbose(SettingDumpServerResumptionLevel,       "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
    }

    if (Settings->IsSet.VersionSettings) {
        QuicTraceLogVerbose(SettingDumpAcceptedVersionsLength,      "[sett] AcceptedVersionslength = %u", Settings->VersionSettings->AcceptableVersionsLength);
        QuicTraceLogVerbose(SettingDumpOfferedVersionsLength,       "[sett] OfferedVersionslength  = %u", Settings->VersionSettings->OfferedVersionsLength);
        QuicTraceLogVerbose(SettingDumpAcceptedVersionsLength,      "[sett] FullyDeployedVerlength = %u", Settings->VersionSettings->FullyDeployedVersionsLength);
        for (uint32_t i = 0; i < Settings->VersionSettings->AcceptableVersionsLength; ++i) {
            QuicTraceLogVerbose(SettingDumpAcceptableVersions,      "[sett] AcceptableVersions[%u]  = 0x%x", i, Settings->VersionSettings->AcceptableVersions[i]);
        }
        for (uint32_t i = 0; i < Settings->VersionSettings->OfferedVersionsLength; ++i) {
            QuicTraceLogVerbose(SettingDumpOfferedVersions,         "[sett] OfferedVersions[%u]     = 0x%x", i, Settings->VersionSettings->OfferedVersions[i]);
        }
        for (uint32_t i = 0; i < Settings->VersionSettings->FullyDeployedVersionsLength; ++i) {
            QuicTraceLogVerbose(SettingDumpFullyDeployedVersions,   "[sett] FullyDeployedVersion[%u]= 0x%x", i, Settings->VersionSettings->FullyDeployedVersions[i]);
        }
    }
    if (Settings->IsSet.VersionNegotiationExtEnabled) {
        QuicTraceLogVerbose(SettingDumpVersionNegoExtEnabled,       "[sett] Version Negotiation Ext Enabled = %hhu", Settings->VersionNegotiationExtEnabled);
    }

    if (Settings->IsSet.MinimumMtu) {
        QuicTraceLogVerbose(SettingDumpMinimumMtu,                  "[sett] MinimumMtu             = %hu", Settings->MinimumMtu);
    }
    if (Settings->IsSet.MaximumMtu) {
        QuicTraceLogVerbose(SettingDumpMaximumMtu,                  "[sett] MaximumMtu             = %hu", Settings->MaximumMtu);
    }
    if (Settings->IsSet.MtuDiscoverySearchCompleteTimeoutUs) {
        QuicTraceLogVerbose(SettingDumpMtuCompleteTimeout,          "[sett] MtuCompleteTimeout     = %llu", Settings->MtuDiscoverySearchCompleteTimeoutUs);
    }
    if (Settings->IsSet.MtuDiscoveryMissingProbeCount) {
        QuicTraceLogVerbose(SettingDumpMtuMissingProbeCount,        "[sett] MtuMissingProbeCount   = %hhu", Settings->MtuDiscoveryMissingProbeCount);
    }

    if (Settings->IsSet.MaxBindingStatelessOperations) {
        QuicTraceLogVerbose(SettingDumpMaxBindingStatelessOper,     "[sett] MaxBindingStatelessOper= %hu", Settings->MaxBindingStatelessOperations);
    }
    if (Settings->IsSet.StatelessOperationExpirationMs) {
        QuicTraceLogVerbose(SettingDumpStatelessOperExpirMs,        "[sett] StatelessOperExpirMs   = %hu", Settings->StatelessOperationExpirationMs);
    }

    if (Settings->IsSet.CongestionControlAlgorithm) {
        QuicTraceLogVerbose(SettingCongestionControlAlgorithm,      "[sett] CongestionControlAlgorithm = %hu", Settings->CongestionControlAlgorithm);
    }
}

#define SETTINGS_SIZE_THRU_FIELD(SettingsType, Field) \
    (FIELD_OFFSET(SettingsType, Field) + sizeof(((SettingsType*)0)->Field))

#define SETTING_HAS_FIELD(SettingsType, Size, Field) \
    (Size >= SETTINGS_SIZE_THRU_FIELD(SettingsType, Field))

#define SETTING_COPY_TO_INTERNAL(Field, Settings, InternalSettings) \
    InternalSettings->IsSet.Field = Settings->IsSet.Field;          \
    InternalSettings->Field = Settings->Field;

#define SETTING_COPY_TO_INTERNAL_SIZED(Field, SettingsType, Settings, SettingsSize, InternalSettings)   \
    if (SETTING_HAS_FIELD(SettingsType, SettingsSize, Field)) {                                         \
        InternalSettings->IsSet.Field = Settings->IsSet.Field;                                          \
        InternalSettings->Field = Settings->Field;                                                      \
    }

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGlobalSettingsToInternal(
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_GLOBAL_SETTINGS* Settings,
    _Out_ QUIC_SETTINGS_INTERNAL* InternalSettings
    )
{
    if (!SETTING_HAS_FIELD(QUIC_GLOBAL_SETTINGS, SettingsSize, LoadBalancingMode)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    InternalSettings->IsSetFlags = 0;
    SETTING_COPY_TO_INTERNAL(RetryMemoryLimit, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(LoadBalancingMode, Settings, InternalSettings);

    //
    // N.B. Anything after this needs to be size checked
    //

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsVersionSettingsToInternal(
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_VERSION_SETTINGS* Settings,
    _Out_ QUIC_SETTINGS_INTERNAL* InternalSettings
    )
{
    if (SettingsSize < sizeof(QUIC_VERSION_SETTINGS)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    InternalSettings->IsSetFlags = 0;

    //
    // Validate the external list only contains versions which MsQuic supports.
    //
    for (uint32_t i = 0; i < Settings->AcceptableVersionsLength; ++i) {
        if (!QuicIsVersionSupported(CxPlatByteSwapUint32(Settings->AcceptableVersions[i])) &&
            !QuicIsVersionReserved(CxPlatByteSwapUint32(Settings->AcceptableVersions[i]))) {
            QuicTraceLogError(
                SettingsInvalidAcceptableVersion,
                "Invalid AcceptableVersion supplied to settings! 0x%x at position %d",
                Settings->AcceptableVersions[i],
                (int32_t)i);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }
    for (uint32_t i = 0; i < Settings->OfferedVersionsLength; ++i) {
        if (!QuicIsVersionSupported(CxPlatByteSwapUint32(Settings->OfferedVersions[i])) &&
            !QuicIsVersionReserved(CxPlatByteSwapUint32(Settings->OfferedVersions[i]))) {
            QuicTraceLogError(
                SettingsInvalidOfferedVersion,
                "Invalid OfferedVersion supplied to settings! 0x%x at position %d",
                Settings->OfferedVersions[i],
                (int32_t)i);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }
    for (uint32_t i = 0; i < Settings->FullyDeployedVersionsLength; ++i) {
        if (!QuicIsVersionSupported(CxPlatByteSwapUint32(Settings->FullyDeployedVersions[i])) &&
            !QuicIsVersionReserved(CxPlatByteSwapUint32(Settings->FullyDeployedVersions[i]))) {
            QuicTraceLogError(
                SettingsInvalidFullyDeployedVersion,
                "Invalid FullyDeployedVersion supplied to settings! 0x%x at position %d",
                Settings->FullyDeployedVersions[i],
                (int32_t)i);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if (Settings->AcceptableVersionsLength == 0 &&
        Settings->FullyDeployedVersionsLength == 0 &&
        Settings->OfferedVersionsLength == 0) {
        InternalSettings->IsSet.VersionNegotiationExtEnabled = TRUE;
        InternalSettings->IsSet.VersionSettings = TRUE;
        InternalSettings->VersionNegotiationExtEnabled = TRUE;
        InternalSettings->VersionSettings = NULL;
    } else {
        InternalSettings->IsSet.VersionNegotiationExtEnabled = TRUE;
        InternalSettings->VersionNegotiationExtEnabled = TRUE;
        InternalSettings->VersionSettings = QuicSettingsCopyVersionSettings(Settings, TRUE);
        if (InternalSettings->VersionSettings == NULL) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        InternalSettings->IsSet.VersionSettings = TRUE;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsSettingsToInternal(
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _Out_ QUIC_SETTINGS_INTERNAL* InternalSettings
    )
{
    if (!SETTING_HAS_FIELD(QUIC_SETTINGS, SettingsSize, MtuDiscoveryMissingProbeCount)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    InternalSettings->IsSetFlags = 0;
    SETTING_COPY_TO_INTERNAL(MaxBytesPerKey, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(HandshakeIdleTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(IdleTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MtuDiscoverySearchCompleteTimeoutUs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(TlsClientMaxSendBuffer, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(TlsServerMaxSendBuffer, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(StreamRecvWindowDefault, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(StreamRecvBufferDefault, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(ConnFlowControlWindow, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MaxWorkerQueueDelayUs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MaxStatelessOperations, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(InitialWindowPackets, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(SendIdleTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(InitialRttMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MaxAckDelayMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(DisconnectTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(KeepAliveIntervalMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(CongestionControlAlgorithm, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(PeerBidiStreamCount, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(PeerUnidiStreamCount, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MaxBindingStatelessOperations, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(StatelessOperationExpirationMs, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MinimumMtu, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MaximumMtu, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MaxOperationsPerDrain, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MtuDiscoveryMissingProbeCount, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(SendBufferingEnabled, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(PacingEnabled, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(MigrationEnabled, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(DatagramReceiveEnabled, Settings, InternalSettings);
    SETTING_COPY_TO_INTERNAL(ServerResumptionLevel, Settings, InternalSettings);

    //
    // N.B. Anything after this needs to be size checked
    //

    //
    // The below is how to add a new field while checking size.
    //
    // SETTING_COPY_TO_INTERNAL_SIZED(
    //     MtuDiscoveryMissingProbeCount,
    //     QUIC_SETTINGS,
    //     Settings,
    //     SettingsSize,
    //     InternalSettings);

    return QUIC_STATUS_SUCCESS;
}

#define SETTING_COPY_FROM_INTERNAL(Field, Settings, InternalSettings)   \
    Settings->IsSet.Field = InternalSettings->IsSet.Field;              \
    Settings->Field = InternalSettings->Field;

#define SETTING_COPY_FROM_INTERNAL_SIZED(Field, SettingsType, Settings, SettingsSize, InternalSettings) \
    if (SETTING_HAS_FIELD(SettingsType, SettingsSize, Field)) {                                         \
        Settings->IsSet.Field = InternalSettings->IsSet.Field;                                          \
        Settings->Field = InternalSettings->Field;                                                      \
    }

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetSettings(
    _In_ const QUIC_SETTINGS_INTERNAL* InternalSettings,
    _Inout_ uint32_t* SettingsLength,
    _Out_writes_bytes_opt_(*SettingsLength)
        QUIC_SETTINGS* Settings
    )
{
    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_SETTINGS, MtuDiscoveryMissingProbeCount);

    if (*SettingsLength == 0) {
        *SettingsLength = sizeof(QUIC_SETTINGS);
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (*SettingsLength < MinimumSettingsSize) {
        *SettingsLength = MinimumSettingsSize;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Settings == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Settings->IsSetFlags = 0;
    SETTING_COPY_FROM_INTERNAL(MaxBytesPerKey, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(HandshakeIdleTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(IdleTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MtuDiscoverySearchCompleteTimeoutUs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(TlsClientMaxSendBuffer, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(TlsServerMaxSendBuffer, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(StreamRecvWindowDefault, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(StreamRecvBufferDefault, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(ConnFlowControlWindow, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MaxWorkerQueueDelayUs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MaxStatelessOperations, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(InitialWindowPackets, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(SendIdleTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(InitialRttMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MaxAckDelayMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(DisconnectTimeoutMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(KeepAliveIntervalMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(CongestionControlAlgorithm, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(PeerBidiStreamCount, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(PeerUnidiStreamCount, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MaxBindingStatelessOperations, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(StatelessOperationExpirationMs, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MinimumMtu, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MaximumMtu, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MaxOperationsPerDrain, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MtuDiscoveryMissingProbeCount, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(SendBufferingEnabled, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(PacingEnabled, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(MigrationEnabled, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(DatagramReceiveEnabled, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(ServerResumptionLevel, Settings, InternalSettings);

    //
    // N.B. Anything after this needs to be size checked
    //

    //
    // The below is how to add a new field while checking size.
    //
    // SETTING_COPY_FROM_INTERNAL_SIZED(
    //     MtuDiscoveryMissingProbeCount,
    //     QUIC_SETTINGS,
    //     Settings,
    //     *SettingsLength,
    //     InternalSettings);

    *SettingsLength = CXPLAT_MIN(*SettingsLength, sizeof(QUIC_SETTINGS));

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetGlobalSettings(
    _In_ const QUIC_SETTINGS_INTERNAL* InternalSettings,
    _Inout_ uint32_t* SettingsLength,
    _Out_writes_bytes_opt_(*SettingsLength)
        QUIC_GLOBAL_SETTINGS* Settings
    )
{
    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_GLOBAL_SETTINGS, LoadBalancingMode);

    if (*SettingsLength == 0) {
        *SettingsLength = sizeof(QUIC_GLOBAL_SETTINGS);
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (*SettingsLength < MinimumSettingsSize) {
        *SettingsLength = MinimumSettingsSize;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Settings == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Settings->IsSetFlags = 0;
    SETTING_COPY_FROM_INTERNAL(RetryMemoryLimit, Settings, InternalSettings);
    SETTING_COPY_FROM_INTERNAL(LoadBalancingMode, Settings, InternalSettings);

    //
    // N.B. Anything after this needs to be size checked
    //

    *SettingsLength = CXPLAT_MIN(*SettingsLength, sizeof(QUIC_GLOBAL_SETTINGS));

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetVersionSettings(
    _In_ const QUIC_SETTINGS_INTERNAL* InternalSettings,
    _Inout_ uint32_t *SettingsLength,
    _Out_writes_bytes_opt_(*SettingsLength)
        QUIC_VERSION_SETTINGS* Settings
    )
{
    uint32_t MinimumSize =
        sizeof(QUIC_VERSION_SETTINGS);
    if (InternalSettings->IsSet.VersionSettings) {
        MinimumSize +=
            (InternalSettings->VersionSettings->AcceptableVersionsLength * sizeof(uint32_t)) +
            (InternalSettings->VersionSettings->OfferedVersionsLength * sizeof(uint32_t)) +
            (InternalSettings->VersionSettings->FullyDeployedVersionsLength * sizeof(uint32_t));
    }

    if (*SettingsLength < MinimumSize) {
        *SettingsLength = MinimumSize;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Settings == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (InternalSettings->IsSet.VersionSettings) {
        Settings->AcceptableVersions = (uint32_t*)(Settings + 1);
        Settings->AcceptableVersionsLength = InternalSettings->VersionSettings->AcceptableVersionsLength;

        Settings->OfferedVersions = Settings->AcceptableVersions + Settings->AcceptableVersionsLength;
        Settings->OfferedVersionsLength = InternalSettings->VersionSettings->OfferedVersionsLength;

        Settings->FullyDeployedVersions = Settings->OfferedVersions + Settings->OfferedVersionsLength;
        Settings->FullyDeployedVersionsLength = InternalSettings->VersionSettings->FullyDeployedVersionsLength;

        CxPlatCopyMemory(
            Settings->AcceptableVersions,
            InternalSettings->VersionSettings->AcceptableVersions,
            InternalSettings->VersionSettings->AcceptableVersionsLength * sizeof(uint32_t));

        CxPlatCopyMemory(
            Settings->OfferedVersions,
            InternalSettings->VersionSettings->OfferedVersions,
            InternalSettings->VersionSettings->OfferedVersionsLength * sizeof(uint32_t));

        CxPlatCopyMemory(
            Settings->FullyDeployedVersions,
            InternalSettings->VersionSettings->FullyDeployedVersions,
            InternalSettings->VersionSettings->FullyDeployedVersionsLength * sizeof(uint32_t));
    } else {
        CxPlatZeroMemory(Settings, MinimumSize);
    }

    *SettingsLength = MinimumSize;

    return QUIC_STATUS_SUCCESS;
}
