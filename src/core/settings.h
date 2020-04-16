/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_SETTINGS {

    BOOLEAN PacingDefault;
    BOOLEAN MigrationEnabled;
    uint8_t MaxPartitionCount;
    uint8_t MaxOperationsPerDrain;
    uint16_t RetryMemoryLimit;
    uint16_t LoadBalancingMode;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint16_t BidiStreamCount;
    uint16_t UnidiStreamCount;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint64_t MaxBytesPerKey;

    struct {
        BOOLEAN PacingDefault : 1;
        BOOLEAN MigrationEnabled : 1;
        BOOLEAN MaxPartitionCount : 1;
        BOOLEAN MaxOperationsPerDrain : 1;
        BOOLEAN RetryMemoryLimit : 1;
        BOOLEAN LoadBalancingMode : 1;
        BOOLEAN MaxWorkerQueueDelayUs : 1;
        BOOLEAN MaxStatelessOperations : 1;
        BOOLEAN InitialWindowPackets : 1;
        BOOLEAN SendIdleTimeoutMs : 1;
        BOOLEAN InitialRttMs : 1;
        BOOLEAN MaxAckDelayMs : 1;
        BOOLEAN DisconnectTimeoutMs : 1;
        BOOLEAN KeepAliveIntervalMs : 1;
        BOOLEAN IdleTimeoutMs : 1;
        BOOLEAN HandshakeIdleTimeoutMs : 1;
        BOOLEAN BidiStreamCount : 1;
        BOOLEAN UnidiStreamCount : 1;
        BOOLEAN TlsClientMaxSendBuffer : 1;
        BOOLEAN TlsServerMaxSendBuffer : 1;
        BOOLEAN StreamRecvWindowDefault : 1;
        BOOLEAN StreamRecvBufferDefault : 1;
        BOOLEAN ConnFlowControlWindow : 1;
        BOOLEAN MaxBytesPerKey : 1;
    } AppSet;

} QUIC_SETTINGS;

//
// Initializes all settings to default values, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsSetDefault(
    _Inout_ QUIC_SETTINGS* Settings
    );

//
// Applies the parent's value to the settings, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCopy(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ const QUIC_SETTINGS* ParentSettings
    );

//
// Loads the settings from storage, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS* Settings,
    _In_ QUIC_STORAGE* Storage
    );

//
// Dumps the settings to logging.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDump(
    _In_ const QUIC_SETTINGS* Settings
    );
