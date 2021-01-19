/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
typedef struct QUIC_SETTINGS_INTERNAL {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey             : 1;
            uint64_t HandshakeIdleTimeoutMs     : 1;
            uint64_t IdleTimeoutMs              : 1;
            uint64_t TlsClientMaxSendBuffer     : 1;
            uint64_t TlsServerMaxSendBuffer     : 1;
            uint64_t StreamRecvWindowDefault    : 1;
            uint64_t StreamRecvBufferDefault    : 1;
            uint64_t ConnFlowControlWindow      : 1;
            uint64_t MaxWorkerQueueDelayUs      : 1;
            uint64_t MaxStatelessOperations     : 1;
            uint64_t InitialWindowPackets       : 1;
            uint64_t SendIdleTimeoutMs          : 1;
            uint64_t InitialRttMs               : 1;
            uint64_t MaxAckDelayMs              : 1;
            uint64_t DisconnectTimeoutMs        : 1;
            uint64_t KeepAliveIntervalMs        : 1;
            uint64_t PeerBidiStreamCount        : 1;
            uint64_t PeerUnidiStreamCount       : 1;
            uint64_t RetryMemoryLimit           : 1;
            uint64_t LoadBalancingMode          : 1;
            uint64_t MaxOperationsPerDrain      : 1;
            uint64_t SendBufferingEnabled       : 1;
            uint64_t PacingEnabled              : 1;
            uint64_t MigrationEnabled           : 1;
            uint64_t DatagramReceiveEnabled     : 1;
            uint64_t ServerResumptionLevel      : 1;
            uint64_t DesiredVersionsList        : 1;
            uint64_t GeneratedCompatibleVersions : 1;
            uint64_t RESERVED                   : 36;
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint32_t* DesiredVersionsList;
    uint32_t DesiredVersionsListLength;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t RetryMemoryLimit;              // Global only
    uint16_t LoadBalancingMode;             // Global only
    uint8_t MaxOperationsPerDrain;
    uint8_t SendBufferingEnabled    : 1;
    uint8_t PacingEnabled           : 1;
    uint8_t MigrationEnabled        : 1;
    uint8_t DatagramReceiveEnabled  : 1;
    uint8_t ServerResumptionLevel   : 2;    // QUIC_SERVER_RESUMPTION_LEVEL
    uint8_t RESERVED                : 2;
    uint32_t* GeneratedCompatibleVersionsList;
    uint32_t GeneratedCompatibleVersionsListLength;

} QUIC_SETTINGS_INTERNAL;

//
// Initializes all settings to default values, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsSetDefault(
    _Inout_ QUIC_SETTINGS_INTERNAL* Settings
    );

//
// Applies the parent's value to the settings, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCopy(
    _Inout_ QUIC_SETTINGS_INTERNAL* Destination,
    _In_ const QUIC_SETTINGS_INTERNAL* Source
    );

//
// Applies the changes from the new settings.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSettingApply(
    _Inout_ QUIC_SETTINGS_INTERNAL* Destination,
    _In_ BOOLEAN OverWrite,
    _In_ BOOLEAN CopyInternalFIelds,
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey), UINT32_MAX)
        uint32_t NewSettingsSize,
    _In_reads_bytes_(NewSettingsSize)
        const QUIC_SETTINGS* Source
    );

//
// Cleans up any memory allocated on the Settings.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCleanup(
    _In_ QUIC_SETTINGS_INTERNAL* Settings
    );

//
// Loads the settings from storage, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS_INTERNAL* Settings,
    _In_ CXPLAT_STORAGE* Storage
    );

//
// Dumps the settings to logging.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDump(
    _In_ const QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDumpNew(
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey), UINT32_MAX)
        uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_SETTINGS_INTERNAL* Settings
    );
