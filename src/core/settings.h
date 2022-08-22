/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_SETTINGS_INTERNAL {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey                         : 1;
            uint64_t HandshakeIdleTimeoutMs                 : 1;
            uint64_t IdleTimeoutMs                          : 1;
            uint64_t TlsClientMaxSendBuffer                 : 1;
            uint64_t TlsServerMaxSendBuffer                 : 1;
            uint64_t StreamRecvWindowDefault                : 1;
            uint64_t StreamRecvBufferDefault                : 1;
            uint64_t ConnFlowControlWindow                  : 1;
            uint64_t MaxWorkerQueueDelayUs                  : 1;
            uint64_t MaxStatelessOperations                 : 1;
            uint64_t InitialWindowPackets                   : 1;
            uint64_t SendIdleTimeoutMs                      : 1;
            uint64_t InitialRttMs                           : 1;
            uint64_t MaxAckDelayMs                          : 1;
            uint64_t DisconnectTimeoutMs                    : 1;
            uint64_t KeepAliveIntervalMs                    : 1;
            uint64_t PeerBidiStreamCount                    : 1;
            uint64_t PeerUnidiStreamCount                   : 1;
            uint64_t RetryMemoryLimit                       : 1;
            uint64_t LoadBalancingMode                      : 1;
            uint64_t MaxOperationsPerDrain                  : 1;
            uint64_t SendBufferingEnabled                   : 1;
            uint64_t PacingEnabled                          : 1;
            uint64_t MigrationEnabled                       : 1;
            uint64_t DatagramReceiveEnabled                 : 1;
            uint64_t ServerResumptionLevel                  : 1;
            uint64_t VersionSettings                        : 1;
            uint64_t VersionNegotiationExtEnabled           : 1;
            uint64_t MinimumMtu                             : 1;
            uint64_t MaximumMtu                             : 1;
            uint64_t MtuDiscoverySearchCompleteTimeoutUs    : 1;
            uint64_t MtuDiscoveryMissingProbeCount          : 1;
            uint64_t MaxBindingStatelessOperations          : 1;
            uint64_t StatelessOperationExpirationMs         : 1;
            uint64_t CongestionControlAlgorithm             : 1;
            uint64_t DestCidUpdateIdleTimeoutMs             : 1;
            uint64_t GreaseQuicBitEnabled                   : 1;
            uint64_t RESERVED                               : 27;
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
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
    uint32_t DestCidUpdateIdleTimeoutMs;
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t RetryMemoryLimit;              // Global only
    uint16_t LoadBalancingMode;             // Global only
    uint8_t MaxOperationsPerDrain;
    uint8_t SendBufferingEnabled            : 1;
    uint8_t PacingEnabled                   : 1;
    uint8_t MigrationEnabled                : 1;
    uint8_t DatagramReceiveEnabled          : 1;
    uint8_t ServerResumptionLevel           : 2;    // QUIC_SERVER_RESUMPTION_LEVEL
    uint8_t VersionNegotiationExtEnabled    : 1;
    uint8_t GreaseQuicBitEnabled            : 1;
    QUIC_VERSION_SETTINGS* VersionSettings;
    uint16_t MinimumMtu;
    uint16_t MaximumMtu;
    uint64_t MtuDiscoverySearchCompleteTimeoutUs;
    uint8_t MtuDiscoveryMissingProbeCount;
    uint16_t MaxBindingStatelessOperations;
    uint16_t StatelessOperationExpirationMs;
    uint16_t CongestionControlAlgorithm;

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
// Does not deep-copy parent values.
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
    _In_ BOOLEAN AllowMtuChanges,
    _In_reads_bytes_(sizeof(QUIC_SETTINGS_INTERNAL))
        const QUIC_SETTINGS_INTERNAL* Source
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
    _In_reads_bytes_(sizeof(QUIC_SETTINGS_INTERNAL))
        const QUIC_SETTINGS_INTERNAL* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsDumpNew(
    _In_reads_bytes_(sizeof(QUIC_SETTINGS_INTERNAL))
        const QUIC_SETTINGS_INTERNAL* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsSettingsToInternal(
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _Out_ QUIC_SETTINGS_INTERNAL* InternalSettings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGlobalSettingsToInternal(
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_GLOBAL_SETTINGS* Settings,
    _Out_ QUIC_SETTINGS_INTERNAL* InternalSettings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsVersionSettingsToInternal(
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_VERSION_SETTINGS* Settings,
    _Out_ QUIC_SETTINGS_INTERNAL* InternalSettings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetSettings(
    _In_ const QUIC_SETTINGS_INTERNAL* InternalSettings,
    _Inout_ uint32_t* SettingsLength,
    _Out_writes_bytes_opt_(*SettingsLength)
        QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetGlobalSettings(
    _In_ const QUIC_SETTINGS_INTERNAL* InternalSettings,
    _Inout_ uint32_t* SettingsLength,
    _Out_writes_bytes_opt_(*SettingsLength)
        QUIC_GLOBAL_SETTINGS* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetVersionSettings(
    _In_ const QUIC_SETTINGS_INTERNAL* InternalSettings,
    _Inout_ uint32_t *SettingsLength,
    _Out_writes_bytes_opt_(*SettingsLength)
        QUIC_VERSION_SETTINGS* Settings
    );

#if defined(__cplusplus)
}
#endif
