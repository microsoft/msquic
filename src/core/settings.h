/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

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
// Does not deep-copy parent values.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsCopy(
    _Inout_ QUIC_SETTINGS* Destination,
    _In_ const QUIC_SETTINGS* Source
    );

//
// Applies the changes from the new settings.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSettingApply(
    _Inout_ QUIC_SETTINGS* Destination,
    _In_ BOOLEAN OverWrite,
    _In_ BOOLEAN CopyExternalToInternal,
    _In_ BOOLEAN AllowMtuChanges,
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, DesiredVersionsList), UINT32_MAX)
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
    _In_ QUIC_SETTINGS* Settings
    );

//
// Loads the settings from storage, if not already set by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSettingsLoad(
    _Inout_ QUIC_SETTINGS* Settings,
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
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, DesiredVersionsList), UINT32_MAX)
        uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetParam(
    _In_ const QUIC_SETTINGS* IncomingSettings,
    _Inout_ uint32_t* OutgoingSize,
    _Out_writes_bytes_opt_(*OutgoingSize)
        QUIC_SETTINGS* OutgoingSettings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSettingsGetDesiredVersions(
    _In_ const QUIC_SETTINGS* Settings,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        uint32_t* Buffer
    );

#if defined(__cplusplus)
}
#endif
