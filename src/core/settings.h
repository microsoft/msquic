/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

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
    _In_range_(FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey), UINT32_MAX)
        uint32_t SettingsSize,
    _In_reads_bytes_(SettingsSize)
        const QUIC_SETTINGS* Settings
    );
