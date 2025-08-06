/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the settings logic.

--*/

#define QUIC_UNIT_TESTS

#include "main.h"
#ifdef QUIC_CLOG
#include "SettingsTest.cpp.clog.h"
#endif

#define SETTINGS_FEATURE_SET_TEST(Field, Func)                                              \
    FieldCount++;                                                                           \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    Settings.IsSet.Field = 1;                                                               \
    Settings.Field = 1;                                                                     \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(sizeof(Settings), &Settings, &InternalSettings));   \
    ASSERT_EQ(1u, InternalSettings.IsSet.Field);                                            \
    ASSERT_EQ(1u, InternalSettings.Field);                                                   \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    Settings.IsSet.Field = 1;                                                               \
    Settings.Field = 0;                                                                     \
    InternalSettings.Field = 1;                                                             \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(sizeof(Settings), &Settings, &InternalSettings));   \
    ASSERT_EQ(1u, InternalSettings.IsSet.Field);                                            \
    ASSERT_EQ(0u, InternalSettings.Field);                                                   \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    Settings.Field = 1;                                                                     \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(sizeof(Settings), &Settings, &InternalSettings));   \
    ASSERT_EQ(0u, InternalSettings.IsSet.Field);                                            \


#define SETTINGS_FEATURE_GET_TEST(Field, Func)                                              \
    FieldCount++;                                                                           \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    InternalSettings.IsSet.Field = 1;                                                       \
    InternalSettings.Field = 1;                                                             \
    SettingsLength = sizeof(Settings);                                                      \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(&InternalSettings, &SettingsLength, &Settings));    \
    ASSERT_EQ(1u, Settings.IsSet.Field);                                                    \
    ASSERT_EQ(1u, Settings.Field);                                                           \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    InternalSettings.IsSet.Field = 1;                                                       \
    InternalSettings.Field = 0;                                                             \
    Settings.Field = 1;                                                                     \
    SettingsLength = sizeof(Settings);                                                      \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(&InternalSettings, &SettingsLength, &Settings));    \
    ASSERT_EQ(1u, Settings.IsSet.Field);                                                    \
    ASSERT_EQ(0u, Settings.Field);                                                           \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    InternalSettings.Field = 1;                                                             \
    SettingsLength = sizeof(Settings);                                                      \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(&InternalSettings, &SettingsLength, &Settings));    \
    ASSERT_EQ(0u, Settings.IsSet.Field);

template<typename T>
static uint32_t PopCount(T Value) {
    uint32_t Count = 0;
    for (uint32_t i = 0; i < (uint32_t)sizeof(Value) * 8; i++) {
        if (Value & 0x1) {
            Count++;
        }
        Value >>= 1;
    }
    return Count;
}

TEST(SettingsTest, TestAllSettingsFieldsSet)
{
    QUIC_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t FieldCount = 0;

    SETTINGS_FEATURE_SET_TEST(MaxBytesPerKey, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(HandshakeIdleTimeoutMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(IdleTimeoutMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MtuDiscoverySearchCompleteTimeoutUs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(TlsClientMaxSendBuffer, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(TlsServerMaxSendBuffer, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamRecvWindowDefault, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamRecvWindowBidiLocalDefault, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamRecvWindowBidiRemoteDefault, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamRecvWindowUnidiDefault, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamRecvBufferDefault, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(ConnFlowControlWindow, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MaxWorkerQueueDelayUs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MaxStatelessOperations, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(InitialWindowPackets, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(SendIdleTimeoutMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(InitialRttMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MaxAckDelayMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(DisconnectTimeoutMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(KeepAliveIntervalMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(CongestionControlAlgorithm, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(PeerBidiStreamCount, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(PeerUnidiStreamCount, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MaxBindingStatelessOperations, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StatelessOperationExpirationMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MinimumMtu, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MaximumMtu, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MaxOperationsPerDrain, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MtuDiscoveryMissingProbeCount, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(SendBufferingEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(PacingEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(MigrationEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(DatagramReceiveEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(ServerResumptionLevel, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(DestCidUpdateIdleTimeoutMs, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(GreaseQuicBitEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(EcnEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(HyStartEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(EncryptionOffloadAllowed, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(ReliableResetEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(XdpEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(QTIPEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(OneWayDelayEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(NetStatsEventEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamMultiReceiveEnabled, QuicSettingsSettingsToInternal);

    // Bias field count on behalf of erstwhile ReservedRioEnabled
    FieldCount++;

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllGlobalSettingsFieldsSet)
{
    QUIC_GLOBAL_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t FieldCount = 0;

    SETTINGS_FEATURE_SET_TEST(RetryMemoryLimit, QuicSettingsGlobalSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(LoadBalancingMode, QuicSettingsGlobalSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(FixedServerID, QuicSettingsGlobalSettingsToInternal);

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

// TEST(SettingsTest, TestAllVersionSettingsFieldsSet)
// {
//     QUIC_VERSION_SETTINGS Settings;
//     QUIC_SETTINGS_INTERNAL InternalSettings;
//     uint32_t FieldCount = 0;

//     SETTINGS_FEATURE_SET_TEST(VersionNegotiationExtEnabled, QuicSettingsVersionSettingsToInternal);

//     FieldCount++; // Force increment field count for separately tested version field

//     Settings.IsSetFlags = 0;
//     Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
//     ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
// }

TEST(SettingsTest, TestAllSettingsFieldsGet)
{
    QUIC_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t SettingsLength;
    uint32_t FieldCount = 0;

    SETTINGS_FEATURE_GET_TEST(MaxBytesPerKey, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(HandshakeIdleTimeoutMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(IdleTimeoutMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MtuDiscoverySearchCompleteTimeoutUs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(TlsClientMaxSendBuffer, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(TlsServerMaxSendBuffer, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamRecvWindowDefault, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamRecvWindowBidiLocalDefault, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamRecvWindowBidiRemoteDefault, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamRecvWindowUnidiDefault, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamRecvBufferDefault, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(ConnFlowControlWindow, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MaxWorkerQueueDelayUs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MaxStatelessOperations, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(InitialWindowPackets, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(SendIdleTimeoutMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(InitialRttMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MaxAckDelayMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(DisconnectTimeoutMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(KeepAliveIntervalMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(CongestionControlAlgorithm, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(PeerBidiStreamCount, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(PeerUnidiStreamCount, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MaxBindingStatelessOperations, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StatelessOperationExpirationMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MinimumMtu, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MaximumMtu, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MaxOperationsPerDrain, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MtuDiscoveryMissingProbeCount, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(SendBufferingEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(PacingEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(MigrationEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(DatagramReceiveEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(ServerResumptionLevel, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(DestCidUpdateIdleTimeoutMs, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(GreaseQuicBitEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(EcnEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(HyStartEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(EncryptionOffloadAllowed, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(ReliableResetEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_SET_TEST(XdpEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(QTIPEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_GET_TEST(OneWayDelayEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(NetStatsEventEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamMultiReceiveEnabled, QuicSettingsGetSettings);

    // Bias field count on behalf of erstwhile ReservedRioEnabled
    FieldCount++;

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllGlobalSettingsFieldsGet)
{
    QUIC_GLOBAL_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t SettingsLength;
    uint32_t FieldCount = 0;

    SETTINGS_FEATURE_GET_TEST(RetryMemoryLimit, QuicSettingsGetGlobalSettings);
    SETTINGS_FEATURE_GET_TEST(LoadBalancingMode, QuicSettingsGetGlobalSettings);
    SETTINGS_FEATURE_GET_TEST(FixedServerID, QuicSettingsGetGlobalSettings);

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, StreamRecvWindowDefaultSetsIndividualLimits)
{
    QUIC_SETTINGS_INTERNAL Source;
    QUIC_SETTINGS_INTERNAL Destination;
    CxPlatZeroMemory(&Source, sizeof(Source));
    CxPlatZeroMemory(&Destination, sizeof(Destination));

    const uint32_t Limit = 1024;

    Source.IsSet.StreamRecvWindowDefault = 1;
    Source.StreamRecvWindowDefault = Limit;

    ASSERT_TRUE(QuicSettingApply(&Destination, TRUE, TRUE, &Source));

    ASSERT_EQ(Destination.StreamRecvWindowDefault, Limit);
    ASSERT_EQ(Destination.StreamRecvWindowBidiLocalDefault, Limit);
    ASSERT_EQ(Destination.StreamRecvWindowBidiRemoteDefault, Limit);
    ASSERT_EQ(Destination.StreamRecvWindowUnidiDefault, Limit);
}

TEST(SettingsTest, StreamRecvWindowDefaultDoesNotOverrideIndividualLimitsWhenSetAtDestination)
{
    QUIC_SETTINGS_INTERNAL Source;
    QUIC_SETTINGS_INTERNAL Destination;
    CxPlatZeroMemory(&Source, sizeof(Source));
    CxPlatZeroMemory(&Destination, sizeof(Destination));

    const uint32_t Limit = 1024;
    const uint32_t Original = 2 * 1024;

    Source.IsSet.StreamRecvWindowDefault = 1;
    Source.StreamRecvWindowDefault = Limit;

    Destination.IsSet.StreamRecvWindowBidiLocalDefault = 1;
    Destination.StreamRecvWindowBidiLocalDefault = Original;

    Destination.IsSet.StreamRecvWindowBidiRemoteDefault = 1;
    Destination.StreamRecvWindowBidiRemoteDefault = Original;

    Destination.IsSet.StreamRecvWindowUnidiDefault = 1;
    Destination.StreamRecvWindowUnidiDefault = Original;

    ASSERT_TRUE(QuicSettingApply(&Destination, FALSE /* no override */, TRUE, &Source));

    ASSERT_EQ(Destination.StreamRecvWindowDefault, Limit);
    ASSERT_EQ(Destination.StreamRecvWindowBidiLocalDefault, Original);
    ASSERT_EQ(Destination.StreamRecvWindowBidiRemoteDefault, Original);
    ASSERT_EQ(Destination.StreamRecvWindowUnidiDefault, Original);
}

TEST(SettingsTest, StreamRecvWindowDefaultGetsOverridenByIndividualLimits)
{
    QUIC_SETTINGS_INTERNAL Source;
    QUIC_SETTINGS_INTERNAL Destination;
    CxPlatZeroMemory(&Source, sizeof(Source));
    CxPlatZeroMemory(&Destination, sizeof(Destination));

    Source.IsSet.StreamRecvWindowDefault = 1;
    Source.StreamRecvWindowDefault = 1 * 1024;

    Source.IsSet.StreamRecvWindowBidiLocalDefault = 1;
    Source.StreamRecvWindowBidiLocalDefault = 2 * 1024;

    Source.IsSet.StreamRecvWindowBidiRemoteDefault = 1;
    Source.StreamRecvWindowBidiRemoteDefault = 4 * 1024;

    Source.IsSet.StreamRecvWindowUnidiDefault = 1;
    Source.StreamRecvWindowUnidiDefault = 8 * 1024;

    ASSERT_TRUE(QuicSettingApply(&Destination, TRUE, TRUE, &Source));

    ASSERT_EQ(Destination.StreamRecvWindowDefault, Source.StreamRecvWindowDefault);
    ASSERT_EQ(Destination.StreamRecvWindowBidiLocalDefault, Source.StreamRecvWindowBidiLocalDefault);
    ASSERT_EQ(Destination.StreamRecvWindowBidiRemoteDefault, Source.StreamRecvWindowBidiRemoteDefault);
    ASSERT_EQ(Destination.StreamRecvWindowUnidiDefault, Source.StreamRecvWindowUnidiDefault);
}

// TEST(SettingsTest, TestAllVersionSettingsFieldsGet)
// {
//     QUIC_VERSION_SETTINGS Settings;
//     QUIC_SETTINGS_INTERNAL InternalSettings;
//     uint32_t SettingsLength;
//     uint32_t FieldCount = 0;

//     SETTINGS_FEATURE_GET_TEST(VersionNegotiationExtEnabled, QuicSettingsGetVersionSettings);

//     FieldCount++; // Force increment field count for separately tested version field

//     Settings.IsSetFlags = 0;
//     Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
//     ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
// }

#define SETTINGS_SIZE_THRU_FIELD(SettingsType, Field) \
    (FIELD_OFFSET(SettingsType, Field) + sizeof(((SettingsType*)0)->Field))

TEST(SettingsTest, QuicSettingsSetDefault_DoesNotOverwriteSetFields)
{
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    // Set a few fields and mark them as set
    Settings.IsSet.SendBufferingEnabled = 1;
    Settings.SendBufferingEnabled = 0;
    Settings.IsSet.PacingEnabled = 1;
    Settings.PacingEnabled = 0;
    QuicSettingsSetDefault(&Settings);

    // These should not be overwritten
    ASSERT_EQ(Settings.SendBufferingEnabled, 0);
    ASSERT_EQ(Settings.PacingEnabled, 0);

    // But an unset field should be set to default
    ASSERT_EQ(Settings.MigrationEnabled, QUIC_DEFAULT_MIGRATION_ENABLED);
}

class QuicStorageSettingScopeGuard {
public:
    static
    QuicStorageSettingScopeGuard Create(
        _In_opt_ const char* StorageName = nullptr)
    {
        return QuicStorageSettingScopeGuard(StorageName);
    }

    QuicStorageSettingScopeGuard(const QuicStorageSettingScopeGuard&) = delete;
    QuicStorageSettingScopeGuard& operator=(const QuicStorageSettingScopeGuard&) = delete;

    QuicStorageSettingScopeGuard(
        _In_ QuicStorageSettingScopeGuard&& Other) noexcept : m_Storage(Other.m_Storage)
    {
        Other.m_Storage = nullptr;
    }

    QuicStorageSettingScopeGuard& operator=(
        _In_ QuicStorageSettingScopeGuard&& Other)
    {
        if (this == &Other)
        {
            return Other;
        }
        ClearAndClose(m_Storage);
        m_Storage = Other.m_Storage;
        Other.m_Storage = nullptr;
        return *this;
    }

    ~QuicStorageSettingScopeGuard()
    {
        ClearAndClose(m_Storage);
    }

    operator CXPLAT_STORAGE*() const {
        return m_Storage;
    }

private:
    QuicStorageSettingScopeGuard(
        _In_opt_ const char* StorageName)
    {
        EXPECT_EQ(
            QUIC_STATUS_SUCCESS,
            CxPlatStorageOpen(
                StorageName,
                nullptr,
                nullptr,
                CXPLAT_STORAGE_OPEN_FLAG_DELETE | CXPLAT_STORAGE_OPEN_FLAG_WRITE | CXPLAT_STORAGE_OPEN_FLAG_CREATE,
                &m_Storage));
        EXPECT_NE(m_Storage, nullptr);
    }

    void ClearAndClose(
        _In_opt_ CXPLAT_STORAGE* Storage)
    {
        if (Storage != nullptr) {
            EXPECT_EQ(QUIC_STATUS_SUCCESS, CxPlatStorageClear(Storage));
            CxPlatStorageClose(Storage);
        }
    }

    CXPLAT_STORAGE* m_Storage = nullptr;
};

// --- Test: QuicSettingsLoad sets fields from storage ---
TEST(SettingsTest, QuicSettingsLoad_SetsFieldsFromStorage)
{
    CXPLAT_STORAGE* TestStorage = NULL;

    QUIC_STATUS Status =
        CxPlatStorageOpen(
            "Apps\\MsQuicUnitTestStorage",
            nullptr,
            nullptr,
            CXPLAT_STORAGE_OPEN_FLAG_CREATE,
            &TestStorage);

    if (Status == QUIC_STATUS_NOT_SUPPORTED) {
        GTEST_SKIP() << "Skipping test because storage is not available. Status:" << Status;
    }
    CxPlatStorageClose(TestStorage);

    ASSERT_EQ(Status, QUIC_STATUS_SUCCESS);

    QuicStorageSettingScopeGuard StorageGuard =
        QuicStorageSettingScopeGuard::Create("Apps\\MsQuicUnitTestStorage");

    uint32_t Value = 0;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageWriteValue(
            StorageGuard,
            QUIC_SETTING_SEND_BUFFERING_DEFAULT,
            CXPLAT_STORAGE_TYPE_UINT32,
            sizeof(Value),
            (uint8_t*)&Value));

    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageWriteValue(
            StorageGuard,
            QUIC_SETTING_SEND_PACING_DEFAULT,
            CXPLAT_STORAGE_TYPE_UINT32,
            sizeof(Value),
            (uint8_t*)&Value));

    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageWriteValue(
            StorageGuard,
            QUIC_SETTING_MIGRATION_ENABLED,
            CXPLAT_STORAGE_TYPE_UINT32,
            sizeof(Value),
            (uint8_t*)&Value));

    Value = 7;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageWriteValue(
            StorageGuard,
            QUIC_SETTING_MAX_OPERATIONS_PER_DRAIN,
            CXPLAT_STORAGE_TYPE_UINT32,
            sizeof(Value),
            (uint8_t*)&Value));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    QuicSettingsLoad(&Settings, StorageGuard);

    // Check that the values were loaded
    ASSERT_EQ(Settings.SendBufferingEnabled, 0u);
    ASSERT_EQ(Settings.PacingEnabled, 0u);
    ASSERT_EQ(Settings.MigrationEnabled, 0u);
    ASSERT_EQ(Settings.MaxOperationsPerDrain, 7u);

    QuicSettingsDumpNew(&Settings);
}

// --- Test: QuicSettingsLoad does not overwrite set fields ---
TEST(SettingsTest, QuicSettingsLoad_DoesNotOverwriteSetFields)
{
    CXPLAT_STORAGE* TestStorage = NULL;

    QUIC_STATUS Status =
        CxPlatStorageOpen(
            "Apps\\MsQuicUnitTestStorage",
            nullptr,
            nullptr,
            CXPLAT_STORAGE_OPEN_FLAG_CREATE,
            &TestStorage);

    if (Status == QUIC_STATUS_NOT_SUPPORTED) {
        GTEST_SKIP() << "Skipping test because storage is not available. Status:" << Status;
    }
    CxPlatStorageClose(TestStorage);

    ASSERT_EQ(Status, QUIC_STATUS_SUCCESS);

    QuicStorageSettingScopeGuard StorageGuard =
        QuicStorageSettingScopeGuard::Create("Apps\\MsQuicUnitTestStorage");

    uint32_t Value = 0;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageWriteValue(
            StorageGuard,
            QUIC_SETTING_SEND_BUFFERING_DEFAULT,
            CXPLAT_STORAGE_TYPE_UINT32,
            sizeof(Value),
            (uint8_t*)&Value));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    // Mark SendBufferingEnabled as set
    Settings.IsSet.SendBufferingEnabled = 1;
    Settings.SendBufferingEnabled = 1;

    QuicSettingsLoad(&Settings, StorageGuard);

    // Should not be overwritten
    ASSERT_EQ(Settings.SendBufferingEnabled, 1u);
}

// --- Test: QuicSettingsLoad uses default if storage missing ---
TEST(SettingsTest, QuicSettingsLoad_UsesDefaultIfStorageMissing)
{
    CXPLAT_STORAGE* TestStorage = NULL;

    QUIC_STATUS Status =
        CxPlatStorageOpen(
            "Apps\\MsQuicUnitTestStorage",
            nullptr,
            nullptr,
            CXPLAT_STORAGE_OPEN_FLAG_CREATE,
            &TestStorage);

    if (Status == QUIC_STATUS_NOT_SUPPORTED) {
        GTEST_SKIP() << "Skipping test because storage is not available. Status:" << Status;
    }
    CxPlatStorageClose(TestStorage);

    ASSERT_EQ(Status, QUIC_STATUS_SUCCESS);

    QuicStorageSettingScopeGuard StorageGuard =
        QuicStorageSettingScopeGuard::Create("Apps\\MsQuicUnitTestStorage");

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    QuicSettingsLoad(&Settings, StorageGuard);

    // Should use default
    ASSERT_EQ(Settings.SendBufferingEnabled, QUIC_DEFAULT_SEND_BUFFERING_ENABLE);
    ASSERT_EQ(Settings.PacingEnabled, QUIC_DEFAULT_SEND_PACING);
    ASSERT_EQ(Settings.MigrationEnabled, QUIC_DEFAULT_MIGRATION_ENABLED);

}

TEST(SettingsTest, SettingsSizesGet)
{
    uint8_t Buffer[sizeof(QUIC_SETTINGS) * 2];
    CxPlatZeroMemory(Buffer, ARRAYSIZE(Buffer));
    QUIC_SETTINGS_INTERNAL InternalSettings;
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));

    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_SETTINGS, MtuDiscoveryMissingProbeCount);

    uint32_t BufferSize = 0;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        QuicSettingsGetSettings(
            &InternalSettings,
            &BufferSize,
            reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
    ASSERT_EQ(sizeof(QUIC_SETTINGS), BufferSize);

    for (uint32_t i = 1; i < MinimumSettingsSize; i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicSettingsGetSettings(
                &InternalSettings,
                &BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
        ASSERT_EQ(MinimumSettingsSize, BufferSize);
    }

    for (uint32_t i = MinimumSettingsSize; i <= sizeof(QUIC_SETTINGS); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGetSettings(
                &InternalSettings,
                &BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
        ASSERT_EQ(i, BufferSize);
    }

    for (uint32_t i = sizeof(QUIC_SETTINGS); i <= sizeof(Buffer); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGetSettings(
                &InternalSettings,
                &BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
        ASSERT_EQ(sizeof(QUIC_SETTINGS), BufferSize);
    }
}

TEST(SettingsTest, SettingsSizesSet)
{
    uint8_t Buffer[sizeof(QUIC_SETTINGS) * 2];
    CxPlatZeroMemory(Buffer, ARRAYSIZE(Buffer));
    QUIC_SETTINGS_INTERNAL InternalSettings;
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));

    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_SETTINGS, MtuDiscoveryMissingProbeCount);

    uint32_t BufferSize = 0;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicSettingsSettingsToInternal(
            BufferSize,
            reinterpret_cast<QUIC_SETTINGS*>(Buffer),
            &InternalSettings));

    for (uint32_t i = 1; i < MinimumSettingsSize; i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicSettingsSettingsToInternal(
                BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer),
                &InternalSettings));
    }

    for (uint32_t i = MinimumSettingsSize; i <= sizeof(QUIC_SETTINGS); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsSettingsToInternal(
                BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer),
                &InternalSettings));
    }

    for (uint32_t i = sizeof(QUIC_SETTINGS); i <= sizeof(Buffer); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsSettingsToInternal(
                BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer),
                &InternalSettings));
    }
}

TEST(SettingsTest, GlobalSettingsSizesGet)
{
    uint8_t Buffer[sizeof(QUIC_GLOBAL_SETTINGS) * 2];
    CxPlatZeroMemory(Buffer, ARRAYSIZE(Buffer));
    QUIC_SETTINGS_INTERNAL InternalSettings;
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));

    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_GLOBAL_SETTINGS, LoadBalancingMode);

    uint32_t BufferSize = 0;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        QuicSettingsGetGlobalSettings(
            &InternalSettings,
            &BufferSize,
            reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer)));
    ASSERT_EQ(sizeof(QUIC_GLOBAL_SETTINGS), BufferSize);

    for (uint32_t i = 1; i < MinimumSettingsSize; i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicSettingsGetGlobalSettings(
                &InternalSettings,
                &BufferSize,
                reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer)));
        ASSERT_EQ(MinimumSettingsSize, BufferSize);
    }

    for (uint32_t i = MinimumSettingsSize; i <= sizeof(QUIC_GLOBAL_SETTINGS); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGetGlobalSettings(
                &InternalSettings,
                &BufferSize,
                reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer)));
        ASSERT_EQ(i, BufferSize);
    }

    for (uint32_t i = sizeof(QUIC_GLOBAL_SETTINGS); i <= sizeof(Buffer); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGetGlobalSettings(
                &InternalSettings,
                &BufferSize,
                reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer)));
        ASSERT_EQ(sizeof(QUIC_GLOBAL_SETTINGS), BufferSize);
    }
}

TEST(SettingsTest, GlobalSettingsSizesSet)
{
    uint8_t Buffer[sizeof(QUIC_GLOBAL_SETTINGS) * 2];
    CxPlatZeroMemory(Buffer, ARRAYSIZE(Buffer));
    QUIC_SETTINGS_INTERNAL InternalSettings;
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));

    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_GLOBAL_SETTINGS, LoadBalancingMode);

    uint32_t BufferSize = 0;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicSettingsGlobalSettingsToInternal(
            BufferSize,
            reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer),
            &InternalSettings));

    for (uint32_t i = 1; i < MinimumSettingsSize; i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicSettingsGlobalSettingsToInternal(
                BufferSize,
                reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer),
                &InternalSettings));
    }

    for (uint32_t i = MinimumSettingsSize; i <= sizeof(QUIC_GLOBAL_SETTINGS); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGlobalSettingsToInternal(
                BufferSize,
                reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer),
                &InternalSettings));
    }

    for (uint32_t i = sizeof(QUIC_GLOBAL_SETTINGS); i <= sizeof(Buffer); i++) {
        BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGlobalSettingsToInternal(
                BufferSize,
                reinterpret_cast<QUIC_GLOBAL_SETTINGS*>(Buffer),
                &InternalSettings));
    }
}

TEST(SettingsTest, GlobalLoadBalancingServerIDSet)
{
    uint16_t Mode = QUIC_LOAD_BALANCING_SERVER_ID_IP;
    uint16_t OldMode = MsQuicLib.Settings.LoadBalancingMode;

    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicLibrarySetGlobalParam(
            QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
            sizeof(Mode),
            &Mode));

    ASSERT_EQ(Mode, MsQuicLib.Settings.LoadBalancingMode);
    ASSERT_EQ(5, MsQuicLib.CidServerIdLength);
    ASSERT_EQ(QUIC_CID_PID_LENGTH + QUIC_CID_PAYLOAD_LENGTH + 5, MsQuicLib.CidTotalLength);

    // Revert
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicLibrarySetGlobalParam(
            QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
            sizeof(OldMode),
            &OldMode));
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(SettingsTest, GlobalExecutionConfigSetAndGet)
{
    uint8_t RawConfig[QUIC_GLOBAL_EXECUTION_CONFIG_MIN_SIZE + 2 * sizeof(uint16_t)] = {0};
    QUIC_GLOBAL_EXECUTION_CONFIG* Config = (QUIC_GLOBAL_EXECUTION_CONFIG*)RawConfig;
    Config->ProcessorCount = 2;
    if (CxPlatProcCount() < 2) {
        Config->ProcessorCount = CxPlatProcCount();
    }
    Config->ProcessorList[0] = 0;
    Config->ProcessorList[1] = 1;

    uint32_t BufferLength = sizeof(RawConfig);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicLibrarySetGlobalParam(
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            BufferLength,
            Config));
    BufferLength = 0;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        QuicLibraryGetGlobalParam(
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            &BufferLength,
            nullptr));
    ASSERT_EQ((uint32_t)sizeof(RawConfig), BufferLength);
    uint16_t GetRawConfig[sizeof(RawConfig)] = {0};
    QUIC_GLOBAL_EXECUTION_CONFIG* GetConfig = (QUIC_GLOBAL_EXECUTION_CONFIG*)GetRawConfig;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicLibraryGetGlobalParam(
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            &BufferLength,
            GetConfig));
    ASSERT_EQ(0, memcmp(GetConfig, Config, BufferLength));
    //
    // Passing a NULL buffer should clear the proc list.
    //
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicLibrarySetGlobalParam(
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            0,
            nullptr));
    BufferLength = 0;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicLibraryGetGlobalParam(
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            &BufferLength,
            nullptr));
    ASSERT_EQ((uint32_t)0, BufferLength);

    //
    // Passing an invalid processor number.
    //
    Config->ProcessorCount = 1;
    Config->ProcessorList[0] = (uint16_t)CxPlatProcCount();
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicLibrarySetGlobalParam(
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            sizeof(RawConfig),
            Config));
}
#endif
