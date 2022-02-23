/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the settings logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "SettingsTest.cpp.clog.h"
#endif

#define SETTINGS_FEATURE_SET_TEST(Field, Func, GetFieldValue)                               \
    FieldCount++;                                                                           \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    Settings.IsSet.Field = 1;                                                               \
    Settings.Field = GetFieldValue<decltype(Settings.Field)>(1);                            \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(sizeof(Settings), &Settings, &InternalSettings));   \
    ASSERT_EQ(1u, InternalSettings.IsSet.Field);                                            \
    ASSERT_EQ(GetFieldValue<decltype(InternalSettings.Field)>(1), InternalSettings.Field);  \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    Settings.IsSet.Field = 1;                                                               \
    Settings.Field = GetFieldValue<decltype(Settings.Field)>(0);                            \
    InternalSettings.Field = GetFieldValue<decltype(InternalSettings.Field)>(1);            \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(sizeof(Settings), &Settings, &InternalSettings));   \
    ASSERT_EQ(1u, InternalSettings.IsSet.Field);                                            \
    ASSERT_EQ(GetFieldValue<decltype(InternalSettings.Field)>(0), InternalSettings.Field);  \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    Settings.Field = GetFieldValue<decltype(Settings.Field)>(1);                            \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(sizeof(Settings), &Settings, &InternalSettings));   \
    ASSERT_EQ(0u, InternalSettings.IsSet.Field);                                            \


#define SETTINGS_FEATURE_GET_TEST(Field, Func, GetFieldValue)                               \
    FieldCount++;                                                                           \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    InternalSettings.IsSet.Field = 1;                                                       \
    InternalSettings.Field = GetFieldValue<decltype(InternalSettings.Field)>(1);            \
    SettingsLength = sizeof(Settings);                                                      \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(&InternalSettings, &SettingsLength, &Settings));    \
    ASSERT_EQ(1u, Settings.IsSet.Field);                                                    \
    ASSERT_EQ(GetFieldValue<decltype(Settings.Field)>(1), Settings.Field);                  \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    InternalSettings.IsSet.Field = 1;                                                       \
    InternalSettings.Field = GetFieldValue<decltype(InternalSettings.Field)>(0);            \
    Settings.Field = GetFieldValue<decltype(Settings.Field)>(1);                            \
    SettingsLength = sizeof(Settings);                                                      \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(&InternalSettings, &SettingsLength, &Settings));    \
    ASSERT_EQ(1u, Settings.IsSet.Field);                                                    \
    ASSERT_EQ(GetFieldValue<decltype(Settings.Field)>(0), Settings.Field);                  \
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));                          \
    CxPlatZeroMemory(&Settings, sizeof(Settings));                                          \
    InternalSettings.Field = GetFieldValue<decltype(InternalSettings.Field)>(1);            \
    SettingsLength = sizeof(Settings);                                                      \
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Func(&InternalSettings, &SettingsLength, &Settings));    \
    ASSERT_EQ(0u, Settings.IsSet.Field);

template<typename T>
static int PopCount(T Value) {
    int Count = 0;
    for (int i = 0; i < sizeof(Value) * 8; i++) {
        if (Value & 0x1) {
            Count++;
        }
        Value >>= 1;
    }
    return Count;
}

template<typename T>
T GetIntValue(T val) {
    return val;
}

template<typename T>
T GetCCValue(int val) {
    return static_cast<QUIC_CONGESTION_CONTROL_ALGORITHM>(val);
}

TEST(SettingsTest, TestAllSettingsFieldsSet)
{
    QUIC_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    int FieldCount = 0;

    SETTINGS_FEATURE_SET_TEST(MaxBytesPerKey, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(HandshakeIdleTimeoutMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(IdleTimeoutMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MtuDiscoverySearchCompleteTimeoutUs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(TlsClientMaxSendBuffer, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(TlsServerMaxSendBuffer, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(StreamRecvWindowDefault, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(StreamRecvBufferDefault, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(ConnFlowControlWindow, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MaxWorkerQueueDelayUs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MaxStatelessOperations, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(InitialWindowPackets, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(SendIdleTimeoutMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(InitialRttMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MaxAckDelayMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(DisconnectTimeoutMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(KeepAliveIntervalMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(CongestionControlAlgorithm, QuicSettingsSettingsToInternal, GetCCValue);
    SETTINGS_FEATURE_SET_TEST(PeerBidiStreamCount, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(PeerUnidiStreamCount, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MaxBindingStatelessOperations, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(StatelessOperationExpirationMs, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MinimumMtu, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MaximumMtu, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MaxOperationsPerDrain, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MtuDiscoveryMissingProbeCount, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(SendBufferingEnabled, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(PacingEnabled, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(MigrationEnabled, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(DatagramReceiveEnabled, QuicSettingsSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(ServerResumptionLevel, QuicSettingsSettingsToInternal, GetIntValue);

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllGlobalSettingsFieldsSet)
{
    QUIC_GLOBAL_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    int FieldCount = 0;

    SETTINGS_FEATURE_SET_TEST(RetryMemoryLimit, QuicSettingsGlobalSettingsToInternal, GetIntValue);
    SETTINGS_FEATURE_SET_TEST(LoadBalancingMode, QuicSettingsGlobalSettingsToInternal, GetIntValue);

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllVersionSettingsFieldsSet)
{
    QUIC_VERSION_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    int FieldCount = 0;

    SETTINGS_FEATURE_SET_TEST(VersionNegotiationExtEnabled, QuicSettingsVersionSettingsToInternal, GetIntValue);

    FieldCount++; // Force increment field count for separately tested version field

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllSettingsFieldsGet)
{
    QUIC_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t SettingsLength;
    int FieldCount = 0;

    SETTINGS_FEATURE_GET_TEST(MaxBytesPerKey, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(HandshakeIdleTimeoutMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(IdleTimeoutMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MtuDiscoverySearchCompleteTimeoutUs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(TlsClientMaxSendBuffer, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(TlsServerMaxSendBuffer, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(StreamRecvWindowDefault, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(StreamRecvBufferDefault, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(ConnFlowControlWindow, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MaxWorkerQueueDelayUs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MaxStatelessOperations, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(InitialWindowPackets, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(SendIdleTimeoutMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(InitialRttMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MaxAckDelayMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(DisconnectTimeoutMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(KeepAliveIntervalMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(CongestionControlAlgorithm, QuicSettingsGetSettings, GetCCValue);
    SETTINGS_FEATURE_GET_TEST(PeerBidiStreamCount, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(PeerUnidiStreamCount, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MaxBindingStatelessOperations, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(StatelessOperationExpirationMs, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MinimumMtu, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MaximumMtu, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MaxOperationsPerDrain, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MtuDiscoveryMissingProbeCount, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(SendBufferingEnabled, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(PacingEnabled, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(MigrationEnabled, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(DatagramReceiveEnabled, QuicSettingsGetSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(ServerResumptionLevel, QuicSettingsGetSettings, GetIntValue);

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllGlobalSettingsFieldsGet)
{
    QUIC_GLOBAL_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t SettingsLength;
    int FieldCount = 0;

    SETTINGS_FEATURE_GET_TEST(RetryMemoryLimit, QuicSettingsGetGlobalSettings, GetIntValue);
    SETTINGS_FEATURE_GET_TEST(LoadBalancingMode, QuicSettingsGetGlobalSettings, GetIntValue);

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

TEST(SettingsTest, TestAllVersionSettingsFieldsGet)
{
    QUIC_VERSION_SETTINGS Settings;
    QUIC_SETTINGS_INTERNAL InternalSettings;
    uint32_t SettingsLength;
    int FieldCount = 0;

    SETTINGS_FEATURE_GET_TEST(VersionNegotiationExtEnabled, QuicSettingsGetVersionSettings, GetIntValue);

    FieldCount++; // Force increment field count for separately tested version field

    Settings.IsSetFlags = 0;
    Settings.IsSet.RESERVED = ~Settings.IsSet.RESERVED;
    ASSERT_EQ(FieldCount, (sizeof(Settings.IsSetFlags) * 8) - PopCount(Settings.IsSetFlags));
}

#define SETTINGS_SIZE_THRU_FIELD(SettingsType, Field) \
    (FIELD_OFFSET(SettingsType, Field) + sizeof(((SettingsType*)0)->Field))

TEST(SettingsTest, SettingsSizesGet)
{
    uint8_t Buffer[sizeof(QUIC_SETTINGS) * 2];
    QUIC_SETTINGS_INTERNAL InternalSettings;

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
    QUIC_SETTINGS_INTERNAL InternalSettings;

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
    QUIC_SETTINGS_INTERNAL InternalSettings;

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
    QUIC_SETTINGS_INTERNAL InternalSettings;

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
