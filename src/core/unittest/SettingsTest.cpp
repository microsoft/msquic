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
    SETTINGS_FEATURE_SET_TEST(RioEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(OneWayDelayEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(NetStatsEventEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_SET_TEST(StreamMultiReceiveEnabled, QuicSettingsSettingsToInternal);

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
    SETTINGS_FEATURE_SET_TEST(RioEnabled, QuicSettingsSettingsToInternal);
    SETTINGS_FEATURE_GET_TEST(OneWayDelayEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(NetStatsEventEnabled, QuicSettingsGetSettings);
    SETTINGS_FEATURE_GET_TEST(StreamMultiReceiveEnabled, QuicSettingsGetSettings);

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

TEST(SettingsTest, CertainDefaultsGetOverridenByIndividualLimits)
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

    Source.IsSet.ResumptionTicketMinVersion = 1;
    Source.ResumptionTicketMinVersion = 1;

    Source.IsSet.ResumptionTicketMaxVersion = 1;
    Source.ResumptionTicketMaxVersion = 2;

    ASSERT_TRUE(QuicSettingApply(&Destination, TRUE, TRUE, &Source));

    ASSERT_EQ(Destination.StreamRecvWindowDefault, Source.StreamRecvWindowDefault);
    ASSERT_EQ(Destination.StreamRecvWindowBidiLocalDefault, Source.StreamRecvWindowBidiLocalDefault);
    ASSERT_EQ(Destination.StreamRecvWindowBidiRemoteDefault, Source.StreamRecvWindowBidiRemoteDefault);
    ASSERT_EQ(Destination.StreamRecvWindowUnidiDefault, Source.StreamRecvWindowUnidiDefault);
    ASSERT_EQ(Destination.ResumptionTicketMinVersion, Source.ResumptionTicketMinVersion);
    ASSERT_EQ(Destination.ResumptionTicketMaxVersion, Source.ResumptionTicketMaxVersion);
}

TEST(SettingsTest, CertainDefaultsDoNotGetOverridenDueToLimits)
{
    QUIC_SETTINGS_INTERNAL Source;
    QUIC_SETTINGS_INTERNAL Destination;
    CxPlatZeroMemory(&Source, sizeof(Source));
    CxPlatZeroMemory(&Destination, sizeof(Destination));

    Source.IsSet.ResumptionTicketMinVersion = 1;
    Source.ResumptionTicketMinVersion = 0;

    Source.IsSet.ResumptionTicketMaxVersion = 1;
    Source.ResumptionTicketMaxVersion = 5;

    ASSERT_TRUE(QuicSettingApply(&Destination, TRUE, TRUE, &Source));

    ASSERT_NE(Destination.ResumptionTicketMinVersion, Source.ResumptionTicketMinVersion);
    ASSERT_NE(Destination.ResumptionTicketMaxVersion, Source.ResumptionTicketMaxVersion);

    Source.IsSet.ResumptionTicketMinVersion = 1;
    Source.ResumptionTicketMinVersion = 1;

    Source.IsSet.ResumptionTicketMaxVersion = 1;
    Source.ResumptionTicketMaxVersion = 0;

    ASSERT_TRUE(QuicSettingApply(&Destination, TRUE, TRUE, &Source));

    ASSERT_EQ(Destination.ResumptionTicketMinVersion, Source.ResumptionTicketMinVersion);
    ASSERT_EQ(Destination.ResumptionTicketMaxVersion, Source.ResumptionTicketMinVersion);
    ASSERT_NE(Destination.ResumptionTicketMaxVersion, Source.ResumptionTicketMaxVersion);

    Source.IsSet.ResumptionTicketMinVersion = 1;
    Source.ResumptionTicketMinVersion = 2;

    Source.IsSet.ResumptionTicketMaxVersion = 1;
    Source.ResumptionTicketMaxVersion = 1;

    ASSERT_TRUE(QuicSettingApply(&Destination, TRUE, TRUE, &Source));

    ASSERT_EQ(Destination.ResumptionTicketMinVersion, Source.ResumptionTicketMinVersion);
    ASSERT_EQ(Destination.ResumptionTicketMaxVersion, Source.ResumptionTicketMinVersion);
    ASSERT_NE(Destination.ResumptionTicketMaxVersion, Source.ResumptionTicketMaxVersion);

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

TEST(SettingsTest, QuicSettingsSetDefault_SetsAllDefaultsWhenUnset)
{
    QUIC_SETTINGS_INTERNAL s;
    CxPlatZeroMemory(&s, sizeof(s));

    // Set all IsSet fields to 0 to simulate unset state
    s.IsSetFlags = 0;

    QuicSettingsSetDefault(&s);

    // Spot-check a few representative fields (add more as needed)
    ASSERT_EQ(s.SendBufferingEnabled, QUIC_DEFAULT_SEND_BUFFERING_ENABLE);
    ASSERT_EQ(s.PacingEnabled, QUIC_DEFAULT_SEND_PACING);
    ASSERT_EQ(s.MigrationEnabled, QUIC_DEFAULT_MIGRATION_ENABLED);
    ASSERT_EQ(s.DatagramReceiveEnabled, QUIC_DEFAULT_DATAGRAM_RECEIVE_ENABLED);
    ASSERT_EQ(s.MaxOperationsPerDrain, QUIC_MAX_OPERATIONS_PER_DRAIN);
    ASSERT_EQ(s.RetryMemoryLimit, QUIC_DEFAULT_RETRY_MEMORY_FRACTION);
    ASSERT_EQ(s.LoadBalancingMode, QUIC_DEFAULT_LOAD_BALANCING_MODE);
    ASSERT_EQ(s.FixedServerID, 0u);
    ASSERT_EQ(s.MaxWorkerQueueDelayUs, MS_TO_US(QUIC_MAX_WORKER_QUEUE_DELAY));
    ASSERT_EQ(s.MaxStatelessOperations, QUIC_MAX_STATELESS_OPERATIONS);
    ASSERT_EQ(s.InitialWindowPackets, QUIC_INITIAL_WINDOW_PACKETS);
    ASSERT_EQ(s.SendIdleTimeoutMs, QUIC_DEFAULT_SEND_IDLE_TIMEOUT_MS);
    ASSERT_EQ(s.InitialRttMs, QUIC_INITIAL_RTT);
    ASSERT_EQ(s.MaxAckDelayMs, QUIC_TP_MAX_ACK_DELAY_DEFAULT);
    ASSERT_EQ(s.DisconnectTimeoutMs, QUIC_DEFAULT_DISCONNECT_TIMEOUT);
    ASSERT_EQ(s.KeepAliveIntervalMs, QUIC_DEFAULT_KEEP_ALIVE_INTERVAL);
    ASSERT_EQ(s.IdleTimeoutMs, QUIC_DEFAULT_IDLE_TIMEOUT);
    ASSERT_EQ(s.HandshakeIdleTimeoutMs, QUIC_DEFAULT_HANDSHAKE_IDLE_TIMEOUT);
    ASSERT_EQ(s.PeerBidiStreamCount, 0u);
    ASSERT_EQ(s.PeerUnidiStreamCount, 0u);
    ASSERT_EQ(s.TlsClientMaxSendBuffer, QUIC_MAX_TLS_SERVER_SEND_BUFFER); // Note: last assignment in function
    ASSERT_EQ(s.StreamRecvWindowDefault, QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE);
    ASSERT_EQ(s.StreamRecvWindowBidiLocalDefault, QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE);
    ASSERT_EQ(s.StreamRecvWindowBidiRemoteDefault, QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE);
    ASSERT_EQ(s.StreamRecvWindowUnidiDefault, QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE);
    ASSERT_EQ(s.StreamRecvBufferDefault, QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE);
    ASSERT_EQ(s.ConnFlowControlWindow, QUIC_DEFAULT_CONN_FLOW_CONTROL_WINDOW);
    ASSERT_EQ(s.MaxBytesPerKey, QUIC_DEFAULT_MAX_BYTES_PER_KEY);
    ASSERT_EQ(s.ServerResumptionLevel, (uint8_t)QUIC_DEFAULT_SERVER_RESUMPTION_LEVEL);
    ASSERT_EQ(s.VersionNegotiationExtEnabled, QUIC_DEFAULT_VERSION_NEGOTIATION_EXT_ENABLED);
    ASSERT_EQ(s.MinimumMtu, QUIC_DPLPMTUD_DEFAULT_MIN_MTU);
    ASSERT_EQ(s.MaximumMtu, QUIC_DPLPMTUD_DEFAULT_MAX_MTU);
    ASSERT_EQ(s.MtuDiscoveryMissingProbeCount, QUIC_DPLPMTUD_MAX_PROBES);
    ASSERT_EQ(s.MtuDiscoverySearchCompleteTimeoutUs, QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT);
    ASSERT_EQ(s.MaxBindingStatelessOperations, QUIC_MAX_BINDING_STATELESS_OPERATIONS);
    ASSERT_EQ(s.StatelessOperationExpirationMs, QUIC_STATELESS_OPERATION_EXPIRATION_MS);
    ASSERT_EQ(s.CongestionControlAlgorithm, QUIC_CONGESTION_CONTROL_ALGORITHM_DEFAULT);
    ASSERT_EQ(s.DestCidUpdateIdleTimeoutMs, QUIC_DEFAULT_DEST_CID_UPDATE_IDLE_TIMEOUT_MS);
    ASSERT_EQ(s.GreaseQuicBitEnabled, QUIC_DEFAULT_GREASE_QUIC_BIT_ENABLED);
    ASSERT_EQ(s.EcnEnabled, QUIC_DEFAULT_ECN_ENABLED);
    ASSERT_EQ(s.HyStartEnabled, QUIC_DEFAULT_HYSTART_ENABLED);
    ASSERT_EQ(s.EncryptionOffloadAllowed, QUIC_DEFAULT_ENCRYPTION_OFFLOAD_ALLOWED);
    ASSERT_EQ(s.ReliableResetEnabled, QUIC_DEFAULT_RELIABLE_RESET_ENABLED);
    ASSERT_EQ(s.XdpEnabled, QUIC_DEFAULT_XDP_ENABLED);
    ASSERT_EQ(s.QTIPEnabled, QUIC_DEFAULT_QTIP_ENABLED);
    ASSERT_EQ(s.RioEnabled, QUIC_DEFAULT_RIO_ENABLED);
    ASSERT_EQ(s.OneWayDelayEnabled, QUIC_DEFAULT_ONE_WAY_DELAY_ENABLED);
    ASSERT_EQ(s.NetStatsEventEnabled, QUIC_DEFAULT_NET_STATS_EVENT_ENABLED);
    ASSERT_EQ(s.StreamMultiReceiveEnabled, QUIC_DEFAULT_STREAM_MULTI_RECEIVE_ENABLED);
    ASSERT_EQ(s.ResumptionTicketMinVersion, CXPLAT_TLS_RESUMPTION_TICKET_VERSION);
    ASSERT_EQ(s.ResumptionTicketMaxVersion, CXPLAT_TLS_RESUMPTION_TICKET_VERSION);
}

TEST(SettingsTest, QuicSettingsSetDefault_DoesNotOverwriteSetFields)
{
    QUIC_SETTINGS_INTERNAL s;
    CxPlatZeroMemory(&s, sizeof(s));

    // Set a few fields and mark them as set
    s.IsSet.SendBufferingEnabled = 1;
    s.SendBufferingEnabled = 1;
    s.IsSet.PacingEnabled = 1;
    s.PacingEnabled = 1;
    s.IsSet.ResumptionTicketMinVersion = 1;
    s.ResumptionTicketMinVersion = 40;
    QuicSettingsSetDefault(&s);

    // These should not be overwritten
    ASSERT_EQ(s.SendBufferingEnabled, 1);
    ASSERT_EQ(s.PacingEnabled, 1);
    ASSERT_EQ(s.ResumptionTicketMinVersion, 40);

    // But an unset field should be set to default
    ASSERT_EQ(s.MigrationEnabled, QUIC_DEFAULT_MIGRATION_ENABLED);
}


#include <winreg.h>

static void ResetMsQuicRegistry()
{
    RegDeleteTreeA(
        HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\TEST");
}

static void PersistValue(const char* Name, uint32_t Value)
{
    HKEY hKey;
    LONG err = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\TEST",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    ASSERT_EQ(err, ERROR_SUCCESS);
    err = RegSetValueExA(
        hKey, Name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&Value), sizeof(Value));
    ASSERT_EQ(err, ERROR_SUCCESS);
    RegCloseKey(hKey);
}

// --- Test: QuicSettingsLoad sets fields from storage ---
TEST(SettingsTest, QuicSettingsLoad_SetsFieldsFromStorage)
{
    ResetMsQuicRegistry();

    // Set up storage values for a few settings
    PersistValue(QUIC_SETTING_SEND_BUFFERING_DEFAULT, 1);
    PersistValue(QUIC_SETTING_SEND_PACING_DEFAULT, 0);
    PersistValue(QUIC_SETTING_MIGRATION_ENABLED, 1);
    PersistValue(QUIC_SETTING_MAX_OPERATIONS_PER_DRAIN, 7);

    QUIC_SETTINGS_INTERNAL s;
    CxPlatZeroMemory(&s, sizeof(s));
    CXPLAT_STORAGE* storage = nullptr;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageOpen(
            "TEST",
            nullptr,
            nullptr,
            &storage));

    QuicSettingsLoad(&s, storage);

    // Check that the values were loaded
    ASSERT_EQ(s.SendBufferingEnabled, 1u);
    // PacingEnabled is not set because the key is different in the code (QUIC_SETTING_SEND_PACING_DEFAULT)
    // So let's check MigrationEnabled and MaxOperationsPerDrain
    ASSERT_EQ(s.MigrationEnabled, 1u);
    ASSERT_EQ(s.MaxOperationsPerDrain, 7u);

    // Read resumption ticket version settings
    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MIN_VERSION, 1);
    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MAX_VERSION, 1);
    CxPlatZeroMemory(&s, sizeof(s));
    QuicSettingsLoad(&s, storage);
    ASSERT_EQ(s.ResumptionTicketMinVersion, 1u);
    ASSERT_EQ(s.ResumptionTicketMaxVersion, 1u);

    // These resumption settings version numbers should be overridden by defaults
    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MIN_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_VERSION -1);
    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MAX_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION + 3);
    CxPlatZeroMemory(&s, sizeof(s));
    QuicSettingsLoad(&s, storage);
    ASSERT_EQ(s.ResumptionTicketMinVersion, CXPLAT_TLS_RESUMPTION_TICKET_VERSION);
    ASSERT_EQ(s.ResumptionTicketMaxVersion, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION);

    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MIN_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION);
    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MAX_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_VERSION - 1);
    CxPlatZeroMemory(&s, sizeof(s));
    QuicSettingsLoad(&s, storage);
    ASSERT_EQ(s.ResumptionTicketMinVersion, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION);
    ASSERT_EQ(s.ResumptionTicketMaxVersion, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION);

    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MIN_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION + 3);
    PersistValue(QUIC_SETTING_RESUMPTION_TICKET_MAX_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_VERSION - 1);
    CxPlatZeroMemory(&s, sizeof(s));
    QuicSettingsLoad(&s, storage);
    ASSERT_EQ(s.ResumptionTicketMinVersion, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION);
    ASSERT_EQ(s.ResumptionTicketMaxVersion, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION);

    QuicSettingsDumpNew(&s);

    CxPlatStorageClose(storage);
    ResetMsQuicRegistry();
}

// --- Test: QuicSettingsLoad does not overwrite set fields ---
TEST(SettingsTest, QuicSettingsLoad_DoesNotOverwriteSetFields)
{
    ResetMsQuicRegistry();
    PersistValue(QUIC_SETTING_SEND_BUFFERING_DEFAULT, 0);

    CXPLAT_STORAGE* storage = nullptr;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageOpen(
            "TEST",
            nullptr,
            nullptr,
            &storage));

    QUIC_SETTINGS_INTERNAL s;
    CxPlatZeroMemory(&s, sizeof(s));

    // Mark SendBufferingEnabled as set
    s.IsSet.SendBufferingEnabled = 1;
    s.SendBufferingEnabled = 1;

    QuicSettingsLoad(&s, storage);

    // Should not be overwritten
    ASSERT_EQ(s.SendBufferingEnabled, 1u);

    CxPlatStorageClose(storage);
    ResetMsQuicRegistry();
}

// --- Test: QuicSettingsLoad uses default if storage missing ---
TEST(SettingsTest, QuicSettingsLoad_UsesDefaultIfStorageMissing)
{
    ResetMsQuicRegistry();

    CXPLAT_STORAGE* storage = nullptr;
    ASSERT_NE(
        QUIC_STATUS_SUCCESS,
        CxPlatStorageOpen(
            "TEST",
            nullptr,
            nullptr,
            &storage));

    QUIC_SETTINGS_INTERNAL s;
    CxPlatZeroMemory(&s, sizeof(s));
    QuicSettingsLoad(&s, storage);

    // Should use default
    ASSERT_EQ(s.SendBufferingEnabled, QUIC_DEFAULT_SEND_BUFFERING_ENABLE);
    ASSERT_EQ(s.PacingEnabled, QUIC_DEFAULT_SEND_PACING);
    ASSERT_EQ(s.MigrationEnabled, QUIC_DEFAULT_MIGRATION_ENABLED);

    CxPlatStorageClose(storage);
    ResetMsQuicRegistry();
 }

TEST(SettingsTest, SettingsSizesGet)
{
    uint8_t Buffer[sizeof(QUIC_SETTINGS) * 2];
    CxPlatZeroMemory(Buffer, ARRAYSIZE(Buffer));
    QUIC_SETTINGS_INTERNAL InternalSettings;
    CxPlatZeroMemory(&InternalSettings, sizeof(InternalSettings));

    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_SETTINGS, StreamRecvWindowUnidiDefault);

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

    uint32_t MinimumSettingsSize = (uint32_t)SETTINGS_SIZE_THRU_FIELD(QUIC_SETTINGS, StreamRecvWindowUnidiDefault);

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
