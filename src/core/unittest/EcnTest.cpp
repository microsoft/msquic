/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_platform.h"

struct QUIC_CONGESTION_CONTROL;
struct QUIC_SETTINGS_INTERNAL;
struct QUIC_REGISTRATION_CONFIG;
struct QUIC_HANDLE;
struct QUIC_CONNECTION_EVENT;

extern "C" {
void QuicCongestionControlInitialize(QUIC_CONGESTION_CONTROL*, const QUIC_SETTINGS_INTERNAL*);
QUIC_STATUS QUIC_API MsQuicRegistrationOpen(const QUIC_REGISTRATION_CONFIG*, QUIC_HANDLE**);
void QUIC_API MsQuicRegistrationClose(QUIC_HANDLE*);
QUIC_STATUS QUIC_API MsQuicConnectionOpen(
    QUIC_HANDLE*,
    QUIC_STATUS (QUIC_API *)(QUIC_HANDLE*, void*, QUIC_CONNECTION_EVENT*),
    void*,
    QUIC_HANDLE**);
void QUIC_API MsQuicConnectionClose(QUIC_HANDLE*);
}

#include "main.h"

extern "C" {
BOOLEAN
QuicConnApplyNewSettings(
    QUIC_CONNECTION* Connection,
    BOOLEAN OverWrite,
    const QUIC_SETTINGS_INTERNAL* NewSettings
    );
}

class EcnTest : public ::testing::TestWithParam<QUIC_CONGESTION_CONTROL_ALGORITHM> {
protected:
    QUIC_CONNECTION Connection{};
    QUIC_CID_LIST_ENTRY* EmptyCid{nullptr};

    void SetUp() override {
        Connection._.Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        QuicSettingsSetDefault(&Connection.Settings);
        QuicPathSetInitialize(&Connection.Paths, &Connection);
        EmptyCid = QuicCidNewDestination(0, nullptr);
        ASSERT_NE(nullptr, EmptyCid);
    }

    void TearDown() override {
        CXPLAT_FREE(EmptyCid, QUIC_POOL_CIDLIST);
    }

    void Initialize(QUIC_CONGESTION_CONTROL_ALGORITHM Algorithm, BOOLEAN EcnEnabled) {
        Connection.Settings.CongestionControlAlgorithm = (uint16_t)Algorithm;
        Connection.Settings.EcnEnabled = EcnEnabled;
        QuicCongestionControlInitialize(&Connection.CongestionControl, &Connection.Settings);
        QuicPathSetInitialize(&Connection.Paths, &Connection);
    }

    ECN_VALIDATION_STATE ExpectedState(BOOLEAN EcnEnabled) const {
        return EcnEnabled && GetParam() == QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC ?
            ECN_VALIDATION_TESTING : ECN_VALIDATION_FAILED;
    }

    static QUIC_STATUS QUIC_API ConnectionCallback(
        HQUIC,
        void*,
        QUIC_CONNECTION_EVENT*) {
        return QUIC_STATUS_SUCCESS;
    }
};

TEST_P(EcnTest, ConnectionAllocationRequiresCongestionResponse)
{
    HQUIC Registration = nullptr;
    const QUIC_REGISTRATION_CONFIG Config{"EcnTest", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    ASSERT_TRUE(QUIC_SUCCEEDED(MsQuicRegistrationOpen(&Config, &Registration)));
    for (BOOLEAN Enabled : {BOOLEAN(FALSE), BOOLEAN(TRUE)}) {
        const uint16_t PreviousAlgorithm = MsQuicLib.Settings.CongestionControlAlgorithm;
        const BOOLEAN PreviousEcnEnabled = MsQuicLib.Settings.EcnEnabled;
        MsQuicLib.Settings.CongestionControlAlgorithm = (uint16_t)GetParam();
        MsQuicLib.Settings.EcnEnabled = Enabled;
        HQUIC Handle = nullptr;
        const QUIC_STATUS Status = MsQuicConnectionOpen(Registration, ConnectionCallback, nullptr, &Handle);
        MsQuicLib.Settings.CongestionControlAlgorithm = PreviousAlgorithm;
        MsQuicLib.Settings.EcnEnabled = PreviousEcnEnabled;

        EXPECT_TRUE(QUIC_SUCCEEDED(Status));
        if (QUIC_SUCCEEDED(Status)) {
            const auto* AllocatedConnection = reinterpret_cast<const QUIC_CONNECTION*>(Handle);
            EXPECT_EQ(GetParam(), AllocatedConnection->Settings.CongestionControlAlgorithm);
            EXPECT_EQ(ExpectedState(Enabled),
                (ECN_VALIDATION_STATE)QuicPathGetActive(&AllocatedConnection->Paths)->EcnValidationState);
            MsQuicConnectionClose(Handle);
        }
    }
    MsQuicRegistrationClose(Registration);
}

TEST_P(EcnTest, PathInitializationRequiresCongestionResponse)
{
    for (BOOLEAN Enabled : {BOOLEAN(FALSE), BOOLEAN(TRUE)}) {
        Initialize(GetParam(), Enabled);
        EXPECT_EQ(ExpectedState(Enabled), (ECN_VALIDATION_STATE)QuicPathGetActive(&Connection.Paths)->EcnValidationState);

        Connection.State.HandshakeConfirmed = TRUE;
        QuicPathGetActive(&Connection.Paths)->DestCid = EmptyCid;
        CXPLAT_ROUTE PacketRoute{};
        PacketRoute.DatapathType = 1; // CXPLAT_DATAPATH_TYPE_NORMAL
        ASSERT_TRUE(QuicAddrFromString("192.0.2.1", 1000, &PacketRoute.LocalAddress));
        ASSERT_TRUE(QuicAddrFromString("198.51.100.1", 2000, &PacketRoute.RemoteAddress));
        QUIC_RX_PACKET Packet{};
        Packet._.Route = &PacketRoute;
        const QUIC_PATH* Path = QuicConnGetPathForPacket(&Connection, &Packet);
        ASSERT_NE(nullptr, Path);
        EXPECT_EQ(2, Connection.Paths.Count);
        EXPECT_EQ(ExpectedState(Enabled), (ECN_VALIDATION_STATE)Path->EcnValidationState);
    }
}

TEST_P(EcnTest, ChangingControllerReevaluatesEcnSupport)
{
    Initialize(QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, TRUE);
    ASSERT_EQ(ECN_VALIDATION_TESTING, (ECN_VALIDATION_STATE)QuicPathGetActive(&Connection.Paths)->EcnValidationState);

    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.IsSet.CongestionControlAlgorithm = TRUE;
    Settings.CongestionControlAlgorithm = (uint16_t)GetParam();
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ExpectedState(TRUE), (ECN_VALIDATION_STATE)QuicPathGetActive(&Connection.Paths)->EcnValidationState);

    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ECN_VALIDATION_TESTING, (ECN_VALIDATION_STATE)QuicPathGetActive(&Connection.Paths)->EcnValidationState);
}

TEST_P(EcnTest, ChangingEcnSettingReevaluatesValidation)
{
    Initialize(GetParam(), TRUE);

    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.IsSet.EcnEnabled = TRUE;
    Settings.EcnEnabled = FALSE;
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ECN_VALIDATION_FAILED, (ECN_VALIDATION_STATE)QuicPathGetActive(&Connection.Paths)->EcnValidationState);

    Settings.EcnEnabled = TRUE;
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ExpectedState(TRUE), (ECN_VALIDATION_STATE)QuicPathGetActive(&Connection.Paths)->EcnValidationState);
}

INSTANTIATE_TEST_SUITE_P(
    Algorithms,
    EcnTest,
    ::testing::Values(
        QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC,
        QUIC_CONGESTION_CONTROL_ALGORITHM_BBR,
        QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3));
