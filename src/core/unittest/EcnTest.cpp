/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

struct QUIC_CONNECTION;
struct QUIC_CONGESTION_CONTROL;
struct QUIC_SETTINGS_INTERNAL;
struct QUIC_PATH;

extern "C" {
void QuicCongestionControlInitialize(QUIC_CONGESTION_CONTROL*, const QUIC_SETTINGS_INTERNAL*);
void QuicPathInitialize(QUIC_CONNECTION*, QUIC_PATH*);
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

    void SetUp() override {
        Connection._.Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        QuicSettingsSetDefault(&Connection.Settings);
        Connection.Paths[0].Mtu = Connection.Settings.MinimumMtu;
        Connection.PathsCount = 1;
    }

    void Initialize(QUIC_CONGESTION_CONTROL_ALGORITHM Algorithm, BOOLEAN EcnEnabled) {
        Connection.Settings.CongestionControlAlgorithm = (uint16_t)Algorithm;
        Connection.Settings.EcnEnabled = EcnEnabled;
        QuicCongestionControlInitialize(&Connection.CongestionControl, &Connection.Settings);
        QuicPathInitialize(&Connection, &Connection.Paths[0]);
    }

    ECN_VALIDATION_STATE ExpectedState(BOOLEAN EcnEnabled) const {
        return EcnEnabled && GetParam() == QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC ?
            ECN_VALIDATION_TESTING : ECN_VALIDATION_FAILED;
    }
};

TEST_P(EcnTest, PathInitializationRequiresCongestionResponse)
{
    for (BOOLEAN Enabled : {BOOLEAN(FALSE), BOOLEAN(TRUE)}) {
        Initialize(GetParam(), Enabled);
        EXPECT_EQ(ExpectedState(Enabled), (ECN_VALIDATION_STATE)Connection.Paths[0].EcnValidationState);

        QuicPathInitialize(&Connection, &Connection.Paths[1]);
        EXPECT_EQ(ExpectedState(Enabled), (ECN_VALIDATION_STATE)Connection.Paths[1].EcnValidationState);
    }
}

TEST_P(EcnTest, ChangingControllerReevaluatesEcnSupport)
{
    Initialize(QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, TRUE);
    ASSERT_EQ(ECN_VALIDATION_TESTING, (ECN_VALIDATION_STATE)Connection.Paths[0].EcnValidationState);

    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.IsSet.CongestionControlAlgorithm = TRUE;
    Settings.CongestionControlAlgorithm = (uint16_t)GetParam();
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ExpectedState(TRUE), (ECN_VALIDATION_STATE)Connection.Paths[0].EcnValidationState);

    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ECN_VALIDATION_TESTING, (ECN_VALIDATION_STATE)Connection.Paths[0].EcnValidationState);
}

TEST_P(EcnTest, ChangingEcnSettingReevaluatesValidation)
{
    Initialize(GetParam(), TRUE);

    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.IsSet.EcnEnabled = TRUE;
    Settings.EcnEnabled = FALSE;
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ECN_VALIDATION_FAILED, (ECN_VALIDATION_STATE)Connection.Paths[0].EcnValidationState);

    Settings.EcnEnabled = TRUE;
    ASSERT_TRUE(QuicConnApplyNewSettings(&Connection, TRUE, &Settings));
    EXPECT_EQ(ExpectedState(TRUE), (ECN_VALIDATION_STATE)Connection.Paths[0].EcnValidationState);
}

INSTANTIATE_TEST_SUITE_P(
    Algorithms,
    EcnTest,
    ::testing::Values(
        QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC,
        QUIC_CONGESTION_CONTROL_ALGORITHM_BBR,
        QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3));
