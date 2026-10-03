/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC Version Negotiation Extension transport parameter
    encoding and decoding logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "VersionNegExtTest.cpp.clog.h"
#endif

class WithType : public testing::Test,
    public testing::WithParamInterface<QUIC_HANDLE_TYPE> {
};

std::ostream& operator << (std::ostream& o, const QUIC_HANDLE_TYPE& arg) {
    switch(arg) {
    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
        return o << "Client";
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
        return o << "Server";
    default:
        return o << arg;
    }
}

TEST_P(WithType, ParseVersionInfoFail)
{
    const uint8_t ValidVI[] = {
        0,0,0,1,        // Chosen Version
        0,0,0,1,        // Available Versions List[0]
        0xab,0xcd,0,0,  // Available Versions List[1]
        0xff,0,0,0x1d   // Available Versions List[2]
    };

    QUIC_VERSION_INFORMATION_V1 ParsedVI = {0};
    QUIC_CONNECTION Connection {};
    Connection._.Type = GetParam();

    //
    // Test parsing a valid VI with too short of buffer
    //

    // Not enough room for Chosen Version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            (QUIC_CONNECTION*)&Connection,
            ValidVI,
            3,
            &ParsedVI));

    if (Connection._.Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) {
        // Not enough room for Others Versions List
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicVersionNegotiationExtParseVersionInfo(
                (QUIC_CONNECTION*)&Connection,
                ValidVI,
                4,
                &ParsedVI));
    }

    // Partial Available Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            (QUIC_CONNECTION*)&Connection,
            ValidVI,
            5,
            &ParsedVI));

    // Partial Available Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            (QUIC_CONNECTION*)&Connection,
            ValidVI,
            6,
            &ParsedVI));

    // Partial Available Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            (QUIC_CONNECTION*)&Connection,
            ValidVI,
            11,
            &ParsedVI));

    // Partial Available Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            (QUIC_CONNECTION*)&Connection,
            ValidVI,
            15,
            &ParsedVI));
}

TEST_P(WithType, EncodeDecodeVersionInfo)
{
    auto Type = GetParam();
    uint32_t TestVersions[] = {QUIC_VERSION_1, QUIC_VERSION_2};
    QUIC_VERSION_SETTINGS VerSettings = {
        TestVersions, TestVersions, TestVersions,
        ARRAYSIZE(TestVersions), ARRAYSIZE(TestVersions), ARRAYSIZE(TestVersions)
    };

    QUIC_CONNECTION Connection {};
    if (Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) {
        MsQuicLib.Settings.VersionSettings = &VerSettings;
        MsQuicLib.Settings.IsSet.VersionSettings = TRUE;
    } else {
        Connection.Settings.VersionSettings = &VerSettings;
        Connection.Settings.IsSet.VersionSettings = TRUE;
    }

    Connection._.Type = Type;
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

    uint32_t VersionInfoLength = 0;
    const uint8_t* VersionInfo =
        QuicVersionNegotiationExtEncodeVersionInfo(&Connection, &VersionInfoLength);

    ASSERT_NE(VersionInfo, nullptr);
    ASSERT_NE(VersionInfoLength, 0ul);

    QUIC_VERSION_INFORMATION_V1 ParsedVI;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        QuicVersionNegotiationExtParseVersionInfo(
            &Connection,
            VersionInfo,
            (uint16_t)VersionInfoLength,
            &ParsedVI));

    ASSERT_EQ(ParsedVI.ChosenVersion, Connection.Stats.QuicVersion);
    ASSERT_EQ(ParsedVI.AvailableVersionsCount, ARRAYSIZE(TestVersions));
    ASSERT_EQ(
        memcmp(
            TestVersions,
            ParsedVI.AvailableVersions,
            sizeof(TestVersions)), 0);

    CXPLAT_FREE(VersionInfo, QUIC_POOL_VERSION_INFO);
    MsQuicLib.Settings.VersionSettings = NULL;
    MsQuicLib.Settings.IsSet.VersionSettings = FALSE;
}

TEST(VersionNegExtTest, GeneratedCompatibleVersionList)
{
    uint8_t Buffer[sizeof(DefaultSupportedVersionsList)];
    {
        //
        // Latest version
        //
        uint32_t CompatibilityListByteLength = 0;
        const uint32_t ExpectedDefaultCompatibleVersions[] = {QUIC_VERSION_1, QUIC_VERSION_2, QUIC_VERSION_MS_1};
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_LATEST,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                NULL,
                &CompatibilityListByteLength));

        ASSERT_EQ(CompatibilityListByteLength, sizeof(ExpectedDefaultCompatibleVersions));
        ASSERT_LE(CompatibilityListByteLength, sizeof(Buffer));

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_LATEST,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                Buffer,
                &CompatibilityListByteLength));
        ASSERT_EQ(
            0,
            memcmp(
                ExpectedDefaultCompatibleVersions,
                Buffer,
                sizeof(ExpectedDefaultCompatibleVersions)));
    }

    {
        //
        // Version 2
        //
        const uint32_t ExpectedVersion2CompatibleVersions[] = {QUIC_VERSION_2};
        uint32_t CompatibilityListByteLength = 0;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_2,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                NULL,
                &CompatibilityListByteLength));

        ASSERT_EQ(CompatibilityListByteLength, sizeof(ExpectedVersion2CompatibleVersions));
        ASSERT_LE(CompatibilityListByteLength, sizeof(Buffer));

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_2,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                Buffer,
                &CompatibilityListByteLength));
        ASSERT_EQ(
            0,
            memcmp(
                ExpectedVersion2CompatibleVersions,
                Buffer,
                sizeof(ExpectedVersion2CompatibleVersions)));
    }

    {
        //
        // Version 1
        //
        const uint32_t ExpectedVersion1CompatibleVersions[] = {QUIC_VERSION_1, QUIC_VERSION_2, QUIC_VERSION_MS_1};
        uint32_t CompatibilityListByteLength = 0;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_1,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                NULL,
                &CompatibilityListByteLength));

        ASSERT_EQ(CompatibilityListByteLength, sizeof(ExpectedVersion1CompatibleVersions));
        ASSERT_LE(CompatibilityListByteLength, sizeof(Buffer));

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_1,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                Buffer,
                &CompatibilityListByteLength));
        ASSERT_EQ(
            0,
            memcmp(
                ExpectedVersion1CompatibleVersions,
                Buffer,
                sizeof(ExpectedVersion1CompatibleVersions)));
    }

    {
        //
        // Version MS 1
        //
        const uint32_t ExpectedVersionMS1CompatibleVersions[] = {QUIC_VERSION_MS_1, QUIC_VERSION_1};
        uint32_t CompatibilityListByteLength = 0;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_MS_1,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                NULL,
                &CompatibilityListByteLength));

        ASSERT_EQ(CompatibilityListByteLength, sizeof(ExpectedVersionMS1CompatibleVersions));
        ASSERT_LE(CompatibilityListByteLength, sizeof(Buffer));

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_MS_1,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                Buffer,
                &CompatibilityListByteLength));
        ASSERT_EQ(
            0,
            memcmp(
                ExpectedVersionMS1CompatibleVersions,
                Buffer,
                sizeof(ExpectedVersionMS1CompatibleVersions)));
    }

    {
        //
        // Draft 29 Version
        //
        const uint32_t ExpectedVersionDraft29CompatibleVersions[] = {QUIC_VERSION_DRAFT_29};
        uint32_t CompatibilityListByteLength = 0;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_DRAFT_29,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                NULL,
                &CompatibilityListByteLength));

        ASSERT_EQ(CompatibilityListByteLength, sizeof(ExpectedVersionDraft29CompatibleVersions));
        ASSERT_LE(CompatibilityListByteLength, sizeof(Buffer));

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                QUIC_VERSION_DRAFT_29,
                DefaultSupportedVersionsList,
                ARRAYSIZE(DefaultSupportedVersionsList),
                Buffer,
                &CompatibilityListByteLength));
        ASSERT_EQ(
            0,
            memcmp(
                ExpectedVersionDraft29CompatibleVersions,
                Buffer,
                sizeof(ExpectedVersionDraft29CompatibleVersions)));
    }

    {
        //
        // No Versions in common
        //
        const uint32_t TestOriginalVersion = QUIC_VERSION_2;
        const uint32_t TestSupportedVersions[] = {QUIC_VERSION_MS_1, QUIC_VERSION_DRAFT_29};
        const uint32_t ExpectedNoCommonVersionsCompatibleVersions[] = {QUIC_VERSION_2};
        uint32_t CompatibilityListByteLength = 0;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                TestOriginalVersion,
                TestSupportedVersions,
                ARRAYSIZE(TestSupportedVersions),
                NULL,
                &CompatibilityListByteLength));

        ASSERT_EQ(CompatibilityListByteLength, sizeof(ExpectedNoCommonVersionsCompatibleVersions));
        ASSERT_LE(CompatibilityListByteLength, sizeof(Buffer));

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                TestOriginalVersion,
                TestSupportedVersions,
                ARRAYSIZE(TestSupportedVersions),
                Buffer,
                &CompatibilityListByteLength));
        ASSERT_EQ(
            0,
            memcmp(
                ExpectedNoCommonVersionsCompatibleVersions,
                Buffer,
                sizeof(ExpectedNoCommonVersionsCompatibleVersions)));
    }
}

INSTANTIATE_TEST_SUITE_P(
    VersionNegExtTest,
    WithType,
    ::testing::Values(QUIC_HANDLE_TYPE_CONNECTION_SERVER, QUIC_HANDLE_TYPE_CONNECTION_CLIENT));

//
// The version-specific cryptographic constants are published in the standards,
// so they can be checked directly instead of being taken on trust from the table
// that is meant to carry them:
//
//   QUIC v1 -- RFC 9001: Initial salt (5.2), HKDF labels (5.1), Retry
//              integrity secret (5.8).
//   QUIC v2 -- RFC 9369: Initial salt (3.3.1), HKDF labels (3.3.2), Retry
//              integrity secret (3.3.3).
//
// This is not hypothetical coverage. The v2 Retry integrity secret had been left
// at the draft-ietf-quic-v2-03 value when the Initial salt immediately above it
// was updated to the RFC's, so msquic computed the v2 Retry integrity tag with a
// key no RFC 9369 peer derives.
//
TEST(VersionNegExtTest, SupportedVersionConstantsMatchSpecs)
{
    const uint8_t V1Salt[] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    const uint8_t V1RetrySecret[] = {
        0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21,
        0x50, 0x6b, 0xcc, 0x02, 0x81, 0x4c, 0x73, 0x03, 0x0f, 0x25,
        0xc7, 0x9d, 0x71, 0xce, 0x87, 0x6e, 0xca, 0x87, 0x6e, 0x6f,
        0xca, 0x8e
    };
    const uint8_t V2Salt[] = {
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    };
    const uint8_t V2RetrySecret[] = {
        0xc4, 0xdd, 0x24, 0x84, 0xd6, 0x81, 0xae, 0xfa, 0x4f, 0xf4,
        0xd6, 0x9c, 0x2c, 0x20, 0x29, 0x99, 0x84, 0xa7, 0x65, 0xa5,
        0xd3, 0xc3, 0x19, 0x82, 0xf3, 0x8f, 0xc7, 0x41, 0x62, 0x15,
        0x5e, 0x9f
    };

    struct {
        uint32_t Version;
        const char* Name;
        const uint8_t* Salt;
        const uint8_t* RetrySecret;
        QUIC_HKDF_LABELS Labels;
    } Expected[] = {
        { QUIC_VERSION_1, "QUIC v1 (RFC 9001)", V1Salt, V1RetrySecret,
          { "quic key", "quic iv", "quic hp", "quic ku" } },
        { QUIC_VERSION_2, "QUIC v2 (RFC 9369)", V2Salt, V2RetrySecret,
          { "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku" } },
    };

    for (uint32_t e = 0; e < ARRAYSIZE(Expected); ++e) {
        const QUIC_VERSION_INFO* Info = nullptr;
        for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
            if (QuicSupportedVersionList[i].Number == Expected[e].Version) {
                Info = &QuicSupportedVersionList[i];
                break;
            }
        }
        ASSERT_NE(nullptr, Info) << Expected[e].Name << " is not in QuicSupportedVersionList";
        ASSERT_EQ(0, memcmp(Info->Salt, Expected[e].Salt, sizeof(Info->Salt)))
            << Expected[e].Name << ": Initial salt";
        ASSERT_EQ(0,
            memcmp(
                Info->RetryIntegritySecret,
                Expected[e].RetrySecret,
                sizeof(Info->RetryIntegritySecret)))
            << Expected[e].Name << ": Retry integrity secret";
        ASSERT_STREQ(Expected[e].Labels.KeyLabel, Info->HkdfLabels.KeyLabel)
            << Expected[e].Name;
        ASSERT_STREQ(Expected[e].Labels.IvLabel, Info->HkdfLabels.IvLabel)
            << Expected[e].Name;
        ASSERT_STREQ(Expected[e].Labels.HpLabel, Info->HkdfLabels.HpLabel)
            << Expected[e].Name;
        ASSERT_STREQ(Expected[e].Labels.KuLabel, Info->HkdfLabels.KuLabel)
            << Expected[e].Name;
    }
}
