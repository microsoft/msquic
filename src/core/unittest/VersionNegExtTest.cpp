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
    if (Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) {
        MsQuicLib.Settings.VersionSettings = NULL;
        MsQuicLib.Settings.IsSet.VersionSettings = FALSE;
    }
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
