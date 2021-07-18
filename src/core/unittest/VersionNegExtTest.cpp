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

TEST(VersionNegExtTest, ParseVersionInfoFail)
{
    const uint8_t ValidVI[] = {
        0,0,0,1,        // Chosen Version
        0,0,0,1,        // Other Versions List[0]
        0xab,0xcd,0,0,  // Other Versions List[1]
        0xff,0,0,0x1d   // Other Versions List[2]
    };

    QUIC_VERSION_INFORMATION_V1 ParsedVI = {0};
    QUIC_CONNECTION* NoOpConnection = (QUIC_CONNECTION*)0x1;

    //
    // Test parsing a valid VI with too short of buffer
    //

    // Not enough room for Chosen Version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            NoOpConnection,
            ValidVI,
            3,
            &ParsedVI));

    // Not enough room for Others Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            NoOpConnection,
            ValidVI,
            4,
            &ParsedVI));

    // Partial Other Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            NoOpConnection,
            ValidVI,
            5,
            &ParsedVI));

    // Partial Other Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            NoOpConnection,
            ValidVI,
            6,
            &ParsedVI));

    // Partial Other Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            NoOpConnection,
            ValidVI,
            11,
            &ParsedVI));

    // Partial Other Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseVersionInfo(
            NoOpConnection,
            ValidVI,
            15,
            &ParsedVI));
}

TEST(VersionNegExtTest, EncodeDecodeVersionInfo)
{
    uint32_t DesiredVersions[] = {QUIC_VERSION_1, QUIC_VERSION_MS_1};

    for (auto Type : {QUIC_HANDLE_TYPE_CONNECTION_SERVER, QUIC_HANDLE_TYPE_CONNECTION_CLIENT}) {
        struct { QUIC_HANDLE Handle;
            QUIC_CONNECTION Connection;
        } Connection {};
        if (Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) {
            MsQuicLib.Settings.DesiredVersionsList = DesiredVersions;
            MsQuicLib.Settings.DesiredVersionsListLength = ARRAYSIZE(DesiredVersions);
            MsQuicLib.Settings.IsSet.DesiredVersionsList = TRUE;
        } else {
            Connection.Connection.Settings.DesiredVersionsList = DesiredVersions;
            Connection.Connection.Settings.DesiredVersionsListLength = ARRAYSIZE(DesiredVersions);
            Connection.Connection.Settings.IsSet.DesiredVersionsList = TRUE;
        }

        ((QUIC_HANDLE*)&Connection)->Type = Type;
        Connection.Connection.Stats.QuicVersion = QUIC_VERSION_1;

        uint32_t VersionInfoLength = 0;
        const uint8_t* VersionInfo =
            QuicVersionNegotiationExtEncodeVersionInfo((QUIC_CONNECTION*)&Connection, &VersionInfoLength);

        ASSERT_NE(VersionInfo, nullptr);
        ASSERT_NE(VersionInfoLength, 0ul);

        QUIC_VERSION_INFORMATION_V1 ParsedVI;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicVersionNegotiationExtParseVersionInfo(
                (QUIC_CONNECTION*)&Connection,
                VersionInfo,
                (uint16_t)VersionInfoLength,
                &ParsedVI));

        ASSERT_EQ(ParsedVI.ChosenVersion, Connection.Connection.Stats.QuicVersion);
        ASSERT_EQ(ParsedVI.OtherVersionsCount, ARRAYSIZE(DesiredVersions));
        ASSERT_TRUE(memcmp(DesiredVersions, ParsedVI.OtherVersions, sizeof(DesiredVersions)) == 0);

        CXPLAT_FREE(VersionInfo, QUIC_POOL_VERSION_INFO);
        if (Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) {
            MsQuicLib.Settings.DesiredVersionsList = NULL;
            MsQuicLib.Settings.DesiredVersionsListLength = 0;
            MsQuicLib.Settings.IsSet.DesiredVersionsList = FALSE;
        }
    }
}
