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

TEST(VersionNegExtTest, ParseClientVerNegInfoFail)
{
    const uint8_t ValidClientVNI[] = {
        0,0,0,1,        // Original Version
        0,0,0,0,        // Previous Version
        0,              // Received Versions List Length
        2,              // Compatible Versions List Length
        0,0,0,1,        // Compatible Versions List[0]
        0xab,0xcd,0,0   // Compatible Versions List[1]
    };

    QUIC_CLIENT_VER_NEG_INFO OutputClientVNI = {0};
    QUIC_CONNECTION* NoOpConnection = (QUIC_CONNECTION*)0x1;

    //
    // Test parsing a valid VNI with too short of buffer
    //

    // Not enough room for Original Version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            ValidClientVNI,
            3,
            &OutputClientVNI));

    // Not enough room for Previous Version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            ValidClientVNI,
            7,
            &OutputClientVNI));

    // Not enough room for Received Versions List Length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            ValidClientVNI,
            8,
            &OutputClientVNI));

    // Not enough room for Compatible Versions List Length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            ValidClientVNI,
            9,
            &OutputClientVNI));

    // Not enough room for Compatible Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            ValidClientVNI,
            11,
            &OutputClientVNI));

    // Not enough room for Compatible Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            ValidClientVNI,
            17,
            &OutputClientVNI));

    //
    // Test parsing different corrupt/invalid Client VNEs
    //

    // Received Versions List length != 0 when list is not present
    const uint8_t InvalidClientVNI_RecvVer[] = {
        0,0,0,1,        // Original Version
        0,0,0,0,        // Previous Version
        1,              // Invalid Received Versions List Length
        2,              // Compatible Versions List Length
        0xff,0,0,0x1d,  // Compatible Versions List[0]
        0,0,0,1         // Compatible Versions List[1]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_RecvVer,
            (uint16_t)sizeof(InvalidClientVNI_RecvVer),
            &OutputClientVNI));

    // Received Versions List Length improperly encoded var int
    const uint8_t InvalidClientVNI_RecvVer2[] = {
        0,0,0,1,        // Original Version
        0,0,0,0,        // Previous Version
        0xc1,           // Invalid Received Versions List Length
        2,              // Compatible Versions List Length
        0,0,0,1,        // Compatible Versions List[0]
        0xab,0xcd,0,0   // Compatible Versions List[1]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_RecvVer2,
            (uint16_t)sizeof(InvalidClientVNI_RecvVer2),
            &OutputClientVNI));

    // Received Versions List Length is less than actual list length
    const uint8_t InvalidClientVNI_RecvVerUnderflow[] = {
        0,0,0,1,        // Original Version
        0,0,0,0,        // Previous Version
        1,              // Invalid Received Versions List Length
        0,0,0,1,        // Received Versions List[0]
        0xab,0xcd,0,0,  // Received Versions List[1]
        2,              // Compatible Versions List Length
        0,0,0,1,        // Compatible Versions List[0]
        0xab,0xcd,0,0   // Compatible Versions List[1]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_RecvVerUnderflow,
            (uint16_t)sizeof(InvalidClientVNI_RecvVerUnderflow),
            &OutputClientVNI));

    // Compatible Versions List Length is greater than actual list length
    const uint8_t InvalidClientVNI_CompatVer[] = {
        0,0,0,1,                // Original Version
        0x0a,0x0a,0x0a,0x0a,    // Previous Version
        1,                      // Received Versions List Length
        0,0,0,1,                // Received Versions List[0]
        2,                      // Invalid Compatible Versions List Length
        0,0,0,1,                // Compatible Versions List[0]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_CompatVer,
            (uint16_t)sizeof(InvalidClientVNI_CompatVer),
            &OutputClientVNI));

    // Compatible Versions List Length improperly encoded var int
    const uint8_t InvalidClientVNI_CompatVer2[] = {
        0,0,0,1,                // Original Version
        0x0a,0x0a,0x0a,0x0a,    // Previous Version
        1,                      // Received Versions List Length
        0,0,0,1,                // Received Versions List[0]
        0xc2,                   // Invalid Compatible Versions List Length
        0,0,0,1,                // Compatible Versions List[0]
        0xab,0xcd,0,0           // Compatible Versions List[1]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_CompatVer2,
            (uint16_t)sizeof(InvalidClientVNI_CompatVer2),
            &OutputClientVNI));

    // Compatible Versions List Length less than actual list length
    const uint8_t InvalidClientVNI_CompatVerUnderflow[] = {
        0,0,0,1,                // Original Version
        0x0a,0x0a,0x0a,0x0a,    // Previous Version
        1,                      // Received Versions List Length
        0,0,0,1,                // Received Versions List[0]
        0x1,                    // Invalid Compatible Versions List Length
        0,0,0,1,                // Compatible Versions List[0]
        0xab,0xcd,0,0           // Compatible Versions List[1]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_CompatVerUnderflow,
            (uint16_t)sizeof(InvalidClientVNI_CompatVerUnderflow),
            &OutputClientVNI));

    // Compatible Versions List Length is zero
    const uint8_t InvalidClientVNI_CompatVerZero[] = {
        0,0,0,1,                // Original Version
        0x0a,0x0a,0x0a,0x0a,    // Previous Version
        1,                      // Received Versions List Length
        0,0,0,1,                // Received Versions List[0]
        0                       // Invalid Compatible Versions List Length
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseClientVerNegInfo(
            NoOpConnection,
            InvalidClientVNI_CompatVerZero,
            (uint16_t)sizeof(InvalidClientVNI_CompatVerZero),
            &OutputClientVNI));
}

TEST(VersionNegExtTest, ParseServerVerNegInfoFail)
{
    const uint8_t ValidServerVNI[] = {
        0,0,0,1,        // Negotiated Version
        3,              // Supported Versions List Length
        0,0,0,1,        // Supported Versions List[0]
        0xab,0xcd,0,0,  // Supported Versions List[1]
        0xff,0,0,0x1d   // Supported Versions List[2]
    };

    QUIC_SERVER_VER_NEG_INFO OutputServerVNI = {0};
    QUIC_CONNECTION* NoOpConnection = (QUIC_CONNECTION*)0x1;

    //
    // Test parsing a valid VNI with too short of buffer
    //

    // Not enough room for Negotiated Version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            ValidServerVNI,
            3,
            &OutputServerVNI));

    // Not enough room for Supported Versions List Length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            ValidServerVNI,
            4,
            &OutputServerVNI));

    // Not enough room for Supported Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            ValidServerVNI,
            5,
            &OutputServerVNI));

    // Not enough room for Supported Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            ValidServerVNI,
            6,
            &OutputServerVNI));

    // Not enough room for Supported Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            ValidServerVNI,
            11,
            &OutputServerVNI));

    // Not enough room for Supported Versions List
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            ValidServerVNI,
            16,
            &OutputServerVNI));

    //
    // Test parsing different corrupt/invalid Server VNEs
    //

    // Test Supported Versions List Length longer than actual
    const uint8_t InvalidServerVNI_SuppVer[] = {
        0,0,0,1,        // Negotiated Version
        4,              // Invalid Supported Versions List Length
        0,0,0,1,        // Supported Versions List[0]
        0xab,0xcd,0,0,  // Supported Versions List[1]
        0xff,0,0,0x1d   // Supported Versions List[2]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            InvalidServerVNI_SuppVer,
            (uint16_t)sizeof(InvalidServerVNI_SuppVer),
            &OutputServerVNI));

    // Test Supported Versions List Length improperly encoded var int
    const uint8_t InvalidServerVNI_SuppVer2[] = {
        0,0,0,1,        // Negotiated Version
        0xc3,           // Invalid Supported Versions List Length
        0,0,0,1,        // Supported Versions List[0]
        0xab,0xcd,0,0,  // Supported Versions List[1]
        0xff,0,0,0x1d   // Supported Versions List[2]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            InvalidServerVNI_SuppVer2,
            (uint16_t)sizeof(InvalidServerVNI_SuppVer2),
            &OutputServerVNI));

    // Test Supported Versions List Length less than actual
    const uint8_t InvalidServerVNI_Underflow[] = {
        0,0,0,1,        // Negotiated Version
        2,              // Invalid Supported Versions List Length
        0,0,0,1,        // Supported Versions List[0]
        0xab,0xcd,0,0,  // Supported Versions List[1]
        0xff,0,0,0x1d   // Supported Versions List[2]
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            InvalidServerVNI_Underflow,
            (uint16_t)sizeof(InvalidServerVNI_Underflow),
            &OutputServerVNI));

    // Test Supported Versions List Length is zero
    const uint8_t InvalidServerVNI_Zero[] = {
        0,0,0,1,        // Negotiated Version
        0               // Invalid Supported Versions List Length
    };

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicVersionNegotiationExtParseServerVerNegInfo(
            NoOpConnection,
            InvalidServerVNI_Zero,
            (uint16_t)sizeof(InvalidServerVNI_Zero),
            &OutputServerVNI));
}
