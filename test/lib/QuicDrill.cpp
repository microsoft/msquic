/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Packet-level tests.

--*/

#include "precomp.h"

void
QuicDrillTestVarIntEncoder(
    )
{
    auto output = QuicDrillEncodeQuicVarInt(0);
    TEST_EQUAL(output[0], 0);

    output = QuicDrillEncodeQuicVarInt(0x3f);
    TEST_EQUAL(output[0], 0x3f);

    output = QuicDrillEncodeQuicVarInt(0x40);
    TEST_EQUAL(output[0], 0x40);
    TEST_EQUAL(output[1], 0x40);

    output = QuicDrillEncodeQuicVarInt(0x3fff);
    TEST_EQUAL(output[0], 0x7f);
    TEST_EQUAL(output[1], 0xff);

    output = QuicDrillEncodeQuicVarInt(0x4000);
    TEST_EQUAL(output[0], 0x80);
    TEST_EQUAL(output[1], 0x00);
    TEST_EQUAL(output[2], 0x40);

    output = QuicDrillEncodeQuicVarInt(0x3FFFFFFFUL);
    TEST_EQUAL(output[0], 0xbf);
    TEST_EQUAL(output[1], 0xff);
    TEST_EQUAL(output[2], 0xff);
    TEST_EQUAL(output[3], 0xff);

    output = QuicDrillEncodeQuicVarInt(0x40000000UL);
    TEST_EQUAL(output[0], 0xc0);
    TEST_EQUAL(output[1], 0x00);
    TEST_EQUAL(output[2], 0x00);
    TEST_EQUAL(output[3], 0x00);
    TEST_EQUAL(output[4], 0x40);

    output = QuicDrillEncodeQuicVarInt(0x3FFFFFFFFFFFFFFFULL);
    TEST_EQUAL(output[0], 0xff);
    TEST_EQUAL(output[1], 0xff);
    TEST_EQUAL(output[2], 0xff);
    TEST_EQUAL(output[3], 0xff);
    TEST_EQUAL(output[4], 0xff);
    TEST_EQUAL(output[5], 0xff);
    TEST_EQUAL(output[6], 0xff);
    TEST_EQUAL(output[7], 0xff);
}