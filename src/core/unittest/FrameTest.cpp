/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the framing logic.

--*/

#include "main.h"
#ifdef QUIC_LOGS_WPP
#include "frametest.tmh"
#endif

uint64_t Encode(uint64_t Value)
{
    uint64_t Encoded = 0;
    TEST_TRUE(QuicVarIntEncode(Value, (uint8_t*)&Encoded) != NULL);
    return Encoded;
}

uint64_t Decode(uint64_t Encoded)
{
    uint64_t Decoded;
    UINT16 Offset = 0;
    TEST_TRUE(QuicVarIntDecode(sizeof(Encoded), (uint8_t*)&Encoded, &Offset, &Decoded));
    return Decoded;
}

void
FrameTestWellKnownEncode(
    )
{
    TEST_EQUAL(Encode(0), 0);
    TEST_EQUAL(Encode(0x3F), 0x3F);
    TEST_EQUAL(Encode(0x40), 0x4040);
    TEST_EQUAL(Encode(0x3FFF), 0xFF7F);
    TEST_EQUAL(Encode(0x4000), 0x400080);
    TEST_EQUAL(Encode(0x3FFFFFFF), 0xFFFFFFBF);
    TEST_EQUAL(Encode(0x40000000), 0x40000000C0ULL);
    TEST_EQUAL(Encode(0x3FFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFF);
}

void
FrameTestWellKnownDecode(
    )
{
    TEST_EQUAL(Decode(0), 0);
    TEST_EQUAL(Decode(0x3F), 0x3F);
    TEST_EQUAL(Decode(0x4040), 0x40);
    TEST_EQUAL(Decode(0xFF7F), 0x3FFF);
    TEST_EQUAL(Decode(0x400080), 0x4000);
    TEST_EQUAL(Decode(0xFFFFFFBF), 0x3FFFFFFF);
    TEST_EQUAL(Decode(0x40000000C0ULL), 0x40000000);
    TEST_EQUAL(Decode(0xFFFFFFFFFFFFFFFF), 0x3FFFFFFFFFFFFFFFULL);
}

void
FrameTestRandomEncodeDecode(
    )
{
    for (uint32_t i = 0; i < 1000; i++) {

        //
        // Generate a random value and make sure the top 2 bits aren't set.
        //
        uint64_t Value;
        TEST_QUIC_SUCCEEDED(QuicRandom(sizeof(Value), &Value));
        Value &= ~(3ULL << 62);

        //
        // Encode the value, decode the result and compare to the original value.
        //
        uint64_t Encoded = Encode(Value);
        uint64_t Decoded = Decode(Encoded);
        TEST_EQUAL(Value, Decoded);
    }
}
