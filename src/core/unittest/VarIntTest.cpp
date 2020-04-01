/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the variable length integer encoding and decoding logic.

--*/

#include "main.h"
#include "VarIntTest.cpp.clog.h"

uint64_t Encode(uint64_t Value)
{
    uint64_t Encoded = 0;
    EXPECT_NE(QuicVarIntEncode(Value, (uint8_t*)&Encoded), nullptr);
    return Encoded;
}

uint64_t Decode(uint64_t Encoded)
{
    uint64_t Decoded;
    uint16_t Offset = 0;
    EXPECT_NE(QuicVarIntDecode(sizeof(Encoded), (uint8_t*)&Encoded, &Offset, &Decoded), (BOOLEAN)0);
    return Decoded;
}

TEST(VarIntTest, WellKnownEncode)
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

TEST(VarIntTest, WellKnownDecode)
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

TEST(VarIntTest, RandomEncodeDecode)
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
