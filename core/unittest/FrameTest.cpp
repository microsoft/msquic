/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the framing logic.

--*/

#include "precomp.h"
#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
#include "frametest.tmh"
#endif

using namespace WEX::Logging;
using namespace WEX::Common;

#define VERIFY_QUIC_SUCCESS(result, ...) \
    VERIFY_ARE_EQUAL(QUIC_STATUS_SUCCESS, result, __VA_ARGS__)

struct FrameTest : public WEX::TestClass<FrameTest>
{
    BEGIN_TEST_CLASS(FrameTest)
    END_TEST_CLASS()

    uint64_t Encode(uint64_t Value)
    {
        uint64_t Encoded = 0;
        VERIFY_IS_NOT_NULL(QuicVarIntEncode(Value, (uint8_t*)&Encoded));
        return Encoded;
    }

    uint64_t Decode(uint64_t Encoded)
    {
        uint64_t Decoded;
        UINT16 Offset = 0;
        VERIFY_IS_TRUE(QuicVarIntDecode(sizeof(Encoded), (uint8_t*)&Encoded, &Offset, &Decoded));
        return Decoded;
    }

    TEST_METHOD(WellKnownEncode)
    {
        VERIFY_ARE_EQUAL(Encode(0), 0);
        VERIFY_ARE_EQUAL(Encode(0x3F), 0x3F);
        VERIFY_ARE_EQUAL(Encode(0x40), 0x4040);
        VERIFY_ARE_EQUAL(Encode(0x3FFF), 0xFF7F);
        VERIFY_ARE_EQUAL(Encode(0x4000), 0x400080);
        VERIFY_ARE_EQUAL(Encode(0x3FFFFFFF), 0xFFFFFFBF);
        VERIFY_ARE_EQUAL(Encode(0x40000000), 0x40000000C0ULL);
        VERIFY_ARE_EQUAL(Encode(0x3FFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFF);
    }

    TEST_METHOD(WellKnownDecode)
    {
        VERIFY_ARE_EQUAL(Decode(0), 0);
        VERIFY_ARE_EQUAL(Decode(0x3F), 0x3F);
        VERIFY_ARE_EQUAL(Decode(0x4040), 0x40);
        VERIFY_ARE_EQUAL(Decode(0xFF7F), 0x3FFF);
        VERIFY_ARE_EQUAL(Decode(0x400080), 0x4000);
        VERIFY_ARE_EQUAL(Decode(0xFFFFFFBF), 0x3FFFFFFF);
        VERIFY_ARE_EQUAL(Decode(0x40000000C0ULL), 0x40000000);
        VERIFY_ARE_EQUAL(Decode(0xFFFFFFFFFFFFFFFF), 0x3FFFFFFFFFFFFFFFULL);
    }

    TEST_METHOD(RandomEncodeDecode)
    {
        for (uint32_t i = 0; i < 1000; i++) {

            //
            // Generate a random value and make sure the top 2 bits aren't set.
            //
            uint64_t Value;
            VERIFY_QUIC_SUCCESS(QuicRandom(sizeof(Value), &Value));
            Value &= ~(3ULL << 62);

            //
            // Encode the value, decode the result and compare to the original value.
            //
            uint64_t Encoded = Encode(Value);
            uint64_t Decoded = Decode(Encoded);
            VERIFY_ARE_EQUAL(Value, Decoded);
        }
    }
};
