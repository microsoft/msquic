/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the packet number related logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "PacketNumberTest.cpp.clog.h"
#endif

struct DecompressEntry {
    uint64_t HighestReceived;
    uint8_t  CompressedBytes;
    uint64_t Compressed;
    uint64_t PacketNumber;
};

TEST(PacketNumberTest, WellKnownDecompress)
{
    DecompressEntry Entries[] = {
        { 63, 1, 0, 0 },
        { 0x10000, 2, 0x8000, 0x18000},
        { 0xFFFE, 2, 0x8000, 0x8000 },
        { 0xFFFF, 2, 0x8000, 0x8000 },
        { 0xDEADBEEF, 4, 0xDEADBEF0, 0xDEADBEF0 },
        { 0xDEADBEEF, 4, 0xDEADBEEF, 0xDEADBEEF },
        { 0xDEADBEEF, 4, 0xDEADBEEE, 0xDEADBEEE },
        { 0xDEADBEEF, 4, 0, 0x100000000ull },
        { 0xDEADBEEF, 4, 1, 0x100000001ull },
        { 0xDEADBEEF, 4, 0x10000000, 0x110000000ull },
        { 0xDEADBEEF, 4, 0x5EADBEEE, 0x15EADBEEEull },
        { 0xDEADBEEF, 4, 0x5EADBEF0, 0x5EADBEF0ull },
        { 0xDEADBEEF, 4, 0x5EADBEEF, 0x15EADBEEFull },
        { 0x5EADBEEF, 4, 0xDEADBEEF, 0xDEADBEEFull },
        { 0x15EADBEEF, 4, 0xDEADBEEF, 0x1DEADBEEFull },
        { 0xDEADBEEF, 2, 0xBEF0, 0xDEADBEF0 },
        { 0xDEADBEEF, 2, 0xBEEF, 0xDEADBEEF },
        { 0xDEADBEEF, 2, 0xBEEE, 0xDEADBEEE },
        { 0xDEADBEEF, 2, 0x3EEE, 0xDEAE3EEEull },
        { 0xDEADBEEF, 2, 0x3EEF, 0xDEAE3EEFull },
        { 0xDEADBEEF, 2, 0x3EF0, 0xDEAD3EF0ull },
        { 0xDEADBEEF, 1, 0xF0, 0xDEADBEF0 },
        { 0xDEADBEEF, 1, 0xEF, 0xDEADBEEF },
        { 0xDEADBEEF, 1, 0xEE, 0xDEADBEEE },
        { 0xDEADBEEF, 1, 0x7F, 0xDEADBE7Full },
        { 0xDEADBE71, 1, 0xEF, 0xDEADBEEFull },
        { 0xDEADBE70, 1, 0xEF, 0xDEADBEEFull },
        { 0xDEADBE6F, 1, 0xEF, 0xDEADBEEFull },
        { 0xDEADBE6E, 1, 0xEF, 0xDEADBDEFull },
        { 0x35, 4, 0xFFFFFFFFull, 0xFFFFFFFFull }
    };

    for (uint8_t i = 0; i < ARRAYSIZE(Entries); i++) {
        ASSERT_EQ(
            QuicPktNumDecompress(
                Entries[i].HighestReceived + 1,
                Entries[i].Compressed,
                Entries[i].CompressedBytes),
            Entries[i].PacketNumber);
    }
}
