/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#include "main.h"
#include "msquic.h"
#include "msquichelper.h"
#include "quic_toeplitz.h"
#include <stdio.h>

#ifdef QUIC_CLOG
#include "ToeplitzTest.cpp.clog.h"
#endif

struct ToeplitzTest : public ::testing::Test
{
    protected:
    static const char* HashKey;

    struct QuicBuffer
    {
        uint8_t* Data;
        uint16_t Length;

        QuicBuffer(const char* HexBytes)
        {
            Length = (uint16_t)(strlen(HexBytes) / 2);
            Data = new uint8_t[Length];

            for (uint16_t i = 0; i < Length; ++i) {
                Data[i] =
                    (DecodeHexChar(HexBytes[i * 2]) << 4) |
                    DecodeHexChar(HexBytes[i * 2 + 1]);
            }
        }

        QuicBuffer(const QuicBuffer&) = delete;
        QuicBuffer(QuicBuffer&&) = delete;
        QuicBuffer& operator=(const QuicBuffer&) = delete;
        QuicBuffer& operator=(QuicBuffer&&) = delete;

        ~QuicBuffer()
        {
            delete [] Data;
        }
    };

    struct QuicTestAddress {
        QUIC_ADDR Addr;
        QuicTestAddress() : Addr{} {}
        QuicTestAddress(const QUIC_ADDR& Address) : Addr(Address) {}
        QuicTestAddress(const char* AddrStr, uint16_t Port) {
            EXPECT_TRUE(QuicAddrFromString(AddrStr, Port, &Addr));
        }
        operator QUIC_ADDR*() { return &Addr; }
        QuicTestAddress& operator=(const QuicTestAddress& Address) {
            Addr = Address.Addr;
            return *this;
        }
    };

    static
    auto
    ValidateRssToeplitzHash(
        _In_ const char* ExpectedHash,
        _In_ const QUIC_ADDR* SourceAddress,
        _In_ const QUIC_ADDR* DestinationAddress,
        _In_ QUIC_ADDRESS_FAMILY Family
        )
    {
        static const QuicBuffer KeyBuffer(HashKey);

        CXPLAT_TOEPLITZ_HASH ToeplitzHash{};
        CxPlatCopyMemory(ToeplitzHash.HashKey, KeyBuffer.Data, KeyBuffer.Length);
        ToeplitzHash.InputSize = CXPLAT_TOEPLITZ_INPUT_SIZE_IP;
        CxPlatToeplitzHashInitialize(&ToeplitzHash);

        QuicBuffer ExpectedHashBuf(ExpectedHash);

        ASSERT_EQ(QuicAddrGetFamily(SourceAddress), Family);

        ASSERT_EQ(QuicAddrGetFamily(DestinationAddress), Family);

        uint32_t Key = 0, Offset = 0;
        CxPlatToeplitzHashComputeRss(&ToeplitzHash, SourceAddress, DestinationAddress, &Key, &Offset);

        // Flip the key around to match the expected hash array
        Key = CxPlatByteSwapUint32(Key);

        if (memcmp(ExpectedHashBuf.Data, &Key, 4)) {
            QUIC_ADDR_STR PrintBuf{};
            printf("Expected Hash: %s, Actual Hash: %x\n", ExpectedHash, CxPlatByteSwapUint32(Key));
            QuicAddrToString(SourceAddress, &PrintBuf);
            printf("Source Address: %s\n", PrintBuf.Address);
            QuicAddrToString(DestinationAddress, &PrintBuf);
            printf("Destination Address: %s\n", PrintBuf.Address);
            ASSERT_TRUE(FALSE);
        }
    }

};

const char* ToeplitzTest::HashKey = "6d5a56da255b0ec24167253d43a38fb0d0ca2bcbae7b30b477cb2da38030f20c6a42b73bbeac01fa";

TEST_F(ToeplitzTest, IPv4WithTcp)
{
    const char* ExpectedHashes[] = {
        "51ccc178",
        "c626b0ea",
        "5c2b394a",
        "afc7327f",
        "10e828a2"
    };
    const QuicTestAddress DestinationAddresses[] = {
        {"161.142.100.80", 1766},
        {"65.69.140.83",   4739},
        {"12.22.207.184", 38024},
        {"209.142.163.6",  2217},
        {"202.188.127.2",  1303},
    };
    const QuicTestAddress SourceAddresses[] = {
        {"66.9.149.187",    2794},
        {"199.92.111.2",   14230},
        {"24.19.198.95",   12898},
        {"38.27.205.30",   48228},
        {"153.39.163.191", 44251},
    };

    for(uint32_t i = 0; i < ARRAYSIZE(ExpectedHashes); i++) {
        printf("Testing Iteration %d...\n", i + 1);

        ValidateRssToeplitzHash(
            ExpectedHashes[i],
            &SourceAddresses[i].Addr,
            &DestinationAddresses[i].Addr,
            QUIC_ADDRESS_FAMILY_INET);
    }
}

TEST_F(ToeplitzTest, IPv6WithTcp)
{
    const char* ExpectedHashes[] = {
        "40207d3d",
        "dde51bbf",
        "02d1feef"
    };
    const QuicTestAddress SourceAddresses[] = {
        {"3ffe:2501:200:1fff::7",                2794},
        {"3ffe:501:8::260:97ff:fe40:efab",      14230},
        {"3ffe:1900:4545:3:200:f8ff:fe21:67cf", 44251}
    };
    const QuicTestAddress DestinationAddresses[] = {
        {"3ffe:2501:200:3::1",        1766},
        {"ff02::1",                   4739},
        {"fe80::200:f8ff:fe21:67cf", 38024},
    };

    for(uint32_t i = 0; i < ARRAYSIZE(ExpectedHashes); i++) {
        printf("Testing Iteration %d...\n", i + 1);

        ValidateRssToeplitzHash(
            ExpectedHashes[i],
            &SourceAddresses[i].Addr,
            &DestinationAddresses[i].Addr,
            QUIC_ADDRESS_FAMILY_INET6);
    }
}
