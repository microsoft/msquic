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

        ~QuicBuffer()
        {
            delete [] Data;
        }
    };

    struct QuicTestAddress {
        QUIC_ADDR Addr;
        QuicTestAddress(const char* AddrStr, uint16_t Port) {
            EXPECT_TRUE(QuicAddrFromString(AddrStr, Port, &Addr));
        }
    };

    static
    auto
    RunTest(
        _In_ const char** ExpectedHashes,
        _In_ const char** SourceAddresses,
        _In_ const uint16_t* SourcePorts,
        _In_ const char** DestinationAddresses,
        _In_ const uint16_t* DestinationPorts,
        _In_ uint32_t TestCaseCount,
        _In_ QUIC_ADDRESS_FAMILY Family
        )
    {
        const QuicBuffer KeyBuffer(HashKey);

        CXPLAT_TOEPLITZ_HASH ToeplitzHash{};
        CxPlatCopyMemory(ToeplitzHash.HashKey, KeyBuffer.Data, KeyBuffer.Length);
        ToeplitzHash.InputSize = CXPLAT_TOEPLITZ_INPUT_SIZE_IP;
        CxPlatToeplitzHashInitialize(&ToeplitzHash);

        for (uint32_t i = 0; i < TestCaseCount; i++) {
            printf("Testing Iteration %d...\n", i + 1);

            QuicBuffer ExpectedHash(ExpectedHashes[i]);

            QUIC_ADDR SrcAddr;
            ASSERT_TRUE(QuicAddrFromString(SourceAddresses[i], SourcePorts[i], &SrcAddr));
            ASSERT_EQ(SrcAddr.si_family, Family);

            QUIC_ADDR DestAddr;
            ASSERT_TRUE(QuicAddrFromString(DestinationAddresses[i], DestinationPorts[i], &DestAddr));
            ASSERT_EQ(DestAddr.si_family, Family);

            uint32_t Key = 0, Offset = 0;
            CxPlatToeplitzHashComputeRss(&ToeplitzHash, &SrcAddr, &DestAddr, &Key, &Offset);

            // Flip the key around to match the expected hash array
            Key = CxPlatByteSwapUint32(Key);

            if (memcmp(ExpectedHash.Data, &Key, 4)) {
                QUIC_ADDR_STR PrintBuf{};
                printf("Expected Hash: %s, Actual Hash: %x\n", ExpectedHashes[i], CxPlatByteSwapUint32(Key));
                QuicAddrToString(&SrcAddr, &PrintBuf);
                printf("Source Address: %s\n", PrintBuf.Address);
                QuicAddrToString(&DestAddr, &PrintBuf);
                printf("Destination Address: %s\n", PrintBuf.Address);
                ASSERT_TRUE(FALSE);
            }
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
    const char* SourceAddresses[] = {
        "66.9.149.187",
        "199.92.111.2",
        "24.19.198.95",
        "38.27.205.30",
        "153.39.163.191"
    };
    const uint16_t SourcePorts[] = {
        2794,
        14230,
        12898,
        48228,
        44251
    };
    const char* DestinationAddresses[] = {
        "161.142.100.80",
        "65.69.140.83",
        "12.22.207.184",
        "209.142.163.6",
        "202.188.127.2"
    };
    const uint16_t DestinationPorts[] = {
        1766,
        4739,
        38024,
        2217,
        1303
    };

    RunTest(ExpectedHashes, SourceAddresses, SourcePorts, DestinationAddresses, DestinationPorts, 5, QUIC_ADDRESS_FAMILY_INET);
}

TEST_F(ToeplitzTest, IPv6WithTcp)
{
    const char* ExpectedHashes[] = {
        "40207d3d",
        "dde51bbf",
        "02d1feef"
    };
    const char* SourceAddresses[] = {
        "3ffe:2501:200:1fff::7",
        "3ffe:501:8::260:97ff:fe40:efab",
        "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
    };
    const uint16_t SourcePorts[] = {
        2794,
        14230,
        44251
    };
    const char* DestinationAddresses[] = {
        "3ffe:2501:200:3::1",
        "ff02::1",
        "fe80::200:f8ff:fe21:67cf"
    };
    const uint16_t DestinationPorts[] = {
        1766,
        4739,
        38024
    };

    RunTest(ExpectedHashes, SourceAddresses, SourcePorts, DestinationAddresses, DestinationPorts, 3, QUIC_ADDRESS_FAMILY_INET6);
}
