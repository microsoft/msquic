/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Unit test

--*/

#include "main.h"

#include "msquic.h"
#ifdef QUIC_CLOG
#include "Platform.cpp.clog.h"
#endif

struct PlatformTest : public ::testing::TestWithParam<int32_t>
{
};

TEST(PlatformTest, QuicAddrParsing)
{
    struct TestEntry {
        const char* Input;
        int Family;
        int Port;
    };

    TestEntry TestData[] = {
        { "::", QUIC_ADDRESS_FAMILY_INET6, 0 },
        { "fe80::9c3a:b64d:6249:1de8", QUIC_ADDRESS_FAMILY_INET6, 0 },
        { "[::1]:80", QUIC_ADDRESS_FAMILY_INET6, 80 },
        { "127.0.0.1", QUIC_ADDRESS_FAMILY_INET, 0 },
        { "127.0.0.1:90", QUIC_ADDRESS_FAMILY_INET, 90 }
    };

    QUIC_ADDR Addr;
    QUIC_ADDR_STR AddrStr;

    for (int i = 0; i < (int)(sizeof(TestData) / sizeof(struct TestEntry)); i++) {
        CxPlatZeroMemory(&Addr, sizeof(QUIC_ADDR));
        TestEntry* entry = &TestData[i];

        if (entry->Family == QUIC_ADDRESS_FAMILY_INET)
        {
            ASSERT_TRUE(QuicAddr4FromString(entry->Input, &Addr));
        } else {
            ASSERT_TRUE(QuicAddr6FromString(entry->Input, &Addr));
        }
        ASSERT_EQ(entry->Family, Addr.Ip.sa_family);
        ASSERT_EQ(entry->Port, ntohs(Addr.Ipv4.sin_port));
        ASSERT_TRUE(QuicAddrToString(&Addr, &AddrStr));
        ASSERT_EQ(0, strcmp(entry->Input, AddrStr.Address));
    }
}

