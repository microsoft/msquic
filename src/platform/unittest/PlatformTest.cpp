/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Unit test

--*/

#include "main.h"

#include "msquic.h"
#ifdef QUIC_CLOG
#include "PlatformTest.cpp.clog.h"
#endif

struct PlatformTest : public ::testing::TestWithParam<int32_t>
{
};

TEST(PlatformTest, QuicAddrParsing)
{
    struct TestEntry {
        const char* Input;
        int Family;
        unsigned short Port;
    };

    TestEntry TestData[] = {
        { "::", QUIC_ADDRESS_FAMILY_INET6, 0 },
        { "fe80::9c3a:b64d:6249:1de8", QUIC_ADDRESS_FAMILY_INET6, 0 },
        { "[::1]:80", QUIC_ADDRESS_FAMILY_INET6, 80 },
        { "127.0.0.1", QUIC_ADDRESS_FAMILY_INET, 0 },
        { "127.0.0.1:90", QUIC_ADDRESS_FAMILY_INET, 90 }
    };

    QUIC_ADDR Addr;
    QUIC_ADDR_STR AddrStr = { 0 };

    for (int i = 0; i < (int)(sizeof(TestData) / sizeof(struct TestEntry)); i++) {
        CxPlatZeroMemory(&Addr, sizeof(QUIC_ADDR));
        TestEntry* entry = &TestData[i];

        ASSERT_TRUE(QuicAddrFromString(entry->Input, entry->Port, &Addr));
        ASSERT_EQ(entry->Port, QuicAddrGetPort(&Addr));
        ASSERT_EQ(entry->Family, QuicAddrGetFamily(&Addr));
        ASSERT_TRUE(QuicAddrToString(&Addr, &AddrStr));
        ASSERT_EQ(0, strcmp(entry->Input, AddrStr.Address));
    }
}

