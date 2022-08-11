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

TEST(PlatformTest, EventQueue)
{
    uint32_t user_data = 0x1234;

    CXPLAT_EVENTQ queue;
    ASSERT_TRUE(CxPlatEventQInitialize(&queue));

    CXPLAT_CQE events[2];
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 100));

#ifdef CXPLAT_SQE
    CXPLAT_SQE sqe;
#ifdef CXPLAT_SQE_INIT
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe, &user_data));
#endif // CXPLAT_SQE_INIT
#endif // CXPLAT_SQE

#ifdef CXPLAT_SQE
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe, &user_data));
#else
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &user_data));
#endif
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ((void*)&user_data, CxPlatCqeUserData(&events[0]));

#ifdef CXPLAT_SQE_INIT
    CxPlatSqeCleanup(&queue, &sqe);
#endif // CXPLAT_SQE_INIT
    CxPlatEventQCleanup(&queue);
}
