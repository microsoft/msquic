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

TEST(PlatformTest, QuicAddrParsing)
{
    struct TestEntry {
        const char* Input;
        uint16_t DefaultPort;
        int Family;
        uint16_t ExpectedPort;
        uint32_t ExpectedScope;
        uint8_t ExpectedAddress[16];
    };

    const TestEntry TestData[] = {
        { "0.0.0.0", 0, QUIC_ADDRESS_FAMILY_INET, 0, 0, { 0, 0, 0, 0 } },
        { "127.0.0.1", 443, QUIC_ADDRESS_FAMILY_INET, 443, 0, { 127, 0, 0, 1 } },
        { "127.0.0.1:90", 443, QUIC_ADDRESS_FAMILY_INET, 90, 0, { 127, 0, 0, 1 } },
        { "255.255.255.255:65535", 0, QUIC_ADDRESS_FAMILY_INET, 65535, 0, { 255, 255, 255, 255 } },
        { "::", 0, QUIC_ADDRESS_FAMILY_INET6, 0, 0, {} },
        { "::1", 443, QUIC_ADDRESS_FAMILY_INET6, 443, 0,
          { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        { "[::1]:80", 443, QUIC_ADDRESS_FAMILY_INET6, 80, 0,
          { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        { "::ffff:192.0.2.128", 0, QUIC_ADDRESS_FAMILY_INET6, 0, 0,
          { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 128 } },
        { "fe80::9c3a:b64d:6249:1de8%3", 0, QUIC_ADDRESS_FAMILY_INET6, 0, 3,
          { 254, 128, 0, 0, 0, 0, 0, 0, 156, 58, 182, 77, 98, 73, 29, 232 } },
        { "[fe80::9c3a:b64d:6249:1de8%3]:443", 0, QUIC_ADDRESS_FAMILY_INET6, 443, 3,
          { 254, 128, 0, 0, 0, 0, 0, 0, 156, 58, 182, 77, 98, 73, 29, 232 } },
        { "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535", 0,
          QUIC_ADDRESS_FAMILY_INET6, 65535, UINT32_MAX,
          { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 } }
    };

    for (const auto& Entry : TestData) {
        QUIC_ADDR Addr{};
        ASSERT_TRUE(QuicAddrFromString(Entry.Input, Entry.DefaultPort, &Addr)) << Entry.Input;
        ASSERT_EQ(Entry.ExpectedPort, QuicAddrGetPort(&Addr)) << Entry.Input;
        ASSERT_EQ(Entry.Family, QuicAddrGetFamily(&Addr)) << Entry.Input;
        if (Entry.Family == QUIC_ADDRESS_FAMILY_INET6) {
            ASSERT_EQ(Entry.ExpectedScope, Addr.Ipv6.sin6_scope_id) << Entry.Input;
        }
        const void* ActualAddress =
            Entry.Family == QUIC_ADDRESS_FAMILY_INET ?
                (void*)&Addr.Ipv4.sin_addr :
                (void*)&Addr.Ipv6.sin6_addr;
        ASSERT_EQ(
            0,
            memcmp(
                Entry.ExpectedAddress,
                ActualAddress,
                Entry.Family == QUIC_ADDRESS_FAMILY_INET ? 4 : 16)) << Entry.Input;
    }

    QUIC_ADDR Addr{};
    ASSERT_FALSE(QuicAddrFromString("fe80::1%", 0, &Addr));
    ASSERT_FALSE(QuicAddrFromString("fe80::1%abc", 0, &Addr));
    ASSERT_FALSE(QuicAddrFromString("fe80::1%4294967296", 0, &Addr));
}

TEST(PlatformTest, QuicAddrToString)
{
    struct TestEntry {
        const char* Input;
        const char* Expected;
    };

    const TestEntry TestData[] = {
        { "0.0.0.0", "0.0.0.0" },
        { "127.0.0.1:443", "127.0.0.1:443" },
        { "127.0.0.1:90", "127.0.0.1:90" },
        { "255.255.255.255:65535", "255.255.255.255:65535" },
        { "::", "::" },
        { "[::1]:443", "[::1]:443" },
        { "[::1]:80", "[::1]:80" },
        { "::ffff:192.0.2.128", "::ffff:192.0.2.128" },
        { "fe80::9c3a:b64d:6249:1de8%3", "fe80::9c3a:b64d:6249:1de8" },
        { "[fe80::9c3a:b64d:6249:1de8%3]:443", "[fe80::9c3a:b64d:6249:1de8]:443" },
        // Maximum scope, port and uncompressed IPv6 literal.
        { "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535",
          "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535" }
    };

    static_assert(sizeof(((QUIC_ADDR_STR*)nullptr)->Address) == 65);
    for (const auto& Entry : TestData) {
        QUIC_ADDR Addr{};
        QUIC_ADDR_STR AddrStr{};
        ASSERT_TRUE(QuicAddrFromString(Entry.Input, 0, &Addr)) << Entry.Input;
        ASSERT_TRUE(QuicAddrToString(&Addr, &AddrStr));
        ASSERT_STREQ(Entry.Expected, AddrStr.Address) << Entry.Input;
    }
}

TEST(PlatformTest, QuicAddrIpToString)
{
    struct TestEntry {
        const char* Input;
        const char* Expected;
    };

    const TestEntry TestData[] = {
        { "0.0.0.0", "0.0.0.0" },
        { "127.0.0.1:443", "127.0.0.1" },
        { "255.255.255.255:65535", "255.255.255.255" },
        { "[::]:65535", "::" },
        { "[::1]:443", "::1" },
        { "[::ffff:192.0.2.128]:443", "::ffff:192.0.2.128" },
        { "[fe80::9c3a:b64d:6249:1de8%3]:443", "fe80::9c3a:b64d:6249:1de8" },
        // Maximum scope, port and uncompressed IPv6 literal.
        { "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535",
          "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }
    };

    for (const auto& Entry : TestData) {
        QUIC_ADDR Addr{};
        QUIC_ADDR_STR AddrStr{};
        ASSERT_TRUE(QuicAddrFromString(Entry.Input, 0, &Addr)) << Entry.Input;
        ASSERT_TRUE(QuicAddrIpToString(&Addr, &AddrStr));
        ASSERT_STREQ(Entry.Expected, AddrStr.Address) << Entry.Input;
    }

    QUIC_ADDR InvalidAddr{};
    QUIC_ADDR_STR AddrStr{};
    ASSERT_FALSE(QuicAddrIpToString(&InvalidAddr, &AddrStr));
}

TEST(PlatformTest, EventQueue)
{
    uint32_t user_data1 = 0x1234, user_data2 = 0x5678, user_data3 = 0x90;

    CXPLAT_EVENTQ queue;
    ASSERT_TRUE(CxPlatEventQInitialize(&queue));

    // Empty queue tests
    CXPLAT_CQE events[2];
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 100));

#ifdef CXPLAT_SQE
    CXPLAT_SQE sqe1 = CXPLAT_SQE_DEFAULT;
    CXPLAT_SQE sqe2 = CXPLAT_SQE_DEFAULT;
    CXPLAT_SQE sqe3 = CXPLAT_SQE_DEFAULT;
#ifdef CXPLAT_SQE_INIT
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe1, &user_data1));
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe2, &user_data2));
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe3, &user_data3));
#endif // CXPLAT_SQE_INIT
#endif // CXPLAT_SQE

    // Single queue/dequeue tests
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1, &user_data1));
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ((void*)&user_data1, CxPlatCqeUserData(&events[0]));

    // Multiple queue/dequeue tests
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1, &user_data1));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe2, &user_data2));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe3, &user_data3));
    ASSERT_EQ(2u, CxPlatEventQDequeue(&queue, events, 2, 100));
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 0));

    struct EventQueueContext {
        CXPLAT_EVENTQ* queue;
#ifdef CXPLAT_SQE
        CXPLAT_SQE* sqe;
#endif
        void* user_data;
        static CXPLAT_THREAD_CALLBACK(EventQueueCallback, Context) {
            auto ctx = (EventQueueContext*)Context;
            CxPlatSleep(100);
            CxPlatEventQEnqueue(ctx->queue, ctx->sqe, ctx->user_data);
            CXPLAT_THREAD_RETURN(0);
        }
    };

    // Async queue/dequeue tests
#ifdef CXPLAT_SQE
    EventQueueContext context = { &queue, &sqe1, &user_data1 };
#else
    EventQueueContext context = { &queue, &user_data1 };
#endif
    CXPLAT_THREAD_CONFIG config = { 0, 0, NULL, EventQueueContext::EventQueueCallback, &context };
    CXPLAT_THREAD thread;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatThreadCreate(&config, &thread)));
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 1000));
    ASSERT_EQ((void*)&user_data1, CxPlatCqeUserData(&events[0]));
    CxPlatThreadWait(&thread);
    CxPlatThreadDelete(&thread);

#ifdef CXPLAT_SQE_INIT
    CxPlatSqeCleanup(&queue, &sqe1);
    CxPlatSqeCleanup(&queue, &sqe2);
    CxPlatSqeCleanup(&queue, &sqe3);
#endif // CXPLAT_SQE_INIT

    CxPlatEventQCleanup(&queue);
}

TEST(PlatformTest, EventQueueWorker)
{
    struct EventQueueContext {
        CXPLAT_EVENTQ* queue;
        uint32_t counts[3];
        static CXPLAT_THREAD_CALLBACK(EventQueueCallback, Context) {
            auto ctx = (EventQueueContext*)Context;
            CXPLAT_CQE events[4];
            while (true) {
                uint32_t count = CxPlatEventQDequeue(ctx->queue, events, ARRAYSIZE(events), UINT32_MAX);
                for (uint32_t i = 0; i < count; i++) {
                    if (CxPlatCqeUserData(&events[i]) == NULL) goto Exit;
                    ctx->counts[CxPlatCqeType(events + i)]++;
                }
            }
        Exit:
            CXPLAT_THREAD_RETURN(0);
        }
    };

    uint32_t user_data1 = 0, user_data2 = 1, user_data3 = 2;

    CXPLAT_EVENTQ queue;
    ASSERT_TRUE(CxPlatEventQInitialize(&queue));

    EventQueueContext context = { &queue, {0} };
    CXPLAT_THREAD_CONFIG config = { 0, 0, NULL, EventQueueContext::EventQueueCallback, &context };
    CXPLAT_THREAD thread;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatThreadCreate(&config, &thread)));

#ifdef CXPLAT_SQE
    CXPLAT_SQE shutdown = CXPLAT_SQE_DEFAULT;
    CXPLAT_SQE sqe1 = CXPLAT_SQE_DEFAULT;
    CXPLAT_SQE sqe2 = CXPLAT_SQE_DEFAULT;
    CXPLAT_SQE sqe3 = CXPLAT_SQE_DEFAULT;
#ifdef CXPLAT_SQE_INIT
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &shutdown, nullptr));
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe1, &user_data1));
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe2, &user_data2));
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, &sqe3, &user_data3));
#endif // CXPLAT_SQE_INIT
#endif // CXPLAT_SQE

    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1, &user_data1));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe2, &user_data2));
    CxPlatSleep(100);
    ASSERT_TRUE(context.counts[0] == 1u);
    ASSERT_TRUE(context.counts[1] == 1u);
    ASSERT_TRUE(context.counts[2] == 0u);

    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1, &user_data1));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe2, &user_data2));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe3, &user_data3));
    CxPlatSleep(100);
    ASSERT_TRUE(context.counts[0] == 2u);
    ASSERT_TRUE(context.counts[1] == 2u);
    ASSERT_TRUE(context.counts[2] == 1u);

    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe3, &user_data3));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &shutdown, nullptr));

    CxPlatThreadWait(&thread);
    CxPlatThreadDelete(&thread);

    ASSERT_TRUE(context.counts[0] == 2u);
    ASSERT_TRUE(context.counts[1] == 2u);
    ASSERT_TRUE(context.counts[2] == 2u);

#ifdef CXPLAT_SQE_INIT
    CxPlatSqeCleanup(&queue, &shutdown);
    CxPlatSqeCleanup(&queue, &sqe1);
    CxPlatSqeCleanup(&queue, &sqe2);
    CxPlatSqeCleanup(&queue, &sqe3);
#endif // CXPLAT_SQE_INIT

    CxPlatEventQCleanup(&queue);
}
