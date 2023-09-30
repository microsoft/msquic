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
