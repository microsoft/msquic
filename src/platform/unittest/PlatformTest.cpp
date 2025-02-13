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
    struct my_sqe : public CXPLAT_SQE {
        uint32_t data;
        static void my_completion_1(CXPLAT_CQE* Cqe) {
            CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
            ASSERT_TRUE(((my_sqe*)Sqe)->data == 0x1234);
        }
        static void my_completion_2(CXPLAT_CQE* Cqe) {
            CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
            ASSERT_TRUE(((my_sqe*)Sqe)->data == 0x5678);
        }
        static void my_completion_3(CXPLAT_CQE* Cqe) {
            CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
            ASSERT_TRUE(((my_sqe*)Sqe)->data == 0x90);
        }
    };
    
    CXPLAT_EVENTQ queue;
    ASSERT_TRUE(CxPlatEventQInitialize(&queue));

    // Empty queue tests
    CXPLAT_CQE events[2];
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 100));

    my_sqe sqe1, sqe2, sqe3;
    sqe1.data = 0x1234;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, my_sqe::my_completion_1, &sqe1));
    sqe2.data = 0x5678;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, my_sqe::my_completion_2, &sqe2));
    sqe3.data = 0x90;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, my_sqe::my_completion_3, &sqe3));

    // Single queue/dequeue tests
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1));
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ(&sqe1, (my_sqe*)CxPlatCqeGetSqe(&events[0]));

    // Multiple queue/dequeue tests
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe2));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe3));
    ASSERT_EQ(2u, CxPlatEventQDequeue(&queue, events, 2, 100));
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 0));
    ASSERT_EQ(0u, CxPlatEventQDequeue(&queue, events, 2, 0));

    struct EventQueueContext {
        CXPLAT_EVENTQ* queue;
        CXPLAT_SQE* sqe;
        static CXPLAT_THREAD_CALLBACK(EventQueueCallback, Context) {
            auto ctx = (EventQueueContext*)Context;
            CxPlatSleep(100);
            CxPlatEventQEnqueue(ctx->queue, ctx->sqe);
            CXPLAT_THREAD_RETURN(0);
        }
    };

    // Async queue/dequeue tests
    EventQueueContext context = { &queue, &sqe1 };
    CXPLAT_THREAD_CONFIG config = { 0, 0, NULL, EventQueueContext::EventQueueCallback, &context };
    CXPLAT_THREAD thread;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatThreadCreate(&config, &thread)));
    ASSERT_EQ(1u, CxPlatEventQDequeue(&queue, events, 2, 1000));
    ASSERT_EQ(&sqe1, (my_sqe*)CxPlatCqeGetSqe(&events[0]));
    CxPlatThreadWait(&thread);
    CxPlatThreadDelete(&thread);

    CxPlatSqeCleanup(&queue, &sqe1);
    CxPlatSqeCleanup(&queue, &sqe2);
    CxPlatSqeCleanup(&queue, &sqe3);

    CxPlatEventQCleanup(&queue);
}

TEST(PlatformTest, EventQueueWorker)
{
    typedef struct EventQueueContext EventQueueContext;

    struct my_sqe : public CXPLAT_SQE {
        EventQueueContext* context;
        uint32_t data;
    };

    struct EventQueueContext {
        CXPLAT_EVENTQ* queue;
        uint32_t counts[3];
        bool running;
        static CXPLAT_THREAD_CALLBACK(EventQueueCallback, Context) {
            auto ctx = (EventQueueContext*)Context;
            CXPLAT_CQE events[4];
            while (ctx->running) {
                uint32_t count = CxPlatEventQDequeue(ctx->queue, events, ARRAYSIZE(events), UINT32_MAX);
                for (uint32_t i = 0; i < count; i++) {
                    auto sqe = CxPlatCqeGetSqe(&events[i]);
                    sqe->Completion(&events[i]);
                }
            }
            CXPLAT_THREAD_RETURN(0);
        }
        static void shutdown_completion(CXPLAT_CQE* Cqe) {
            auto Sqe = (my_sqe*)CxPlatCqeGetSqe(Cqe);
            Sqe->context->running = false;
        }
        static void my_completion(CXPLAT_CQE* Cqe) {
            auto Sqe = (my_sqe*)CxPlatCqeGetSqe(Cqe);
            Sqe->context->counts[Sqe->data]++;
        }
    };

    CXPLAT_EVENTQ queue;
    ASSERT_TRUE(CxPlatEventQInitialize(&queue));

    EventQueueContext context = { &queue, {0}, true };
    CXPLAT_THREAD_CONFIG config = { 0, 0, NULL, EventQueueContext::EventQueueCallback, &context };
    CXPLAT_THREAD thread;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatThreadCreate(&config, &thread)));
    
    my_sqe shutdown, sqe1, sqe2, sqe3;
    shutdown.context = &context;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, EventQueueContext::shutdown_completion, &shutdown));
    sqe1.context = &context;
    sqe1.data = 0;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, EventQueueContext::my_completion, &sqe1));
    sqe2.context = &context;
    sqe2.data = 1;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, EventQueueContext::my_completion, &sqe2));
    sqe3.context = &context;
    sqe3.data = 2;
    ASSERT_TRUE(CxPlatSqeInitialize(&queue, EventQueueContext::my_completion, &sqe3));

    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe2));
    CxPlatSleep(100);
    ASSERT_TRUE(context.counts[0] == 1u);
    ASSERT_TRUE(context.counts[1] == 1u);
    ASSERT_TRUE(context.counts[2] == 0u);

    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe1));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe2));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe3));
    CxPlatSleep(100);
    ASSERT_TRUE(context.counts[0] == 2u);
    ASSERT_TRUE(context.counts[1] == 2u);
    ASSERT_TRUE(context.counts[2] == 1u);

    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &sqe3));
    ASSERT_TRUE(CxPlatEventQEnqueue(&queue, &shutdown));

    CxPlatThreadWait(&thread);
    CxPlatThreadDelete(&thread);

    ASSERT_TRUE(context.counts[0] == 2u);
    ASSERT_TRUE(context.counts[1] == 2u);
    ASSERT_TRUE(context.counts[2] == 2u);

    CxPlatSqeCleanup(&queue, &shutdown);
    CxPlatSqeCleanup(&queue, &sqe1);
    CxPlatSqeCleanup(&queue, &sqe2);
    CxPlatSqeCleanup(&queue, &sqe3);

    CxPlatEventQCleanup(&queue);
}
