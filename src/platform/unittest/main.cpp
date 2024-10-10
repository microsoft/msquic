/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#include "msquichelper.h"
#include "msquic.hpp"
#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

const char* PfxPath = nullptr;
bool UseDuoNic = false;
uint32_t Timeout = UINT32_MAX;
const char* OsRunner = nullptr;
CXPLAT_WORKER_POOL WorkerPool;

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    CxPlatWatchdog* watchdog;
    void SetUp() override {
        CxPlatSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatInitialize()));
        CxPlatWorkerPoolInit(&WorkerPool);
        watchdog = new CxPlatWatchdog(Timeout);
    }
    void TearDown() override {
        CxPlatWorkerPoolUninit(&WorkerPool);
        CxPlatUninitialize();
        CxPlatSystemUnload();
        delete watchdog;
    }
};

int main(int argc, char** argv) {
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--duoNic", argv[i]) == 0) {
            UseDuoNic = true;
        } else if (strcmp("--timeout", argv[i]) == 0) {
            if (i + 1 < argc) {
                Timeout = atoi(argv[i + 1]);
                ++i;
            }
        } else if (strstr(argv[i], "--osRunner")) {
            OsRunner = argv[i] + sizeof("--osRunner");
        }
    }
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    PfxPath = GetValue(argc, argv, "PfxPath");
    return RUN_ALL_TESTS();
}
