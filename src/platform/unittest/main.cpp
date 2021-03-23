/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

char* PfxPath = nullptr;

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        CxPlatSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatInitialize()));
    }
    void TearDown() override {
        CxPlatUninitialize();
        CxPlatSystemUnload();
    }
};

static void ProcessArguments(int argc, char** argv) {
    for (int i = 0; i < argc; i++) {
        if (strcasecmp(argv[i], "-p") == 0 || strcasecmp(argv[i], "-PfxPath") == 0 ||
            strcasecmp(argv[i], "--PfxPath")) {
            if (  + 1 < argc) {
                PfxPath = argv[i+1];
                i++;
            }
        }
    }
}

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    ProcessArguments(argc, argv);
    return RUN_ALL_TESTS();
}
