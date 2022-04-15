/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#include "msquichelper.h"
#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

const char* PfxPath = nullptr;
bool UseDuoNic = false;

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

int main(int argc, char** argv) {
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--duoNic", argv[i]) == 0) {
            UseDuoNic = true;
        }
    }
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    PfxPath = GetValue(argc, argv, "PfxPath");
    return RUN_ALL_TESTS();
}
