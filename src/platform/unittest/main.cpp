/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        QuicPlatformSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(QuicPlatformInitialize()));
    }
    void TearDown() override {
        QuicPlatformUninitialize();
        QuicPlatformSystemUnload();
    }
};

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
