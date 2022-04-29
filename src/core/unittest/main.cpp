/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        CxPlatSystemLoad();
        TEST_QUIC_SUCCEEDED(CxPlatInitialize());
    }
    void TearDown() override {
        CxPlatUninitialize();
        CxPlatSystemUnload();
        CxPlatZeroMemory(&MsQuicLib, sizeof(MsQuicLib));
    }
};

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
