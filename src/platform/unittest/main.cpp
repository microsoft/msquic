/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"

#ifdef QUIC_LOGS_WPP
#include "main.tmh"
#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

extern "C" {
void* CreateServerCertificate();
void FreeServerCertificate(void* CertCtx);
}

void* SecConfigCertContext;

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        QuicPlatformSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(QuicPlatformInitialize()));
        ASSERT_NE(nullptr, (SecConfigCertContext = CreateServerCertificate()));
    }
    void TearDown() override {
        FreeServerCertificate(SecConfigCertContext);
        SecConfigCertContext = nullptr;
        QuicPlatformUninitialize();
        QuicPlatformSystemUnload();
    }
};

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
