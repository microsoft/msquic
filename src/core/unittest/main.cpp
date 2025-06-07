/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

extern "C" {
void
MsQuicLibraryLoad(
    void
    );

QUIC_STATUS
MsQuicAddRef(
    void
    );

void
MsQuicRelease(
    void
    );

void
MsQuicLibraryUnload(
    void
    );
}

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        MsQuicLibraryLoad();
        TEST_QUIC_SUCCEEDED(MsQuicAddRef());
    }
    void TearDown() override {
        MsQuicRelease();
        MsQuicLibraryUnload();
        CxPlatZeroMemory(&MsQuicLib, sizeof(MsQuicLib));
    }
};

int QUIC_MAIN_EXPORT main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
