/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"

#ifdef QUIC_LOGS_WPP
#include "main.tmh"
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

struct TestLogger {
    const char* TestName;
    TestLogger(const char* Name) : TestName(Name) {
        QuicTraceLogInfo("[test] START %s", TestName);
    }
    ~TestLogger() {
        QuicTraceLogInfo("[test] END %s", TestName);
    }
};

template<class T>
struct TestLoggerT {
    const char* TestName;
    TestLoggerT(const char* Name, const T& Params) : TestName(Name) {
        std::ostringstream stream; stream << Params;
        QuicTraceLogInfo("[test] START %s, %s", TestName, stream.str().c_str());
    }
    ~TestLoggerT() {
        QuicTraceLogInfo("[test] END %s", TestName);
    }
};

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
