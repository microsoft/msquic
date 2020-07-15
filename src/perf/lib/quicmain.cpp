#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

#include "quic_driver_run.h"

#include "ThroughputServer.h"

const QUIC_API_TABLE* MsQuic;
uint8_t SelfSignedSecurityHash[20];
bool IsSelfSignedValid{ false };

struct CMsQuic {
    CMsQuic() :
        Result{MsQuicOpen(&MsQuic)} 
    {
    }
    ~CMsQuic() 
    {
        if (IsValid()) {
            MsQuicClose(MsQuic);
        }
    }
    bool IsValid() const { return QUIC_SUCCEEDED(Result); }
    QUIC_STATUS Result;
};

int
QuicMain(int argc, char ** argv, QUIC_EVENT StopEvent, QUIC_EVENT ReadyEvent) {

    auto TestName = GetValue(argc, argv, "TestName");
    uint8_t ServerMode = 0;
    TryGetValue(argc, argv, "ServerMode", &ServerMode);

    if (!TestName) {
        WriteOutput("Must have a TestName specified. Ex: -TestName:Throughput\n");
        return QUIC_RUN_MISSING_TEST_TYPE;
    }

    CMsQuic MsQuicHolder;

    if (!MsQuicHolder.IsValid()) {
        return QUIC_RUN_FAILED_QUIC_OPEN;
    }

    UniquePtr<TestRunner> TestToRun;

    if (IsValue(TestName, "Throughput")) {
        if (ServerMode) {
            TestToRun.reset(new ThroughputServer{argc, argv});
        } else {
            // TODO Throughput Client
        }
    } else {
        return QUIC_RUN_UNKNOWN_TEST_TYPE;
    }

    if (TestToRun && TestToRun->IsValid()) {
        if (QUIC_SUCCEEDED(TestToRun->Init())) {
            return TestToRun->Run(StopEvent, ReadyEvent);
        }

    }

    return QUIC_RUN_FAILED_TEST_INITIALIZE;
}
