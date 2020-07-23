/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/


#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1
#endif
#include "quic_driver_main.h"

#include "ThroughputServer.h"
#include "ThroughputClient.h"

const QUIC_API_TABLE* MsQuic;
#ifdef _KERNEL_MODE
uint8_t SelfSignedSecurityHash[20];
#else
QUIC_SEC_CONFIG_PARAMS* SelfSignedParams{nullptr};
#endif
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

struct QuicMainStore {
    CMsQuic MsQuicHolder;
    UniquePtr<PerfRunner> TestToRun;
};

QuicMainStore* MainStore = nullptr;

int
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT StopEvent
    ) {
    const char* TestName = GetValue(argc, argv, "TestName");
    uint8_t ServerMode = 0;
    TryGetValue(argc, argv, "ServerMode", &ServerMode);

    if (!TestName) {
        WriteOutput("Must have a TestName specified. Ex: -TestName:Throughput\n");
        return QUIC_RUN_MISSING_TEST_TYPE;
    }

    UniquePtr<QuicMainStore> LocalStore{new QuicMainStore};

    if (!LocalStore || !LocalStore->MsQuicHolder.IsValid()) {
        return QUIC_RUN_FAILED_QUIC_OPEN;
    }

    if (IsValue(TestName, "Throughput")) {
        if (ServerMode) {
            LocalStore->TestToRun.reset(new ThroughputServer{});
        } else {
            LocalStore->TestToRun.reset(new ThroughputClient{});
        }
    } else {
        return QUIC_RUN_UNKNOWN_TEST_TYPE;
    }

    if (LocalStore->TestToRun) {
        QUIC_STATUS Status = LocalStore->TestToRun->Init(argc, argv);
        WriteOutput("Init Status! %d\n", Status);
        if (QUIC_SUCCEEDED(Status)) {
            MainStore = LocalStore.release();
            Status = MainStore->TestToRun->Start(StopEvent);
            WriteOutput("Run Status! %s %d\n", QuicStatusToString(Status), QUIC_SUCCEEDED(Status));
            if (QUIC_SUCCEEDED(Status)) {
                return QUIC_RUN_SUCCESS;
            }
        }

    }

    return QUIC_RUN_FAILED_TEST_INITIALIZE;
}

int
QuicMainStop(
    _In_ int Timeout
    ) {
    if (!MainStore) {
        return QUIC_RUN_SUCCESS;
    }

    QUIC_STATUS Status = MainStore->TestToRun->Wait(Timeout);
    delete MainStore;
    if (QUIC_SUCCEEDED(Status)) {
        return QUIC_RUN_SUCCESS;
    }
    return QUIC_RUN_STOP_FAILURE;
}
