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

const QuicApiTable* MsQuic{nullptr};
#ifdef _KERNEL_MODE
uint8_t SelfSignedSecurityHash[20];
#else
QUIC_SEC_CONFIG_PARAMS* SelfSignedParams{nullptr};
#endif
bool IsSelfSignedValid{ false };

PerfRunner* TestToRun{nullptr};

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

    MsQuic = new QuicApiTable{};

    if (QUIC_FAILED(MsQuic->InitStatus())) {
        delete MsQuic;
        MsQuic = nullptr;
        return QUIC_RUN_FAILED_QUIC_OPEN;
    }

    if (IsValue(TestName, "Throughput")) {
        if (ServerMode) {
            TestToRun = new ThroughputServer{};
        } else {
            TestToRun = new ThroughputClient{};
        }
    } else {
        delete MsQuic;
        return QUIC_RUN_UNKNOWN_TEST_TYPE;
    }

    if (TestToRun != nullptr) {
        QUIC_STATUS Status = TestToRun->Init(argc, argv);
        WriteOutput("Init Status! %d\n", Status);
        if (QUIC_SUCCEEDED(Status)) {
            Status = TestToRun->Start(StopEvent);
            WriteOutput("Run Status! %s %d\n", QuicStatusToString(Status), QUIC_SUCCEEDED(Status));
            if (QUIC_SUCCEEDED(Status)) {
                return QUIC_RUN_SUCCESS;
            }
        }
    }

    if (TestToRun != nullptr) {
        delete TestToRun;
    }
    if (MsQuic != nullptr) {
        delete MsQuic;
    }
    return QUIC_RUN_FAILED_TEST_INITIALIZE;
}

int
QuicMainStop(
    _In_ int Timeout
    ) {
    if (TestToRun == nullptr) {
        return QUIC_RUN_SUCCESS;
    }

    QUIC_STATUS Status = TestToRun->Wait(Timeout);
    delete TestToRun;
    delete MsQuic;
    if (QUIC_SUCCEEDED(Status)) {
        return QUIC_RUN_SUCCESS;
    }
    return QUIC_RUN_STOP_FAILURE;
}
