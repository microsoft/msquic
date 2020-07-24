/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/



#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1
#endif
#include "quic_driver_main.h"

#include "ThroughputServer.h"
#include "ThroughputClient.h"

#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

const QuicApiTable* MsQuic {nullptr};

PerfBase* TestToRun {nullptr};

QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT StopEvent,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    ) {
    const char* TestName = GetValue(argc, argv, "TestName");
    uint8_t ServerMode = 0;
    TryGetValue(argc, argv, "ServerMode", &ServerMode);

    if (!TestName) {
        WriteOutput("Must have a TestName specified. Ex: -TestName:Throughput\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_STATUS Status;
    MsQuic = new QuicApiTable{};
    if (QUIC_FAILED(Status = MsQuic->InitStatus())) {
        delete MsQuic;
        MsQuic = nullptr;
        return Status;
    }

    if (IsValue(TestName, "Throughput")) {
        if (ServerMode) {
            TestToRun = new ThroughputServer{SelfSignedConfig};
        } else {
            TestToRun = new ThroughputClient{};
        }
    } else {
        delete MsQuic;
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (TestToRun != nullptr) {
        Status = TestToRun->Init(argc, argv);
        if (QUIC_SUCCEEDED(Status)) {
            Status = TestToRun->Start(StopEvent);
            if (QUIC_SUCCEEDED(Status)) {
                return QUIC_STATUS_SUCCESS;
            }
        }
    } else {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
    }

    delete TestToRun;
    delete MsQuic;
    return Status;
}

QUIC_STATUS
QuicMainStop(
    _In_ int Timeout
    ) {
    if (TestToRun == nullptr) {
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS Status = TestToRun->Wait(Timeout);
    delete TestToRun;
    delete MsQuic;
    return Status;
}
