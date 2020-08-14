/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/

#include "PerfHelpers.h"
#include "ThroughputServer.h"
#include "ThroughputClient.h"
#include "RpsServer.h"
#include "RpsClient.h"

#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

const QuicApiTable* MsQuic;
volatile int BufferCurrent;
char Buffer[BufferLength];

PerfBase* TestToRun;

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "Usage: quicperf -TestName:<Throughput|RPS> [-ServerMode:<1:0>] [options]\n"
        "\n"
        );
}

QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT* StopEvent,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    ) {
    argc--; argv++; // Skip app name

    if (argc == 0 || IsArg(argv[0], "?") || IsArg(argv[0], "help")) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (!IsArg(argv[0], "TestName")) {
        WriteOutput("Must specify -TestName argument\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const char* TestName = GetValue(argc, argv, "TestName");
    argc--; argv++;

    uint8_t ServerMode = 0;
    if (argc != 0 && IsArg(argv[0], "ServerMode")) {
        TryGetValue(argc, argv, "ServerMode", &ServerMode);
        argc--; argv++;
    }

    QUIC_STATUS Status;
    MsQuic = new(std::nothrow) QuicApiTable;
    if (MsQuic == nullptr) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    if (QUIC_FAILED(Status = MsQuic->InitStatus())) {
        delete MsQuic;
        MsQuic = nullptr;
        return Status;
    }

    if (IsValue(TestName, "Throughput")) {
        if (ServerMode) {
            TestToRun = new(std::nothrow) ThroughputServer(SelfSignedConfig);
        } else {
            TestToRun = new(std::nothrow) ThroughputClient;
        }
    } else if (IsValue(TestName, "RPS")) {
        if (ServerMode) {
            TestToRun = new(std::nothrow) RpsServer(SelfSignedConfig);
        } else {
            TestToRun = new(std::nothrow) RpsClient;
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
    TestToRun = nullptr;
    delete MsQuic;
    MsQuic = nullptr;
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
