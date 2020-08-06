/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/

#include "PerfHelpers.h"
#include "ThroughputServer.h"
#include "ThroughputClient.h"

#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

const QuicApiTable* MsQuic;

PerfBase* TestToRun;

static
void
PrintHelp(
    ) {
    WriteOutput("Usage: quicperf -TestName:[Throughput|] [options]\n" \
        "\n" \
        "  -ServerMode:<1:0>        default: '0'\n" \
        "\n\n" \
        "Run a test without arguments to see it's specific help\n"
        );
}

QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT* StopEvent,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    ) {
    if (argc < 3 || IsArg(argv[1], "?") || IsArg(argv[1], "help") || !IsArg(argv[2], "TestName")) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const char* TestName = GetValue(argc, argv, "TestName");
    argc -= 2; argv += 2;

    uint8_t ServerMode = 0;
    if (TryGetValue(argc, argv, "ServerMode", &ServerMode)) {
        argc--; argv++;
    }

    QUIC_STATUS Status;
    MsQuic = new QuicApiTable;
    if (QUIC_FAILED(Status = MsQuic->InitStatus())) {
        delete MsQuic;
        MsQuic = nullptr;
        return Status;
    }

    if (IsValue(TestName, "Throughput")) {
        if (ServerMode) {
            TestToRun = new ThroughputServer(SelfSignedConfig);
        } else {
            TestToRun = new ThroughputClient;
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
