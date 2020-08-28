/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/

#include "PerfHelpers.h"
#include "PerfServer.h"
#include "ThroughputClient.h"
#include "RpsClient.h"

#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

const QuicApiTable* MsQuic;
volatile int BufferCurrent;
char Buffer[BufferLength];

PerfBase* TestToRun;

#include "quic_datapath.h"

QUIC_DATAPATH_RECEIVE_CALLBACK DatapathReceive;
QUIC_DATAPATH_UNREACHABLE_CALLBACK DatapathUnreachable;
QUIC_DATAPATH* Datapath;
QUIC_DATAPATH_BINDING* Binding;
uint8_t ServerMode = 0;

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "Usage: quicperf -ServerMode:<1:0> [-TestName:<Throughput|RPS>] [options]\n"
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

    ServerMode = 0;
    if (!IsArg(argv[0], "ServerMode")) {
        WriteOutput("Must specify -ServerMode argument\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    TryGetValue(argc, argv, "ServerMode", &ServerMode);
    argc--; argv++;

    QUIC_STATUS Status;

    if (ServerMode) {
        Datapath = nullptr;
        Binding = nullptr;
        Status = QuicDataPathInitialize(0, DatapathReceive, DatapathUnreachable, &Datapath);
        if (QUIC_FAILED(Status)) {
            return Status;
        }

        QuicAddr LocalAddress {AF_INET, (uint16_t)9999};
        Status = QuicDataPathBindingCreate(Datapath, &LocalAddress.SockAddr, nullptr, StopEvent, &Binding);
        if (QUIC_FAILED(Status)) {
            QuicDataPathUninitialize(Datapath);
            return Status;
        }
    }

    MsQuic = new(std::nothrow) QuicApiTable;
    if (MsQuic == nullptr) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    if (QUIC_FAILED(Status = MsQuic->InitStatus())) {
        delete MsQuic;
        MsQuic = nullptr;
        return Status;
    }

    if (ServerMode) {
        TestToRun = new(std::nothrow) PerfServer(SelfSignedConfig);

    } else {
        if (!IsArg(argv[0], "TestName")) {
            WriteOutput("Must specify -TestName argument\n");
            PrintHelp();
            delete MsQuic;
            MsQuic = nullptr;
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        const char* TestName = GetValue(argc, argv, "TestName");
        argc--; argv++;

        if (IsValue(TestName, "Throughput")) {
            TestToRun = new(std::nothrow) ThroughputClient;
        } else if (IsValue(TestName, "RPS")) {
            TestToRun = new(std::nothrow) RpsClient;
        } else {
            delete MsQuic;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
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
        if (ServerMode) {
            QuicDataPathBindingDelete(Binding);
            QuicDataPathUninitialize(Datapath);
            Datapath = nullptr;
            Binding = nullptr;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS Status = TestToRun->Wait(Timeout);
    delete TestToRun;
    delete MsQuic;
    if (ServerMode) {
        QuicDataPathBindingDelete(Binding);
        QuicDataPathUninitialize(Datapath);
        Datapath = nullptr;
        Binding = nullptr;
    }
    MsQuic = nullptr;
    TestToRun = nullptr;
    return Status;
}

void
DatapathReceive(
    _In_ QUIC_DATAPATH_BINDING*,
    _In_ void* Context,
    _In_ QUIC_RECV_DATAGRAM*
    )
{
    QUIC_EVENT* Event = static_cast<QUIC_EVENT*>(Context);
    QuicEventSet(*Event);
}

void
DatapathUnreachable(
    _In_ QUIC_DATAPATH_BINDING*,
    _In_ void*,
    _In_ const QUIC_ADDR*
    )
{
    //
    // Do nothing, we never send
    //
}
