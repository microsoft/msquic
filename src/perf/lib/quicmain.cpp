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
#include "HpsClient.h"

#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

const MsQuicApi* MsQuic;
volatile int BufferCurrent;
char Buffer[BufferLength];

PerfBase* TestToRun;

#include "quic_datapath.h"

CXPLAT_DATAPATH_RECEIVE_CALLBACK DatapathReceive;
CXPLAT_DATAPATH_UNREACHABLE_CALLBACK DatapathUnreachable;
CXPLAT_DATAPATH* Datapath;
CXPLAT_SOCKET* Binding;
bool ServerMode = false;

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "quicperf usage:\n"
        "\n"
        "Server: quicperf [options]\n"
        "\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "\n"
        "Client: quicperf -TestName:<Throughput|RPS|HPS> [options]\n"
        "\n",
        PERF_DEFAULT_PORT
        );
}

QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ CXPLAT_EVENT* StopEvent,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig
    ) {
    argc--; argv++; // Skip app name

    if (argc != 0 && (IsArg(argv[0], "?") || IsArg(argv[0], "help"))) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const char* TestName = GetValue(argc, argv, "TestName");
    if (TestName == nullptr) {
        TestName = GetValue(argc, argv, "test");
    }

    ServerMode = TestName == nullptr;

    QUIC_STATUS Status;

    if (ServerMode) {
        Datapath = nullptr;
        Binding = nullptr;
        const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
            DatapathReceive,
            DatapathUnreachable
        };
        Status = CxPlatDataPathInitialize(0, &DatapathCallbacks, NULL, &Datapath);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Datapath for shutdown failed to initialize: %d\n", Status);
            return Status;
        }

        QuicAddr LocalAddress {QUIC_ADDRESS_FAMILY_INET, (uint16_t)9999};
        Status = CxPlatSocketCreateUdp(Datapath, &LocalAddress.SockAddr, nullptr, StopEvent, &Binding);
        if (QUIC_FAILED(Status)) {
            CxPlatDataPathUninitialize(Datapath);
            Datapath = nullptr;
            WriteOutput("Datapath Binding for shutdown failed to initialize: %d\n", Status);
            return Status;
        }
    }

    MsQuic = new(std::nothrow) MsQuicApi;
    if (MsQuic == nullptr) {
        WriteOutput("MsQuic Alloc Out of Memory\n");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    if (QUIC_FAILED(Status = MsQuic->GetInitStatus())) {
        delete MsQuic;
        MsQuic = nullptr;
        WriteOutput("MsQuic Failed To Initialize: %d\n", Status);
        return Status;
    }

    if (ServerMode) {
        TestToRun = new(std::nothrow) PerfServer(SelfSignedCredConfig);
    } else {
        if (IsValue(TestName, "Throughput") || IsValue(TestName, "tput")) {
            TestToRun = new(std::nothrow) ThroughputClient;
        } else if (IsValue(TestName, "RPS")) {
            TestToRun = new(std::nothrow) RpsClient;
        } else if (IsValue(TestName, "HPS")) {
            TestToRun = new(std::nothrow) HpsClient;
        } else {
            PrintHelp();
            delete MsQuic;
            MsQuic = nullptr;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if (TestToRun != nullptr) {
        Status = TestToRun->Init(argc, argv);
        if (QUIC_SUCCEEDED(Status)) {
            Status = TestToRun->Start(StopEvent);
            if (QUIC_SUCCEEDED(Status)) {
                return QUIC_STATUS_SUCCESS;
            } else {
                WriteOutput("Test Failed To Start: %d\n", Status);
            }
        } else {
            WriteOutput("Test Failed To Initialize: %d\n", Status);
        }
    } else {
        WriteOutput("Test Alloc Out Of Memory\n");
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
    return Status;
}

void
QuicMainFree(
    )
{
    delete TestToRun;
    TestToRun = nullptr;
    delete MsQuic;
    MsQuic = nullptr;

    if (Binding) {
        CxPlatSocketDelete(Binding);
        Binding = nullptr;
    }
    if (Datapath) {
        CxPlatDataPathUninitialize(Datapath);
        Datapath = nullptr;
    }
}

QUIC_STATUS
QuicMainGetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Metadata
    )
{
    if (TestToRun == nullptr) {
        return QUIC_STATUS_INVALID_STATE;
    }

    TestToRun->GetExtraDataMetadata(Metadata);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicMainGetExtraData(
    _Out_writes_bytes_(*Length) uint8_t* Data,
    _Inout_ uint32_t* Length
    )
{
    if (TestToRun == nullptr) {
        *Length = 0;
        return QUIC_STATUS_INVALID_STATE;
    }

    return TestToRun->GetExtraData(Data, Length);
}

void
DatapathReceive(
    _In_ CXPLAT_SOCKET*,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA*
    )
{
    CXPLAT_EVENT* Event = static_cast<CXPLAT_EVENT*>(Context);
    CxPlatEventSet(*Event);
}

void
DatapathUnreachable(
    _In_ CXPLAT_SOCKET*,
    _In_ void*,
    _In_ const QUIC_ADDR*
    )
{
    //
    // Do nothing, we never send
    //
}
