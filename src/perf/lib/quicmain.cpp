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

#ifdef __linux__
#include <sys/resource.h>
#endif

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
uint32_t MaxRuntime = 0;

#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)

class QuicPerfWatchdog {
    CXPLAT_THREAD WatchdogThread;
    CXPLAT_EVENT ShutdownEvent;
    uint32_t TimeoutMs;
    static
    CXPLAT_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (QuicPerfWatchdog*)Context;
        if (!CxPlatEventWaitWithTimeout(This->ShutdownEvent, This->TimeoutMs)) {
            WriteOutput("Watchdog timeout fired!\n");
            CXPLAT_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        CXPLAT_THREAD_RETURN(0);
    }
public:
    QuicPerfWatchdog(uint32_t WatchdogTimeoutMs) : TimeoutMs(WatchdogTimeoutMs) {
        CxPlatEventInitialize(&ShutdownEvent, TRUE, FALSE);
        CXPLAT_THREAD_CONFIG Config = { 0 };
        Config.Name = "perf_watchdog";
        Config.Callback = WatchdogThreadCallback;
        Config.Context = this;
        ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &WatchdogThread));
    }
    ~QuicPerfWatchdog() {
        CxPlatEventSet(ShutdownEvent);
        CxPlatThreadWait(&WatchdogThread);
        CxPlatThreadDelete(&WatchdogThread);
        CxPlatEventUninitialize(ShutdownEvent);
    }
};

QuicPerfWatchdog* Watchdog;

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
    TryGetValue(argc, argv, "maxruntime", &MaxRuntime);

    uint32_t WatchdogTimeout = 0;
    TryGetValue(argc, argv, "watchdog", &WatchdogTimeout);

    Watchdog = new(std::nothrow) QuicPerfWatchdog{WatchdogTimeout};

#ifdef __linux__
    struct rlimit rlim;
    memset(&rlim, 0, sizeof(rlim));
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rlim);
    }
#endif

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
        delete Watchdog;
        Watchdog = nullptr;
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
            delete Watchdog;
            Watchdog = nullptr;
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
    delete Watchdog;
    Watchdog = nullptr;
    return Status;
}

QUIC_STATUS
QuicMainStop(
    ) {
    return TestToRun ? TestToRun->Wait((int)MaxRuntime) : QUIC_STATUS_SUCCESS;
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

    delete Watchdog;
    Watchdog = nullptr;
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
