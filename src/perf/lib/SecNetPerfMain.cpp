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
#include "Tcp.h"

#ifndef _KERNEL_MODE
#include <vector>
#endif

#ifdef QUIC_CLOG
#include "SecNetPerfMain.cpp.clog.h"
#endif

const MsQuicApi* MsQuic;
volatile int BufferCurrent;
char Buffer[BufferLength];

PerfBase* TestToRun;

#include "quic_datapath.h"

const uint8_t SecNetPerfShutdownGuid[16] = { // {ff15e657-4f26-570e-88ab-0796b258d11c}
    0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
    0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c};
CXPLAT_THREAD ControlThreadHandle;
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

class SecNetPerfWatchdog {
    CXPLAT_THREAD WatchdogThread;
    CXPLAT_EVENT ShutdownEvent;
    uint32_t TimeoutMs;
    static
    CXPLAT_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (SecNetPerfWatchdog*)Context;
        if (!CxPlatEventWaitWithTimeout(This->ShutdownEvent, This->TimeoutMs)) {
            WriteOutput("Watchdog timeout fired!\n");
            CXPLAT_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        CXPLAT_THREAD_RETURN(0);
    }
public:
    SecNetPerfWatchdog(uint32_t WatchdogTimeoutMs) : TimeoutMs(WatchdogTimeoutMs) {
        CxPlatEventInitialize(&ShutdownEvent, TRUE, FALSE);
        CXPLAT_THREAD_CONFIG Config = { 0 };
        Config.Name = "perf_watchdog";
        Config.Callback = WatchdogThreadCallback;
        Config.Context = this;
        ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &WatchdogThread));
    }
    ~SecNetPerfWatchdog() {
        CxPlatEventSet(ShutdownEvent);
        CxPlatThreadWait(&WatchdogThread);
        CxPlatThreadDelete(&WatchdogThread);
        CxPlatEventUninitialize(ShutdownEvent);
    }
};

SecNetPerfWatchdog* Watchdog;

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "secnetperf usage:\n"
        "\n"
        "Server: secnetperf [options]\n"
        "\n"
        "  -bind:<addr>                A local IP address to bind to.\n"
        "  -cibir:<hex_bytes>          A CIBIR well-known idenfitier.\n"
        "\n"
        "Client: secnetperf -TestName:<Throughput|RPS|HPS> [options]\n"
#ifndef _KERNEL_MODE
        "Both:\n"
        "  -cpu:<cpu_index>            Specify the processor(s) for the datapath to use.\n"
        "  -cipher:<value>             Decimal value of 1 or more QUIC_ALLOWED_CIPHER_SUITE_FLAGS.\n"
#endif // _KERNEL_MODE
        "\n"
        );
}

#ifdef QUIC_USE_RAW_DATAPATH
CXPLAT_THREAD_CALLBACK(ControlThread, Context)
{
    WSADATA WsaData;
    WSAStartup(MAKEWORD(2, 2), &WsaData);

    CXPLAT_EVENT* Event = static_cast<CXPLAT_EVENT*>(Context);
    SOCKADDR_STORAGE Addr = {0};
    uint8_t RecvBuf[sizeof(SecNetPerfShutdownGuid)] = {0};

    IN4ADDR_SETANY((SOCKADDR_IN*)&Addr);
    SS_PORT(&Addr) = htons(9999);
    SOCKET Listener = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (bind(Listener, (SOCKADDR*)&Addr, sizeof(Addr)) == SOCKET_ERROR) {
        printf("control listener failed to bind with error %d\n", WSAGetLastError());
        goto Done;
    }

    while (true) {
        int BytesRcvd =
            recvfrom(
                Listener, (char*)RecvBuf, sizeof(RecvBuf), 0, NULL, NULL);
        if (BytesRcvd == SOCKET_ERROR) {
            int Error = WSAGetLastError();
            if (Error == WSAEMSGSIZE) {
                continue;
            }
            printf("recvfrom failed with error %d\n", Error);
            goto Done;
        }

        if (BytesRcvd == sizeof(RecvBuf) &&
            memcmp(RecvBuf, SecNetPerfShutdownGuid, sizeof(SecNetPerfShutdownGuid)) == 0) {
            break;
        }
    }
Done:
    CxPlatEventSet(*Event);
    closesocket(Listener);
    CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}
#endif

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

    if (WatchdogTimeout != 0) {
        Watchdog = new(std::nothrow) SecNetPerfWatchdog{WatchdogTimeout};
    }

    QUIC_STATUS Status;

#ifdef QUIC_USE_RAW_DATAPATH
    if (ServerMode) {
        CXPLAT_THREAD_CONFIG ThreadConfig = {
            CXPLAT_THREAD_FLAG_NONE,
            0,
            "ControlThread",
            ControlThread,
            StopEvent
        };

        Status = CxPlatThreadCreate(&ThreadConfig, &ControlThreadHandle);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
    }
#else
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        DatapathReceive,
        DatapathUnreachable
    };

    Status = CxPlatDataPathInitialize(0, &DatapathCallbacks, &TcpEngine::TcpCallbacks, nullptr, &Datapath);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Datapath for shutdown failed to initialize: %d\n", Status);
        return Status;
    }

    if (ServerMode) {
        QuicAddr LocalAddress {QUIC_ADDRESS_FAMILY_INET, (uint16_t)9999};
        CXPLAT_UDP_CONFIG UdpConfig = {0};
        UdpConfig.LocalAddress = &LocalAddress.SockAddr;
        UdpConfig.RemoteAddress = nullptr;
        UdpConfig.Flags = 0;
        UdpConfig.InterfaceIndex = 0;
        UdpConfig.CallbackContext = StopEvent;
#ifdef QUIC_OWNING_PROCESS
        UdpConfig.OwningProcess = QuicProcessGetCurrentProcess();
#endif

        Status = CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Binding);
        if (QUIC_FAILED(Status)) {
            CxPlatDataPathUninitialize(Datapath);
            Datapath = nullptr;
            //
            // Must explicitly set binding to null, as CxPlatSocketCreateUdp
            // can set the Binding variable even in invalid cases.
            //
            Binding = nullptr;
            WriteOutput("Datapath Binding for shutdown failed to initialize: %d\n", Status);
            return Status;
        }
    }
#endif

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

#ifndef _KERNEL_MODE
    const char* CpuStr;
    if ((CpuStr = GetValue(argc, argv, "cpu")) != nullptr) {
        std::vector<uint16_t> ProcList;
        if (strtol(CpuStr, nullptr, 10) == -1) {
            // Use all procs for raw datapath except proc 0 so that the machine will be in a usable state.
            for (uint16_t i = 1; i < CxPlatProcActiveCount(); ++i) {
                ProcList.push_back(i);
            }
        } else {
            do {
                if (*CpuStr == ',') CpuStr++;
                ProcList.push_back((uint16_t)strtoul(CpuStr, (char**)&CpuStr, 10));
            } while (*CpuStr);
        }

        if (QUIC_FAILED(
            Status =
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_DATAPATH_PROCESSORS,
                (uint32_t)ProcList.size() * sizeof(uint16_t),
                ProcList.data()))) {
            WriteOutput("MsQuic Failed To Set DataPath Procs %d\n", Status);
            return Status;
        }
    }
#endif // _KERNEL_MODE

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

#ifdef QUIC_USE_RAW_DATAPATH
    if (ControlThreadHandle) {
        CxPlatThreadWait(&ControlThreadHandle);
        CxPlatThreadDelete(&ControlThreadHandle);
    }
#else
    if (Datapath) {
        CxPlatDataPathUninitialize(Datapath);
        Datapath = nullptr;
    }
#endif

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
    _In_ CXPLAT_RECV_DATA* Data
    )
{
    if (Data->BufferLength != sizeof(SecNetPerfShutdownGuid)) {
        return;
    }
    if (memcmp(Data->Buffer, SecNetPerfShutdownGuid, sizeof(SecNetPerfShutdownGuid))) {
        return;
    }
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
