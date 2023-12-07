/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/

#include "PerfHelpers.h"
#include "PerfServer.h"
#include "PerfClient.h"
#include "Tcp.h"

#ifdef QUIC_CLOG
#include "SecNetPerfMain.cpp.clog.h"
#endif

const MsQuicApi* MsQuic;
volatile int BufferCurrent;
char Buffer[BufferLength];

QUIC_EXECUTION_PROFILE PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
QUIC_CONGESTION_CONTROL_ALGORITHM PerfDefaultCongestionControl = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
uint8_t PerfDefaultEcnEnabled = false;
uint8_t PerfDefaultQeoAllowed = false;

#include "quic_datapath.h"

const uint8_t SecNetPerfShutdownGuid[16] = { // {ff15e657-4f26-570e-88ab-0796b258d11c}
    0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
    0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c};
CXPLAT_DATAPATH_RECEIVE_CALLBACK DatapathReceive;
CXPLAT_DATAPATH_UNREACHABLE_CALLBACK DatapathUnreachable;
CXPLAT_DATAPATH* Datapath;
CXPLAT_SOCKET* Binding;
CxPlatWatchdog* Watchdog;
PerfServer* Server;
PerfClient* Client;
uint32_t MaxRuntime = 0;

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
        "  -bind:<addr>             A local IP address to bind to.\n"
        "  -port:<####>             The UDP port of the server. Ignored if \"bind\" is passed. (def:%u)\n"
        "  -serverid:<####>         The ID of the server (used for load balancing).\n"
        "  -cibir:<hex_bytes>       A CIBIR well-known idenfitier.\n"
        "\n"
        "Client: secnetperf -target:<hostname/ip> [options]\n"
        "\n"
        "  Remote options:\n"
        "  -ip:<0/4/6>              A hint for the resolving the hostname to an IP address. (def:0)\n"
        "  -port:<####>             The UDP port of the server. (def:%u)\n"
        "  -cibir:<hex_bytes>       A CIBIR well-known idenfitier.\n"
        "  -inctarget:<0/1>         Append unique ID to target hostname for each worker (def:0).\n"
        "\n"
        "  Local options:\n"
        "  -threads:<####>          The max number of worker threads to use.\n"
        "  -affinitize:<0/1>        Affinitizes worker threads to a core. (def:0)\n"
        #ifdef QUIC_COMPARTMENT_ID
        "  -comp:<####>             The network compartment ID to run in.\n"
        #endif
        "  -bind:<addr>             The local IP address(es)/port(s) to bind to.\n"
        "  -share:<0/1>             Shares the same local bindings. (def:0)\n"
        "\n"
        "  Config options:\n"
        "  -tcp:<0/1>               Disables/enables TCP usage (instead of QUIC). (def:0)\n"
        "  -encrypt:<0/1>           Disables/enables encryption. (def:1)\n"
        "  -pacing:<0/1>            Disables/enables send pacing. (def:1)\n"
        "  -sendbuf:<0/1>           Disables/enables send buffering. (def:0)\n"
        "  -ptput:<0/1>             Print throughput information. (def:0)\n"
        "  -pconn:<0/1>             Print connection statistics. (def:0)\n"
        "  -pstream:<0/1>           Print stream statistics. (def:0)\n"
        "  -platency<0/1>           Print latency statistics. (def:0)\n"
        "\n"
        "  Scenario options:\n"
        "  -conns:<####>            The number of connections to use. (def:1)\n"
        "  -streams:<####>          The number of streams to send on at a time. (def:0)\n"
        "  -upload:<####>           The length of bytes to send on each stream. (def:0)\n"
        "  -download:<####>         The length of bytes to receive on each stream. (def:0)\n"
        "  -iosize:<####>           The size of each send request queued.\n"
        "  -timed:<0/1>             Indicates the upload/download args are times (in ms). (def:0)\n"
        //"  -inline:<0/1>            Create new streams on callbacks. (def:0)\n"
        "  -rconn:<0/1>             Repeat the scenario at the connection level. (def:0)\n"
        "  -rstream:<0/1>           Repeat the scenario at the stream level. (def:0)\n"
        "  -runtime:<####>          The total runtime (in ms). Only relevant for repeat scenarios. (def:0)\n"
        "\n"
        "Both (client & server) options:\n"
        "  -exec:<profile>          Execution profile to use {lowlat, maxtput, scavenger, realtime}.\n"
        "  -cc:<algo>               Congestion control algorithm to use {cubic, bbr}.\n"
        "  -pollidle:<time_us>      Amount of time to poll while idle before sleeping (default: 0).\n"
        "  -ecn:<0/1>               Enables/disables sender-side ECN support. (def:0)\n"
        "  -qeo:<0/1>               Allows/disallowes QUIC encryption offload. (def:0)\n"
#ifndef _KERNEL_MODE
        "  -cpu:<cpu_index>         Specify the processor(s) to use.\n"
        "  -cipher:<value>          Decimal value of 1 or more QUIC_ALLOWED_CIPHER_SUITE_FLAGS.\n"
        "  -qtip:<0/1>              Enables/disables QUIC over TCP support. (def:0)\n"
        "  -rio:<0/1>               Enables/disables RIO support. (def:0)\n"
#endif // _KERNEL_MODE
        "\n",
        PERF_DEFAULT_PORT,
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

    if (GetFlag(argc, argv, "?") || GetFlag(argc, argv, "help")) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    bool ClientMode =
        GetValue(argc, argv, "target") ||
        GetValue(argc, argv, "server") ||
        GetValue(argc, argv, "to") ||
        GetValue(argc, argv, "remote") ||
        GetValue(argc, argv, "peer");

    TryGetValue(argc, argv, "maxruntime", &MaxRuntime);

    uint32_t WatchdogTimeout = 0;
    TryGetValue(argc, argv, "watchdog", &WatchdogTimeout);

    if (WatchdogTimeout != 0) {
        Watchdog = new(std::nothrow) CxPlatWatchdog(WatchdogTimeout, "perf_watchdog");
    }

    QUIC_STATUS Status;

    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        DatapathReceive,
        DatapathUnreachable
    };

    Status = CxPlatDataPathInitialize(0, &DatapathCallbacks, &TcpEngine::TcpCallbacks, nullptr, &Datapath);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Datapath for shutdown failed to initialize: %d\n", Status);
        return Status;
    }

    if (!ClientMode) {
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

    uint8_t RawConfig[QUIC_EXECUTION_CONFIG_MIN_SIZE + 256 * sizeof(uint16_t)] = {0};
    QUIC_EXECUTION_CONFIG* Config = (QUIC_EXECUTION_CONFIG*)RawConfig;
    Config->PollingIdleTimeoutUs = UINT32_MAX; // Default to no sleep.
    bool SetConfig = false;

#ifndef _KERNEL_MODE
    uint8_t QuicOverTcpEnabled;
    if (TryGetValue(argc, argv, "qtip", &QuicOverTcpEnabled)) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_QTIP;
        SetConfig = true;
    }

    uint8_t RioEnabled;
    if (TryGetValue(argc, argv, "rio", &RioEnabled)) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_RIO;
        SetConfig = true;
    }

    const char* CpuStr;
    if ((CpuStr = GetValue(argc, argv, "cpu")) != nullptr) {
        SetConfig = true;
        if (strtol(CpuStr, nullptr, 10) == -1) {
            for (uint16_t i = 0; i < CxPlatProcActiveCount() && Config->ProcessorCount < 256; ++i) {
                Config->ProcessorList[Config->ProcessorCount++] = i;
            }
        } else {
            do {
                if (*CpuStr == ',') CpuStr++;
                Config->ProcessorList[Config->ProcessorCount++] =
                    (uint16_t)strtoul(CpuStr, (char**)&CpuStr, 10);
            } while (*CpuStr && Config->ProcessorCount < 256);
        }
    }
#endif // _KERNEL_MODE

    if (TryGetValue(argc, argv, "pollidle", &Config->PollingIdleTimeoutUs)) {
        SetConfig = true;
    }

    if (SetConfig &&
        QUIC_FAILED(
        Status =
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
            (uint32_t)QUIC_EXECUTION_CONFIG_MIN_SIZE + Config->ProcessorCount * sizeof(uint16_t),
            Config))) {
        WriteOutput("Failed to set execution config %d\n", Status);
        return Status;
    }

    const char* ExecStr = GetValue(argc, argv, "exec");
    if (ExecStr != nullptr) {
        if (IsValue(ExecStr, "lowlat")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
        } else if (IsValue(ExecStr, "maxtput")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
        } else if (IsValue(ExecStr, "scavenger")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
        } else if (IsValue(ExecStr, "realtime")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
        } else {
            WriteOutput("Failed to parse execution profile[%s], use lowlat as default\n", ExecStr);
        }
    }

    const char* CcName = GetValue(argc, argv, "cc");
    if (CcName != nullptr) {
        if (IsValue(CcName, "cubic")) {
            PerfDefaultCongestionControl = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
        } else if (IsValue(CcName, "bbr")) {
            PerfDefaultCongestionControl = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
        } else {
            WriteOutput("Failed to parse congestion control algorithm[%s], use cubic as default\n", CcName);
        }
    }

    TryGetValue(argc, argv, "ecn", &PerfDefaultEcnEnabled);
    TryGetValue(argc, argv, "qeo", &PerfDefaultQeoAllowed);

    if (ClientMode) {
        Client = new(std::nothrow) PerfClient;
        if ((QUIC_SUCCEEDED(Status = Client->Init(argc, argv)) &&
             QUIC_SUCCEEDED(Status = Client->Start(StopEvent)))) {
            return QUIC_STATUS_SUCCESS;
        }
        WriteOutput("Client Failed To Start: %d\n", Status);
        delete Client;
        Client = nullptr;
    } else {
        Server = new(std::nothrow) PerfServer(SelfSignedCredConfig);
        if ((QUIC_SUCCEEDED(Status = Server->Init(argc, argv)) &&
             QUIC_SUCCEEDED(Status = Server->Start(StopEvent)))) {
            return QUIC_STATUS_SUCCESS;
        }
        WriteOutput("Server Failed To Start: %d\n", Status);
        delete Server;
        Server = nullptr;
    }

    delete MsQuic;
    MsQuic = nullptr;
    delete Watchdog;
    Watchdog = nullptr;
    return Status;
}

QUIC_STATUS
QuicMainStop(
    ) {
    return Client ? Client->Wait((int)MaxRuntime) : Server->Wait((int)MaxRuntime);
}

void
QuicMainFree(
    )
{
    delete Client;
    Client = nullptr;
    delete Server;
    Server = nullptr;
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
QuicMainGetExtraDataLength(
    _Out_ uint32_t* DataLength
    )
{
    if (Client == nullptr) {
        return QUIC_STATUS_INVALID_STATE;
    }

    Client->GetExtraDataLength(DataLength);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicMainGetExtraData(
    _Out_writes_bytes_(*Length) uint8_t* Data,
    _Inout_ uint32_t* Length
    )
{
    if (Client == nullptr) {
        *Length = 0;
        return QUIC_STATUS_INVALID_STATE;
    }

    return Client->GetExtraData(Data, Length);
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
