/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution engine.

--*/

#include "SecNetPerf.h"
#include "PerfServer.h"
#include "PerfClient.h"
#include "Tcp.h"

const MsQuicApi* MsQuic;
CXPLAT_WORKER_POOL WorkerPool;
CXPLAT_DATAPATH* Datapath;
CxPlatWatchdog* Watchdog;
PerfServer* Server;
PerfClient* Client;

uint32_t MaxRuntime = 0;
QUIC_EXECUTION_PROFILE PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
TCP_EXECUTION_PROFILE TcpDefaultExecutionProfile = TCP_EXECUTION_PROFILE_LOW_LATENCY;
QUIC_CONGESTION_CONTROL_ALGORITHM PerfDefaultCongestionControl = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
uint8_t PerfDefaultEcnEnabled = false;
uint8_t PerfDefaultQeoAllowed = false;
uint8_t PerfDefaultHighPriority = false;
uint8_t PerfDefaultAffinitizeThreads = false;

#ifdef _KERNEL_MODE
volatile int BufferCurrent;
char Buffer[BufferLength];
static inline LONG _strtol(const CHAR* nptr, CHAR** endptr, int base) {
    UNREFERENCED_PARAMETER(base);
    ULONG temp;
    RtlCharToInteger(nptr, base, &temp);
    if (endptr != NULL) {
        const CHAR* ptr = nptr;
        while (*ptr >= '0' && *ptr <= '9') {
            ptr++;
        }
        *endptr = (CHAR*)ptr;
    }
    return (LONG)temp;
}

static inline ULONG _strtoul(const CHAR* nptr, CHAR** endptr, int base) {
    UNREFERENCED_PARAMETER(base);
    ULONG temp;
    RtlCharToInteger(nptr, base, &temp);
    if (endptr != NULL) {
        const CHAR* ptr = nptr;
        while (*ptr >= '0' && *ptr <= '9') {
            ptr++;
        }
        *endptr = (CHAR*)ptr;
    }
    return temp;
}
#else
#define _strtol strtol
#define _strtoul strtoul
#endif

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
        "  -inctarget:<0/1>         Append unique ID to target hostname for each worker (def:1).\n"
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
        "  -scenario:<profile>      Scenario profile to use.\n"
        "                            - {upload, download, hps, rps, rps-multi, latency}.\n"
        "  -conns:<####>            The number of connections to use. (def:1)\n"
        "  -streams:<####>          The number of streams to send on at a time. (def:0)\n"
        "  -upload:<####>[unit]     The length of bytes to send on each stream, with an optional (time or length) unit. (def:0)\n"
        "  -download:<####>[unit]   The length of bytes to receive on each stream, with an optional (time or length) unit. (def:0)\n"
        "  -iosize:<####>           The size of each send request queued.\n"
        //"  -inline:<0/1>            Create new streams on callbacks. (def:0)\n"
        "  -rconn:<0/1>             Repeat the scenario at the connection level. (def:0)\n"
        "  -rstream:<0/1>           Repeat the scenario at the stream level. (def:0)\n"
        "  -runtime:<####>[unit]    The total runtime, with an optional unit (def unit is us). Only relevant for repeat scenarios. (def:0)\n"
        "\n"
        "Both (client & server) options:\n"
        "  -exec:<profile>          Execution profile to use.\n"
        "                            - {lowlat, maxtput, scavenger, realtime}.\n"
        "  -cc:<algo>               Congestion control algorithm to use.\n"
        "                            - {cubic, bbr}.\n"
        "  -pollidle:<time_us>      Amount of time to poll while idle before sleeping (default: 0).\n"
        "  -ecn:<0/1>               Enables/disables sender-side ECN support. (def:0)\n"
        "  -qeo:<0/1>               Allows/disallowes QUIC encryption offload. (def:0)\n"
#ifdef _KERNEL_MODE
        "  -io:<mode>               Configures a requested network IO model to be used.\n"
        "                            - {iocp, rio, xdp, qtip, wsk, epoll, kqueue}\n"
#else
        "  -io:<mode>               Configures a requested network IO model to be used.\n"
        "                            - {xdp}\n"
#endif // _KERNEL_MODE
        "  -cpu:<cpu_index>         Specify the processor(s) to use.\n"
        "  -cipher:<value>          Decimal value of 1 or more QUIC_ALLOWED_CIPHER_SUITE_FLAGS.\n"
        "  -highpri:<0/1>           Configures MsQuic to run threads at high priority. (def:0)\n"
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
    _In_opt_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig
    ) {
    argc--; argv++; // Skip app name

    if (GetFlag(argc, argv, "?") || GetFlag(argc, argv, "help")) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Try to see if there is a client target specified on the command line to
    // determine if we are a client or server.
    //
    const char* Target = TryGetTarget(argc, argv);

    TryGetValue(argc, argv, "maxruntime", &MaxRuntime);

    QUIC_STATUS Status = QUIC_STATUS_OUT_OF_MEMORY;
    MsQuic = new(std::nothrow) MsQuicApi;
    if (!MsQuic || QUIC_FAILED(Status = MsQuic->GetInitStatus())) {
        WriteOutput("MsQuic failed To initialize, 0x%x.\n", Status);
        return Status;
    }

    uint8_t RawConfig[QUIC_EXECUTION_CONFIG_MIN_SIZE + 256 * sizeof(uint16_t)] = {0};
    QUIC_EXECUTION_CONFIG* Config = (QUIC_EXECUTION_CONFIG*)RawConfig;
    Config->PollingIdleTimeoutUs = 0; // Default to no polling.
    bool SetConfig = false;
    const char* IoMode = GetValue(argc, argv, "io");

#ifndef _KERNEL_MODE
    if (IoMode && IsValue(IoMode, "qtip")) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_QTIP;
        SetConfig = true;
    }

    if (IoMode && IsValue(IoMode, "rio")) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_RIO;
        SetConfig = true;
    }

#endif // _KERNEL_MODE

    if (IoMode && IsValue(IoMode, "xdp")) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_XDP;
        SetConfig = true;
    }

    const char* CpuStr;
    if ((CpuStr = GetValue(argc, argv, "cpu")) != nullptr) {
        SetConfig = true;
        if (_strtol(CpuStr, nullptr, 10) == -1) {
            for (uint32_t i = 0; i < CxPlatProcCount() && Config->ProcessorCount < 256; ++i) {
                Config->ProcessorList[Config->ProcessorCount++] = (uint16_t)i;
            }
        } else {
            do {
                if (*CpuStr == ',') CpuStr++;
                Config->ProcessorList[Config->ProcessorCount++] =
                    (uint16_t)_strtoul(CpuStr, (char**)&CpuStr, 10);
            } while (*CpuStr && Config->ProcessorCount < 256);
        }
    }

    TryGetValue(argc, argv, "highpri", &PerfDefaultHighPriority);
    if (PerfDefaultHighPriority) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_HIGH_PRIORITY;
        SetConfig = true;
    }

    TryGetValue(argc, argv, "affinitize", &PerfDefaultAffinitizeThreads);
    if (PerfDefaultHighPriority) {
        Config->Flags |= QUIC_EXECUTION_CONFIG_FLAG_AFFINITIZE;
        SetConfig = true;
    }

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

    const char* ScenarioStr = GetValue(argc, argv, "scenario");
    if (ScenarioStr != nullptr) {
        if (IsValue(ScenarioStr, "upload") ||
            IsValue(ScenarioStr, "download") ||
            IsValue(ScenarioStr, "hps")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
            TcpDefaultExecutionProfile = TCP_EXECUTION_PROFILE_MAX_THROUGHPUT;
        } else if (
            IsValue(ScenarioStr, "rps") ||
            IsValue(ScenarioStr, "rps-multi") ||
            IsValue(ScenarioStr, "latency")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
            TcpDefaultExecutionProfile = TCP_EXECUTION_PROFILE_LOW_LATENCY;
        } else {
            WriteOutput("Failed to parse scenario profile[%s]!\n", ScenarioStr);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    const char* ExecStr = GetValue(argc, argv, "exec");
    if (ExecStr != nullptr) {
        if (IsValue(ExecStr, "lowlat")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
            TcpDefaultExecutionProfile = TCP_EXECUTION_PROFILE_LOW_LATENCY;
        } else if (IsValue(ExecStr, "maxtput")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
            TcpDefaultExecutionProfile = TCP_EXECUTION_PROFILE_MAX_THROUGHPUT;
        } else if (IsValue(ExecStr, "scavenger")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
        } else if (IsValue(ExecStr, "realtime")) {
            PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
        } else {
            WriteOutput("Failed to parse execution profile[%s]!\n", ExecStr);
            return QUIC_STATUS_INVALID_PARAMETER;
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

    uint32_t WatchdogTimeout = 0;
    if (TryGetValue(argc, argv, "watchdog", &WatchdogTimeout) && WatchdogTimeout != 0) {
        Watchdog = new(std::nothrow) CxPlatWatchdog(WatchdogTimeout, "perf_watchdog", true);
    }

    CxPlatWorkerPoolInit(&WorkerPool);

    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        PerfServer::DatapathReceive,
        PerfServer::DatapathUnreachable
    };
    Status = CxPlatDataPathInitialize(0, &DatapathCallbacks, &TcpEngine::TcpCallbacks, &WorkerPool, nullptr, &Datapath);
    if (QUIC_FAILED(Status)) {
        CxPlatWorkerPoolUninit(&WorkerPool);
        WriteOutput("Datapath for shutdown failed to initialize: %d\n", Status);
        return Status;
    }

    if (Target) {
        Client = new(std::nothrow) PerfClient;
        if ((QUIC_SUCCEEDED(Status = Client->Init(argc, argv, Target)) &&
             QUIC_SUCCEEDED(Status = Client->Start(StopEvent)))) {
            return QUIC_STATUS_SUCCESS;
        }
    } else {
        CXPLAT_FRE_ASSERT(SelfSignedCredConfig);
        Server = new(std::nothrow) PerfServer(SelfSignedCredConfig);
        if ((QUIC_SUCCEEDED(Status = Server->Init(argc, argv)) &&
             QUIC_SUCCEEDED(Status = Server->Start(StopEvent)))) {
            return QUIC_STATUS_SUCCESS;
        }
    }

    WriteOutput("\nPlease run 'secnetperf -help' for command line options.\n");

    return Status; // QuicMainFree is called on failure
}

QUIC_STATUS
QuicMainWaitForCompletion(
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

    if (Datapath) {
        CxPlatDataPathUninitialize(Datapath);
        CxPlatWorkerPoolUninit(&WorkerPool);
        Datapath = nullptr;
    }

    delete Watchdog;
    Watchdog = nullptr;
}

uint32_t QuicMainGetExtraDataLength() {
    return Client ? Client->GetExtraDataLength() : 0;
}

void
QuicMainGetExtraData(
    _Out_writes_bytes_(Length) uint8_t* Data,
    _In_ uint32_t Length
    )
{
    CXPLAT_FRE_ASSERT(Client);
    Client->GetExtraData(Data, Length);
}
