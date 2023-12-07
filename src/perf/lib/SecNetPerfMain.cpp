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
CXPLAT_DATAPATH* Datapath;
CxPlatWatchdog* Watchdog;
PerfServer* Server;
PerfClient* Client;

uint32_t MaxRuntime = 0;
QUIC_EXECUTION_PROFILE PerfDefaultExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
QUIC_CONGESTION_CONTROL_ALGORITHM PerfDefaultCongestionControl = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
uint8_t PerfDefaultEcnEnabled = false;
uint8_t PerfDefaultQeoAllowed = false;

#ifdef _KERNEL_MODE
volatile int BufferCurrent;
char Buffer[BufferLength];
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

    //
    // Try to see if there is a client target specified on the command line to
    // determine if we are a client or server.
    //
    const char* Target = nullptr;
    TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "server", &Target);
    TryGetValue(argc, argv, "to", &Target);
    TryGetValue(argc, argv, "remote", &Target);
    TryGetValue(argc, argv, "peer", &Target);

    TryGetValue(argc, argv, "maxruntime", &MaxRuntime);

    QUIC_STATUS Status = QUIC_STATUS_OUT_OF_MEMORY;
    MsQuic = new(std::nothrow) MsQuicApi;
    if (!MsQuic || QUIC_FAILED(Status = MsQuic->GetInitStatus())) {
        WriteOutput("MsQuic failed To initialize, 0x%x.\n", Status);
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

    uint32_t WatchdogTimeout = 0;
    if (TryGetValue(argc, argv, "watchdog", &WatchdogTimeout) && WatchdogTimeout != 0) {
        Watchdog = new(std::nothrow) CxPlatWatchdog(WatchdogTimeout, "perf_watchdog");
    }

    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        PerfServer::DatapathReceive,
        PerfServer::DatapathUnreachable
    };
    Status = CxPlatDataPathInitialize(0, &DatapathCallbacks, &TcpEngine::TcpCallbacks, nullptr, &Datapath);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Datapath for shutdown failed to initialize: %d\n", Status);
        return Status;
    }

    if (Target) {
        Client = new(std::nothrow) PerfClient;
        if ((QUIC_SUCCEEDED(Status = Client->Init(argc, argv, Target, Datapath)) &&
             QUIC_SUCCEEDED(Status = Client->Start(StopEvent)))) {
            return QUIC_STATUS_SUCCESS;
        }
    } else {
        Server = new(std::nothrow) PerfServer(SelfSignedCredConfig);
        if ((QUIC_SUCCEEDED(Status = Server->Init(argc, argv, Datapath)) &&
             QUIC_SUCCEEDED(Status = Server->Start(StopEvent)))) {
            return QUIC_STATUS_SUCCESS;
        }
    }

    PrintHelp();

    return Status; // QuicMainFree is called on failure
}

void
QuicMainStop(
    ) {
    Client ? Client->Wait((int)MaxRuntime) : Server->Wait((int)MaxRuntime);
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
        Datapath = nullptr;
    }

    delete Watchdog;
    Watchdog = nullptr;
}

uint32_t QuicMainGetExtraDataLength() {
    return Client ? Client->GetExtraDataLength() : 0;
}

QUIC_STATUS
QuicMainGetExtraData(
    _Out_writes_bytes_(Length) uint8_t* Data,
    _In_ uint32_t Length
    )
{
    return Client ? Client->GetExtraData(Data, Length) : QUIC_STATUS_INVALID_STATE;
}
