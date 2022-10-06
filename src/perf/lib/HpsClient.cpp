/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf HPS Client Implementation.

--*/

#include "HpsClient.h"

#ifdef QUIC_CLOG
#include "HpsClient.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "HPS Client options:\n"
        "\n"
        "  -target:<####>              The target server to connect to.\n"
        "  -runtime:<####>             The total runtime (in ms). (def:%u)\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -parallel:<####>            The number of parallel connections per core. (def:%u)\n"
        "  -threads:<####>             The number of threads to use. Defaults and capped to number of cores/threads\n"
        "  -incrementtarget:<#>        Set to 1 to append core index to target\n"
        "\n",
        HPS_DEFAULT_RUN_TIME,
        PERF_DEFAULT_PORT,
        HPS_DEFAULT_PARALLEL_COUNT
        );
}

QUIC_STATUS
HpsClient::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (argc > 0 && (IsArg(argv[0], "?") || IsArg(argv[0], "help"))) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (!Configuration.IsValid()) {
        return Configuration.GetInitStatus();
    }

    ActiveProcCount = CxPlatProcActiveCount();
    if (ActiveProcCount >= 60) {
        //
        // If we have enough cores, leave 2 cores for OS overhead
        //
        ActiveProcCount -= 2;
    }

    uint32_t TmpProcCount = ActiveProcCount;
    if (TryGetValue(argc, argv, "threads", &TmpProcCount) && TmpProcCount < ActiveProcCount) {
        if (TmpProcCount == 0) {
            PrintHelp();
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        ActiveProcCount = TmpProcCount;
    }

    if (ActiveProcCount > PERF_MAX_THREAD_COUNT) {
        ActiveProcCount = PERF_MAX_THREAD_COUNT;
    }

    const char* target;
    if (!TryGetValue(argc, argv, "target", &target) &&
        !TryGetValue(argc, argv, "server", &target)) {
        WriteOutput("Must specify '-target' argument!\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t Len = strlen(target);
    Target.reset(new(std::nothrow) char[Len + 1]);
    if (!Target.get()) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatCopyMemory(Target.get(), target, Len);
    Target[Len] = '\0';

    TryGetValue(argc, argv, "runtime", &RunTime);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "parallel", &Parallel);
    TryGetValue(argc, argv, "incrementtarget", &IncrementTarget);

    return QUIC_STATUS_SUCCESS;
}

static void AppendIntToString(char* String, uint8_t Value) {
    const char* Hex = "0123456789ABCDEF";

    String[0] = Hex[(Value >> 4) & 0xF];
    String[1] = Hex[Value & 0xF];
    String[2] = '\0';
}

CXPLAT_THREAD_CALLBACK(HpsWorkerThread, Context)
{
    auto Worker = (HpsWorkerContext*)Context;

    while (!Worker->pThis->Shutdown) {
        if ((uint32_t)Worker->OutstandingConnections == Worker->pThis->Parallel) {
            CxPlatEventWaitForever(Worker->WakeEvent);
        } else {
            InterlockedIncrement(&Worker->OutstandingConnections);
            Worker->pThis->StartConnection(Worker);
        }
    }

    CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

QUIC_STATUS
HpsClient::Start(
    _In_ CXPLAT_EVENT* StopEvent
    ) {
    CompletionEvent = StopEvent;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_DATAPATH* Datapath = nullptr;
    if (QUIC_FAILED(Status = CxPlatDataPathInitialize(0, nullptr, nullptr, nullptr, &Datapath))) {
        WriteOutput("Failed to initialize datapath for resolution!\n");
        return Status;
    }

    for (uint32_t Proc = 0; Proc < ActiveProcCount; ++Proc) {
        auto Worker = &Contexts[Proc];

        Worker->pThis = this;
        Worker->Processor = (uint16_t)Proc;

        const char* NewTarget = Target.get();
        size_t Len = strlen(NewTarget);
        Worker->Target.reset(new(std::nothrow) char[Len + 10]);
        CxPlatCopyMemory(Worker->Target.get(), NewTarget, Len);
        if (IncrementTarget) {
            AppendIntToString(Worker->Target.get() + Len, (uint8_t)Worker->Processor);
        } else {
            Worker->Target.get()[Len] = '\0';
        }

        Status = CxPlatDataPathResolveAddress(Datapath, Worker->Target.get(), &Worker->RemoteAddr);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Failed to resolve remote address!\n");
            break;
        }
    }

    CxPlatDataPathUninitialize(Datapath);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    StartTime = CxPlatTimeUs64();

    for (uint32_t Proc = 0; Proc < ActiveProcCount; ++Proc) {
        auto Worker = &Contexts[Proc];

        CXPLAT_THREAD_CONFIG ThreadConfig = {
            CXPLAT_THREAD_FLAG_SET_AFFINITIZE,
            (uint16_t)Proc,
            "HPS Worker",
            HpsWorkerThread,
            Worker
        };

        Status = CxPlatThreadCreate(&ThreadConfig, &Worker->Thread);
        if (QUIC_FAILED(Status)) {
            break;
        }
        Worker->ThreadStarted = true;
    }

    uint32_t ThreadToSetAffinityTo = CxPlatProcActiveCount();
    if (ThreadToSetAffinityTo > 2) {
        ThreadToSetAffinityTo -= 2;
        Status =
            CxPlatSetCurrentThreadProcessorAffinity((uint16_t)ThreadToSetAffinityTo);
    }

    return Status;
}

QUIC_STATUS
HpsClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout == 0) {
        Timeout = RunTime;
    }

    WriteOutput("Waiting %d ms!\n", Timeout);
    CxPlatEventWaitWithTimeout(*CompletionEvent, Timeout);

    Shutdown = true;
    for (uint32_t i = 0; i < ActiveProcCount; ++i) {
        CxPlatEventSet(Contexts[i].WakeEvent);
    }

    uint64_t CreatedConnections = 0;
    uint64_t StartedConnections = 0;
    uint64_t CompletedConnections = 0;

    for (uint32_t i  = 0; i < ActiveProcCount; i++) {
        Contexts[i].WaitForWorker();
        CreatedConnections += (uint64_t)Contexts[i].CreatedConnections;
        StartedConnections += (uint64_t)Contexts[i].StartedConnections;
        CompletedConnections += (uint64_t)Contexts[i].CompletedConnections;
    }

    uint64_t EndTime = CxPlatTimeUs64();

    RunTime = (uint32_t)US_TO_MS(CxPlatTimeDiff64(StartTime, EndTime));

    uint32_t HPS = (uint32_t)((CompletedConnections * 1000ull) / (uint64_t)RunTime);
    if (HPS == 0) {
        WriteOutput("Error: No handshakes were completed (%u created, %u started\n)",
            (uint32_t)CreatedConnections, (uint32_t)StartedConnections);
    } else {
        WriteOutput("Result: %u HPS\n", HPS);
    }
    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);

    return QUIC_STATUS_SUCCESS;
}

void
HpsClient::GetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Result
    )
{
    Result->TestType = PerfTestType::HpsClient;
    Result->ExtraDataLength = 0;
}

QUIC_STATUS
HpsClient::GetExtraData(
    _Out_writes_bytes_(*Length) uint8_t*,
    _Inout_ uint32_t* Length
    )
{
    *Length = 0;
    return QUIC_STATUS_SUCCESS;
}

static
QUIC_STATUS
ConnectionCallback(
    _In_opt_ HpsBindingContext* Binding,
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        MsQuic->SetContext(ConnectionHandle, nullptr); // Dissassociate our context with this connection now
        InterlockedIncrement64(&Binding->Worker->CompletedConnections);
        if (QuicAddrGetPort(&Binding->LocalAddr) == 0) { // Cache local address
            uint32_t AddrLen = sizeof(Binding->LocalAddr);
            MsQuic->GetParam(
                ConnectionHandle,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                &AddrLen,
                &Binding->LocalAddr);
        }
        MsQuic->ConnectionShutdown(ConnectionHandle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        InterlockedDecrement(&Binding->Worker->OutstandingConnections);
        CxPlatEventSet(Binding->Worker->WakeEvent);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (Binding) { // Means we failed to connect
            InterlockedDecrement(&Binding->Worker->OutstandingConnections);
            CxPlatEventSet(Binding->Worker->WakeEvent);
        }
        MsQuic->ConnectionClose(ConnectionHandle);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


void
HpsClient::StartConnection(
    HpsWorkerContext* Worker
    ) {

    HpsBindingContext* Binding = &Worker->Bindings[Worker->NextLocalAddr];
    Worker->NextLocalAddr = (Worker->NextLocalAddr + 1) % HPS_BINDINGS_PER_WORKER;

    struct ScopeCleanup {
        HQUIC Connection {nullptr};
        HpsBindingContext* Binding;
        ScopeCleanup(HpsBindingContext* Binding) : Binding(Binding) { }
        ~ScopeCleanup() {
            if (Connection) {
                InterlockedDecrement(&Binding->Worker->OutstandingConnections);
                MsQuic->ConnectionClose(Connection);
            }
        }
    } Scope(Binding);

    QUIC_CONNECTION_CALLBACK_HANDLER Handler =
        [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
            return ConnectionCallback((HpsBindingContext*)Context, Conn, Event);
        };

    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            Handler,
            Binding,
            &Scope.Connection);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("ConnectionOpen failed, 0x%x\n", Status);
        }
        return;
    }

    InterlockedIncrement64(&Worker->CreatedConnections);

    BOOLEAN Opt = TRUE;
    Status =
        MsQuic->SetParam(
            Scope.Connection,
            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
            sizeof(Opt),
            &Opt);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("SetParam(CONN_SHARE_UDP_BINDING) failed, 0x%x\n", Status);
        }
        return;
    }

    if (QuicAddrGetPort(&Binding->LocalAddr) != 0) {
        Status =
            MsQuic->SetParam(
                Scope.Connection,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                sizeof(QUIC_ADDR),
                &Binding->LocalAddr);
        if (QUIC_FAILED(Status)) {
            if (!Shutdown) {
                WriteOutput("SetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
            }
            return;
        }
    }

    Status =
        MsQuic->SetParam(
            Scope.Connection,
            QUIC_PARAM_CONN_REMOTE_ADDRESS,
            sizeof(QUIC_ADDR),
            &Worker->RemoteAddr);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("SetParam(CONN_REMOTE_ADDRESS) failed, 0x%x\n", Status);
        }
        return;
    }

    Status =
        MsQuic->ConnectionStart(
            Scope.Connection,
            Configuration,
            QUIC_ADDRESS_FAMILY_UNSPEC,
            Worker->Target.get(),
            Port);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("ConnectionStart failed, 0x%x\n", Status);
        }
        return;
    }

    InterlockedIncrement64(&Worker->StartedConnections);
    Scope.Connection = nullptr;
}
