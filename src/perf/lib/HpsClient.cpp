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

    if (!Session.IsValid()) {
        return Session.GetInitStatus();
    }

    ActiveProcCount = QuicProcActiveCount();
    if (ActiveProcCount >= 60) {
        //
        // If we have enough cores, leave 2 cores for OS overhead
        //
        ActiveProcCount -= 2;
    }
    if (ActiveProcCount > HPS_MAX_WORKER_COUNT) {
        ActiveProcCount = HPS_MAX_WORKER_COUNT;
    }

    const char* target;
    if (!TryGetValue(argc, argv, "target", &target)) {
        WriteOutput("Must specify '-target' argument!\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t Len = strlen(target);
    Target.reset(new(std::nothrow) char[Len + 1]);
    if (!Target.get()) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QuicCopyMemory(Target.get(), target, Len);
    Target[Len] = '\0';

    TryGetValue(argc, argv, "runtime", &RunTime);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "parallel", &Parallel);

    return QUIC_STATUS_SUCCESS;
}

QUIC_THREAD_CALLBACK(HpsWorkerThread, _Context)
{
    auto Context = (HpsWorkerContext*)_Context;

    while (!Context->pThis->Shutdown) {
        if ((uint32_t)Context->OutstandingConnections == Context->pThis->Parallel) {
            QuicEventWaitForever(Context->WakeEvent);
        } else {
            InterlockedIncrement(&Context->OutstandingConnections);
            Context->pThis->StartConnection(Context);
        }
    }

    QUIC_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

QUIC_STATUS
HpsClient::Start(
    _In_ QUIC_EVENT* StopEvent
    ) {
    CompletionEvent = StopEvent;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    for (uint32_t Proc = 0; Proc < ActiveProcCount; ++Proc) {
        Contexts[Proc].pThis = this;
        Contexts[Proc].Processor = (uint16_t)Proc;

        QUIC_THREAD_CONFIG ThreadConfig = {
            QUIC_THREAD_FLAG_SET_IDEAL_PROC | QUIC_THREAD_FLAG_SET_AFFINITIZE,
            (uint16_t)Proc,
            "HPS Worker",
            HpsWorkerThread,
            &Contexts[Proc]
        };

        Status = QuicThreadCreate(&ThreadConfig, &Contexts[Proc].Thread);
        if (QUIC_FAILED(Status)) {
            break;
        }
        Contexts[Proc].ThreadStarted = true;
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
    QuicEventWaitWithTimeout(*CompletionEvent, Timeout);

    Shutdown = true;
    for (uint32_t i = 0; i < ActiveProcCount; ++i) {
        QuicEventSet(Contexts[i].WakeEvent);
    }

    uint32_t HPS = (uint32_t)((CompletedConnections * 1000ull) / (uint64_t)RunTime);
    WriteOutput("Result: %u HPS\n", HPS);
    //WriteOutput("Result: %u HPS (%ull create, %ull start, %ull complete)\n",
    //    HPS, CreatedConnections, StartedConnections, CompletedConnections);
    Session.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
HpsClient::ConnectionCallback(
    _In_ HpsWorkerContext* Context,
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        InterlockedIncrement64((int64_t*)&CompletedConnections);
        MsQuic->ConnectionShutdown(ConnectionHandle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        InterlockedDecrement(&Context->OutstandingConnections);
        if (!Shutdown) {
            QuicEventSet(Context->WakeEvent);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (!Shutdown && !Event->SHUTDOWN_COMPLETE.HandshakeCompleted) {
            InterlockedDecrement(&Context->OutstandingConnections);
            QuicEventSet(Context->WakeEvent);
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
    HpsWorkerContext* Context
    ) {

    struct ScopeCleanup {
        HQUIC Connection {nullptr};
        HpsWorkerContext* Context;
        ScopeCleanup(HpsWorkerContext* Context) : Context(Context) { }
        ~ScopeCleanup() {
            if (Connection) {
                InterlockedDecrement(&Context->OutstandingConnections);
                MsQuic->ConnectionClose(Connection);
            }
        }
    } Scope(Context);

    QUIC_CONNECTION_CALLBACK_HANDLER Handler =
        [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
            return ((HpsWorkerContext*)Context)->pThis->
                ConnectionCallback(
                    (HpsWorkerContext*)Context,
                    Conn,
                    Event);
        };

    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Session,
            Handler,
            Context,
            &Scope.Connection);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("ConnectionOpen failed, 0x%x\n", Status);
        }
        return;
    }

    InterlockedIncrement64((int64_t*)&CreatedConnections);

    uint32_t SecFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    Status =
        MsQuic->SetParam(
            Scope.Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(SecFlags),
            &SecFlags);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("SetParam(CONN_CERT_VALIDATION_FLAGS) failed, 0x%x\n", Status);
        }
        return;
    }

    BOOLEAN Opt = TRUE;
    Status =
        MsQuic->SetParam(
            Scope.Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
            sizeof(Opt),
            &Opt);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("SetParam(CONN_SHARE_UDP_BINDING) failed, 0x%x\n", Status);
        }
        return;
    }

    bool LocalAddrSet = QuicAddrGetPort(&Context->LocalAddrs[Context->NextLocalAddr]) != 0;
    if (LocalAddrSet) {
        Status =
            MsQuic->SetParam(
                Scope.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                sizeof(QUIC_ADDR),
                &Context->LocalAddrs[Context->NextLocalAddr]);
        if (QUIC_FAILED(Status)) {
            if (!Shutdown) {
                WriteOutput("SetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
            }
            return;
        }
    }

    if (Context->RemoteAddrSet) {
        Status =
            MsQuic->SetParam(
                Scope.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_REMOTE_ADDRESS,
                sizeof(QUIC_ADDR),
                &Context->RemoteAddr);
        if (QUIC_FAILED(Status)) {
            if (!Shutdown) {
                WriteOutput("SetParam(CONN_REMOTE_ADDRESS) failed, 0x%x\n", Status);
            }
            return;
        }
    }

    Status =
        MsQuic->ConnectionStart(
            Scope.Connection,
            AF_UNSPEC,
            Target.get(),
            Port);
    if (QUIC_FAILED(Status)) {
        if (!Shutdown) {
            WriteOutput("ConnectionStart failed, 0x%x\n", Status);
        }
        return;
    }

    if (!LocalAddrSet) {
        uint32_t AddrLen = sizeof(QUIC_ADDR);
        Status =
            MsQuic->GetParam(
                Scope.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                &AddrLen,
                &Context->LocalAddrs[Context->NextLocalAddr]);
        if (QUIC_FAILED(Status)) {
            if (!Shutdown) {
                WriteOutput("GetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
            }
        }
    }

    if (!Context->RemoteAddrSet) {
        uint32_t AddrLen = sizeof(QUIC_ADDR);
        Status =
            MsQuic->GetParam(
                Scope.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_REMOTE_ADDRESS,
                &AddrLen,
                &Context->RemoteAddr);
        if (QUIC_FAILED(Status)) {
            if (!Shutdown) {
                WriteOutput("GetParam(CONN_REMOTE_ADDRESS) failed, 0x%x\n", Status);
            }
        }
        Context->RemoteAddrSet = true;
    }

    Context->NextLocalAddr = (Context->NextLocalAddr + 1) % HPS_BINDINGS_PER_WORKER;
    InterlockedIncrement64((int64_t*)&StartedConnections);
    Scope.Connection = nullptr;
}
