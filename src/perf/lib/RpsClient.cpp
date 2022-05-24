/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf RPS Client Implementation.

--*/

#include "RpsClient.h"

#ifdef QUIC_CLOG
#include "RpsClient.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "RPS Client options:\n"
        "\n"
        "  -target:<####>              The target server to connect to.\n"
        "  -runtime:<####>             The total runtime (in ms). (def:%u)\n"
        "  -encrypt:<0/1>              Enables/disables encryption. (def:1)\n"
        "  -inline:<0/1>               Configured sending requests inline. (def:0)\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -ip:<0/4/6>                 A hint for the resolving the hostname to an IP address. (def:0)\n"
        "  -cibir:<hex_bytes>          A CIBIR well-known idenfitier.\n"
        "  -conns:<####>               The number of connections to use. (def:%u)\n"
        "  -requests:<####>            The number of requests to send at a time. (def:2*conns)\n"
        "  -request:<####>             The length of request payloads. (def:%u)\n"
        "  -response:<####>            The length of request payloads. (def:%u)\n"
        "  -threads:<####>             The number of threads to use. Defaults and capped to number of cores\n"
        "  -affinitize:<0/1>           Affinitizes threads to a core. (def:0)\n"
        "  -sendbuf:<0/1>              Whether to use send buffering. (def:0)\n"
        "\n",
        RPS_DEFAULT_RUN_TIME,
        PERF_DEFAULT_PORT,
        RPS_DEFAULT_CONNECTION_COUNT,
        RPS_DEFAULT_REQUEST_LENGTH,
        RPS_DEFAULT_RESPONSE_LENGTH
        );
}

QUIC_STATUS
RpsClient::Init(
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
    TryGetValue(argc, argv, "encrypt", &UseEncryption);
    TryGetValue(argc, argv, "inline", &SendInline);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "conns", &ConnectionCount);
    RequestCount = 2 * ConnectionCount;
    TryGetValue(argc, argv, "requests", &RequestCount);
    TryGetValue(argc, argv, "request", &RequestLength);
    TryGetValue(argc, argv, "response", &ResponseLength);

    const char* CibirBytes = nullptr;
    if (TryGetValue(argc, argv, "cibir", &CibirBytes)) {
        CibirId[0] = 0; // offset
        if ((CibirIdLength = DecodeHexBuffer(CibirBytes, 6, CibirId+1)) == 0) {
            WriteOutput("Cibir ID must be a hex string <= 6 bytes.\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    uint16_t Ip;
    if (TryGetValue(argc, argv, "ip", &Ip)) {
        switch (Ip) {
        case 4: RemoteFamily = QUIC_ADDRESS_FAMILY_INET; break;
        case 6: RemoteFamily = QUIC_ADDRESS_FAMILY_INET6; break;
        }
    }

    uint32_t Affinitize;
    if (TryGetValue(argc, argv, "affinitize", &Affinitize)) {
        AffinitizeWorkers = Affinitize != 0;
    }

    uint32_t SendBuf;
    if (TryGetValue(argc, argv, "sendbuf", &SendBuf)) {
        MsQuicSettings settings;
        Configuration.GetSettings(settings);
        settings.SetSendBufferingEnabled(SendBuf != 0);
        Configuration.SetSettings(settings);
    }

    WorkerCount = CxPlatProcActiveCount();
    if (WorkerCount > PERF_MAX_THREAD_COUNT) {
        WorkerCount = PERF_MAX_THREAD_COUNT;
    }
    if (WorkerCount >= 60) {
        //
        // If we have enough cores, leave 2 cores for OS overhead
        //
        WorkerCount -= 2;
    }

    uint32_t ThreadCount;
    if (TryGetValue(argc, argv, "threads", &ThreadCount) && ThreadCount < WorkerCount) {
        WorkerCount = ThreadCount;
    }

    RequestBuffer.Buffer = (QUIC_BUFFER*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + sizeof(uint64_t) + RequestLength, QUIC_POOL_PERF);
    if (!RequestBuffer.Buffer) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    RequestBuffer.Buffer->Length = sizeof(uint64_t) + RequestLength;
    RequestBuffer.Buffer->Buffer = (uint8_t*)(RequestBuffer.Buffer + 1);
    *(uint64_t*)(RequestBuffer.Buffer->Buffer) = CxPlatByteSwapUint64(ResponseLength);
    for (uint32_t i = 0; i < RequestLength; ++i) {
        RequestBuffer.Buffer->Buffer[sizeof(uint64_t) + i] = (uint8_t)i;
    }

    MaxLatencyIndex = ((uint64_t)RunTime / 1000) * RPS_MAX_REQUESTS_PER_SECOND;
    if (MaxLatencyIndex > (UINT32_MAX / sizeof(uint32_t))) {
        MaxLatencyIndex = UINT32_MAX / sizeof(uint32_t);
    }

    LatencyValues = UniquePtr<uint32_t[]>(new(std::nothrow) uint32_t[(size_t)MaxLatencyIndex]);
    if (LatencyValues == nullptr) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(LatencyValues.get(), (size_t)(sizeof(uint32_t) * MaxLatencyIndex));

    return QUIC_STATUS_SUCCESS;
}

CXPLAT_THREAD_CALLBACK(RpsWorkerThread, Context)
{
    auto Worker = (RpsWorkerContext*)Context;

    while (Worker->Client->Running) {
        while (Worker->RequestCount != 0) {
            InterlockedDecrement((long*)&Worker->RequestCount);
            auto Connection = Worker->GetConnection();
            if (!Connection) break; // Means we're shutting down
            Connection->SendRequest(Worker->RequestCount != 0);
        }
        CxPlatEventWaitForever(Worker->WakeEvent);
    }

    CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

QUIC_STATUS
RpsClient::Start(
    _In_ CXPLAT_EVENT* StopEvent
    ) {
    CompletionEvent = StopEvent;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    for (uint32_t i = 0; i < WorkerCount; ++i) {
        auto ThreadFlags = AffinitizeWorkers ? CXPLAT_THREAD_FLAG_SET_AFFINITIZE : CXPLAT_THREAD_FLAG_NONE;
        CXPLAT_THREAD_CONFIG ThreadConfig = {
            (uint16_t)ThreadFlags,
            (uint16_t)i,
            "RPS Worker",
            RpsWorkerThread,
            &Workers[i]
        };

        Status = CxPlatThreadCreate(&ThreadConfig, &Workers[i].Thread);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
        Workers[i].ThreadStarted = true;
    }

    QUIC_CONNECTION_CALLBACK_HANDLER Handler =
        [](HQUIC /* Conn */, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
            return ((RpsConnectionContext*)Context)->ConnectionCallback(Event);
        };

    Connections = UniquePtr<RpsConnectionContext[]>(new(std::nothrow) RpsConnectionContext[ConnectionCount]);
    if (!Connections.get()) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    uint32_t ActiveProcCount = CxPlatProcActiveCount();
    if (ActiveProcCount >= 60) {
        //
        // If we have enough cores, leave 2 cores for OS overhead
        //
        ActiveProcCount -= 2;
    }
    for (uint32_t i = 0; i < ConnectionCount; ++i) {
        Status = CxPlatSetCurrentThreadProcessorAffinity((uint16_t)(i % ActiveProcCount));
        if (QUIC_FAILED(Status)) {
            WriteOutput("Setting Thread Group Failed 0x%x\n", Status);
            return Status;
        }

        Connections[i].Client = this;

        Status =
            MsQuic->ConnectionOpen(
                Registration,
                Handler,
                &Connections[i],
                &Connections[i].Handle);
        if (QUIC_FAILED(Status)) {
            WriteOutput("ConnectionOpen failed, 0x%x\n", Status);
            return Status;
        }

        if (WorkerCount == 0) {
            Workers[i % ActiveProcCount].QueueConnection(&Connections[i]);
        } else {
            Workers[i % WorkerCount].QueueConnection(&Connections[i]);
        }

        if (!UseEncryption) {
            BOOLEAN value = TRUE;
            Status =
                MsQuic->SetParam(
                    Connections[i].Handle,
                    QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                    sizeof(value),
                    &value);
            if (QUIC_FAILED(Status)) {
                WriteOutput("MsQuic->SetParam (CONN_DISABLE_1RTT_ENCRYPTION) failed!\n");
                return Status;
            }
        }

        BOOLEAN Opt = TRUE;
        Status =
            MsQuic->SetParam(
                Connections[i],
                QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                sizeof(Opt),
                &Opt);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetParam(CONN_SHARE_UDP_BINDING) failed, 0x%x\n", Status);
            return Status;
        }

        if (CibirIdLength) {
            Status =
                MsQuic->SetParam(
                    Connections[i],
                    QUIC_PARAM_CONN_CIBIR_ID,
                    CibirIdLength+1,
                    CibirId);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetParam(CONN_CIBIR_ID) failed, 0x%x\n", Status);
                return Status;
            }
        }

        if (i >= RPS_MAX_CLIENT_PORT_COUNT) {
            Status =
                MsQuic->SetParam(
                    Connections[i],
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(QUIC_ADDR),
                    &LocalAddresses[i % RPS_MAX_CLIENT_PORT_COUNT]);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
                return Status;
            }
        }

        Status =
            MsQuic->ConnectionStart(
                Connections[i],
                Configuration,
                RemoteFamily,
                Target.get(),
                Port);
        if (QUIC_FAILED(Status)) {
            WriteOutput("ConnectionStart failed, 0x%x\n", Status);
            return Status;
        }

        if (i < RPS_MAX_CLIENT_PORT_COUNT) {
            uint32_t AddrLen = sizeof(QUIC_ADDR);
            Status =
                MsQuic->GetParam(
                    Connections[i],
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    &AddrLen,
                    &LocalAddresses[i]);
            if (QUIC_FAILED(Status)) {
                WriteOutput("GetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
                return Status;
            }
        }
    }

    if (!CxPlatEventWaitWithTimeout(AllConnected.Handle, RPS_ALL_CONNECT_TIMEOUT)) {
        if (ActiveConnections == 0) {
            WriteOutput("Failed to connect to the server\n");
            return QUIC_STATUS_CONNECTION_TIMEOUT;
        }
        WriteOutput("WARNING: Only %u (of %u) connections connected successfully.\n", ActiveConnections, ConnectionCount);
    }

    WriteOutput("All Connected! Waiting for idle.\n");
    CxPlatSleep(RPS_IDLE_WAIT);

    WriteOutput("Start sending request...\n");
    for (uint32_t i = 0; i < RequestCount; ++i) {
        Connections[i % ConnectionCount].Worker->QueueSendRequest();
    }

    uint32_t ThreadToSetAffinityTo = CxPlatProcActiveCount();
    if (ThreadToSetAffinityTo > 2) {
        ThreadToSetAffinityTo -= 2;
        Status =
            CxPlatSetCurrentThreadProcessorAffinity((uint16_t)ThreadToSetAffinityTo);
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout == 0) {
        Timeout = RunTime;
    }

    CxPlatEventWaitWithTimeout(*CompletionEvent, Timeout);

    Running = false;
    for (uint32_t i = 0; i < WorkerCount; ++i) {
        Workers[i].Uninitialize();
    }

    CachedCompletedRequests = CompletedRequests;
    return QUIC_STATUS_SUCCESS;
}

void
RpsClient::GetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Result
    )
{
    Result->TestType = PerfTestType::RpsClient;
    uint64_t DataLength = sizeof(RunTime) + sizeof(CachedCompletedRequests) + (CachedCompletedRequests * sizeof(uint32_t));
    CXPLAT_FRE_ASSERT(DataLength <= UINT32_MAX); // TODO Limit values properly
    Result->ExtraDataLength = (uint32_t)DataLength;
}

QUIC_STATUS
RpsClient::GetExtraData(
    _Out_writes_bytes_(*Length) uint8_t* Data,
    _Inout_ uint32_t* Length
    )
{
    CXPLAT_FRE_ASSERT(*Length >= sizeof(RunTime) + sizeof(CachedCompletedRequests));
    CxPlatCopyMemory(Data, &RunTime, sizeof(RunTime));
    Data += sizeof(RunTime);
    CxPlatCopyMemory(Data, &CachedCompletedRequests, sizeof(CachedCompletedRequests));
    Data += sizeof(CachedCompletedRequests);
    uint64_t BufferLength = *Length - sizeof(RunTime) - sizeof(CachedCompletedRequests);
    if (BufferLength > CachedCompletedRequests * sizeof(uint32_t)) {
        BufferLength = CachedCompletedRequests * sizeof(uint32_t);
        *Length = (uint32_t)(BufferLength + sizeof(RunTime) + sizeof(CachedCompletedRequests));
    }
    CxPlatCopyMemory(Data, LatencyValues.get(), (uint32_t)BufferLength);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsConnectionContext::ConnectionCallback(
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        if ((uint32_t)InterlockedIncrement64((int64_t*)&Client->ActiveConnections) == Client->ConnectionCount) {
            CxPlatEventSet(Client->AllConnected.Handle);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //WriteOutput("Connection died, 0x%x\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        if ((uint32_t)Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor >= Client->WorkerCount) {
            Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor = (uint16_t)(Client->WorkerCount - 1);
        }
        Client->Workers[Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor].UpdateConnection(this);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsConnectionContext::StreamCallback(
    _In_ StreamContext* StrmContext,
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            uint64_t ToPlaceIndex = (uint64_t)InterlockedIncrement64((int64_t*)&Worker->Client->CompletedRequests) - 1;
            uint64_t EndTime = CxPlatTimeUs64();
            uint64_t Delta = CxPlatTimeDiff64(StrmContext->StartTime, EndTime);
            if (ToPlaceIndex < Worker->Client->MaxLatencyIndex) {
                if (Delta > UINT32_MAX) {
                    Delta = UINT32_MAX;
                }
                Worker->Client->LatencyValues[(size_t)ToPlaceIndex] = (uint32_t)Delta;
            }
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        InterlockedIncrement64((int64_t*)&Worker->Client->SendCompletedRequests);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        WriteOutput("Peer stream aborted!\n");
        MsQuic->StreamShutdown(
            StreamHandle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
            0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        Worker->Client->StreamContextAllocator.Free(StrmContext);
        MsQuic->StreamClose(StreamHandle);
        Worker->QueueSendRequest();
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
RpsConnectionContext::SendRequest(bool DelaySend) {

    QUIC_STREAM_CALLBACK_HANDLER Handler =
        [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
            StreamContext* Ctx = reinterpret_cast<StreamContext*>(Context);
            return Ctx->Connection->
                StreamCallback(
                    Ctx,
                    Stream,
                    Event);
        };

    uint64_t StartTime = CxPlatTimeUs64();
    StreamContext* StrmContext = Worker->Client->StreamContextAllocator.Alloc(this, StartTime);

    HQUIC Stream = nullptr;
    if (QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            Handler,
            StrmContext,
            &Stream))) {
        InterlockedIncrement64((int64_t*)&Worker->Client->StartedRequests);
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN;
        if (DelaySend) {
            Flags |= QUIC_SEND_FLAG_DELAY_SEND;
        }
        if (QUIC_FAILED(
            MsQuic->StreamSend(
                Stream,
                Worker->Client->RequestBuffer,
                1,
                Flags,
                nullptr))) {
            MsQuic->StreamClose(Stream);
            Worker->Client->StreamContextAllocator.Free(StrmContext);
        }
    } else {
        Worker->Client->StreamContextAllocator.Free(StrmContext);
    }
}

void
RpsWorkerContext::QueueSendRequest() {
    if (Client->Running) {
        if (ThreadStarted && !Client->SendInline) {
            InterlockedIncrement((long*)&RequestCount);
            CxPlatEventSet(WakeEvent);
        } else {
            GetConnection()->SendRequest(false); // Inline if thread isn't running
        }
    }
}
