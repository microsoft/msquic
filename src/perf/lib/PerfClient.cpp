/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Client Implementation

--*/

#include "PerfClient.h"

#ifdef QUIC_CLOG
#include "PerfClient.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "Client options:\n"
        "\n"
        "  Remote options:"
        "  -target:<####>              The target server to connect to.\n"
        "  -ip:<0/4/6>                 A hint for the resolving the hostname to an IP address. (def:0)\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -cibir:<hex_bytes>          A CIBIR well-known idenfitier.\n"
        "\n"
        "  Local options:"
        "  -bind:<addr>                The local IP address(es)/port(s) to bind to.\n"
        "  -addrs:<####>               The max number of local addresses to use. (def:%u)\n"
        "  -threads:<####>             The max number of worker threads to use.\n"
        "  -affinitize:<0/1>           Affinitizes worker threads to a core. (def:0)\n"
#ifdef QUIC_COMPARTMENT_ID
        "  -comp:<####>                The network compartment ID to run in.\n"
#endif
        "\n"
        "  Config options:"
        "  -encrypt:<0/1>              Disables/enables encryption. (def:1)\n"
        "  -pacing:<0/1>               Disables/enables send pacing. (def:1)\n"
        "  -sendbuf:<0/1>              Disables/enables send buffering. (def:0)\n"
        "  -stats:<0/1>                Print connection stats on connection shutdown. (def:0)\n"
        "  -sstats:<0/1>               Print stream stats on stream shutdown. (def:0)\n"
        "  -latency<0/1>               Print latency stats at end of run. (def:0)\n"
        "\n"
        "  Scenario options:"
        "  -conns:<####>               The number of connections to use. (def:1)\n"
        "  -streams:<####>             The number of streams to send on at a time. (def:0)\n"
        "  -upload:<####>              The length of bytes to send on each stream. (def:0)\n"
        "  -download:<####>            The length of bytes to receive on each stream. (def:0)\n"
        "  -timed:<0/1>                Indicates the upload/download args are times (in ms). (def:0)\n"
        "  -wait:<####>                The time (in ms) to wait for handshakes to complete. (def:0)\n"
        "  -inline:<0/1>               Create new streams on callbacks. (def:0)\n"
        "  -repeatconn:<0/1>           Continue to loop the scenario at the connection level. (def:0)\n"
        "  -repeatstream:<0/1>         Continue to loop the scenario at the stream level. (def:0)\n"
        "  -runtime:<####>             The total runtime (in ms). Only relevant for repeat scenarios. (def:0)\n"
        "\n",
        PERF_DEFAULT_PORT,
        PERF_MAX_CLIENT_PORT_COUNT
        );
}

QUIC_STATUS
PerfClient::Init(
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

    //
    // Remote target/server options
    //

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

    uint16_t Ip;
    if (TryGetValue(argc, argv, "ip", &Ip)) {
        switch (Ip) {
        case 4: TargetFamily = QUIC_ADDRESS_FAMILY_INET; break;
        case 6: TargetFamily = QUIC_ADDRESS_FAMILY_INET6; break;
        }
    }

    TryGetValue(argc, argv, "port", &TargetPort);

    const char* CibirBytes = nullptr;
    if (TryGetValue(argc, argv, "cibir", &CibirBytes)) {
        CibirId[0] = 0; // offset
        if ((CibirIdLength = DecodeHexBuffer(CibirBytes, 6, CibirId+1)) == 0) {
            WriteOutput("Cibir ID must be a hex string <= 6 bytes.\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    //
    // Local address and execution configuration options
    //

    TryGetValue(argc, argv, "addrs", &MaxLocalAddrCount);

    char* LocalAddress = (char*)GetValue(argc, argv, "bind");
    if (LocalAddress != nullptr) {
        SpecificLocalAddresses = true;
        MaxLocalAddrCount = 0;
        while (LocalAddress) {
            char* AddrEnd = strchr(LocalAddress, ',');
            if (AddrEnd) {
                *AddrEnd = '\0';
                AddrEnd++;
            }
            if (!ConvertArgToAddress(LocalAddress, 0, &LocalAddresses[MaxLocalAddrCount++])) {
                WriteOutput("Failed to decode bind IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", LocalAddress);
                PrintHelp();
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            LocalAddress = AddrEnd;
        }
    }

    if (MaxLocalAddrCount > PERF_MAX_CLIENT_PORT_COUNT) {
        WriteOutput("Too many local addresses!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    WorkerCount = CxPlatProcActiveCount();
    TryGetValue(argc, argv, "threads", &WorkerCount);
    TryGetValue(argc, argv, "workers", &WorkerCount);
    TryGetValue(argc, argv, "affinitize", &AffinitizeWorkers);

#ifdef QUIC_COMPARTMENT_ID
    TryGetValue(argc, argv, "comp",  &CompartmentId);
#endif

    //
    // General configuration options
    //

    TryGetValue(argc, argv, "encrypt", &UseEncryption);
    TryGetValue(argc, argv, "pacing", &UsePacing);
    TryGetValue(argc, argv, "sendbuf", &UseSendBuffering);
    TryGetValue(argc, argv, "stats", &PrintStats);
    TryGetValue(argc, argv, "sstats", &PrintStreamStats);
    TryGetValue(argc, argv, "latency", &PrintLatencyStats);

    if (UseSendBuffering || !UsePacing) { // Update settings if non-default
        MsQuicSettings Settings;
        Configuration.GetSettings(Settings);
        if (!UseSendBuffering) {
            Settings.SetSendBufferingEnabled(UseSendBuffering != 0);
        }
        if (!UsePacing) {
            Settings.SetPacingEnabled(UsePacing != 0);
        }
        Configuration.SetSettings(Settings);
    }

    //
    // Scenario options
    //

    TryGetValue(argc, argv, "conns", &ConnectionCount);
    TryGetValue(argc, argv, "requests", &StreamCount);
    TryGetValue(argc, argv, "streams", &StreamCount);
    TryGetValue(argc, argv, "iosize", &IoSize);
    if (IoSize < 256) {
        WriteOutput("'iosize' too small'!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    TryGetValue(argc, argv, "request", &Upload);
    TryGetValue(argc, argv, "upload", &Upload);
    TryGetValue(argc, argv, "response", &Download);
    TryGetValue(argc, argv, "download", &Download);
    TryGetValue(argc, argv, "timed", &Timed);
    TryGetValue(argc, argv, "wait", &HandshakeWaitTime);
    TryGetValue(argc, argv, "inline", &SendInline);
    TryGetValue(argc, argv, "repeatconn", &RepeateConnections);
    TryGetValue(argc, argv, "repeatstream", &RepeatStreams);
    TryGetValue(argc, argv, "runtime", &RunTime);

    //
    // Other state initialization
    //

    RequestBuffer.Init(IoSize, Timed ? UINT64_MAX : Download);
    if (PrintLatencyStats && RunTime) {
        MaxLatencyIndex = ((uint64_t)RunTime / 1000) * PERF_MAX_REQUESTS_PER_SECOND;
        if (MaxLatencyIndex > (UINT32_MAX / sizeof(uint32_t))) {
            MaxLatencyIndex = UINT32_MAX / sizeof(uint32_t);
            WriteOutput("Warning! Limiting request latency tracking to %llu requests\n",
                (unsigned long long)MaxLatencyIndex);
        }

        LatencyValues = UniquePtr<uint32_t[]>(new(std::nothrow) uint32_t[(size_t)MaxLatencyIndex]);
        if (LatencyValues == nullptr) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        CxPlatZeroMemory(LatencyValues.get(), (size_t)(sizeof(uint32_t) * MaxLatencyIndex));
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfClient::Start(
    _In_ CXPLAT_EVENT* StopEvent
    ) {
    CompletionEvent = StopEvent;

    QUIC_STATUS Status = StartWorkers();
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Connections = UniquePtr<PerfClientConnection[]>(new(std::nothrow) PerfClientConnection[ConnectionCount]);
    if (!Connections.get()) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    for (uint32_t i = 0; i < ConnectionCount; ++i) {
        Status = CxPlatSetCurrentThreadProcessorAffinity(Workers[i % WorkerCount].Processor);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Setting Thread Group Failed 0x%x\n", Status);
            return Status;
        }

        Connections[i] = new(std:nothrow) PerfClientConnection(Registration, this);
        if (!Connections[i]->IsValid()) {
            WriteOutput("ConnectionOpen failed, 0x%x\n", Connections[i]->GetInitStatus());
            return Connections[i]->GetInitStatus();
        }

        Workers[i % WorkerCount].QueueConnection(Connections[i]);

        if (!UseEncryption) {
            Status = Connections[i]->SetDisable1RttEncryption();
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetDisable1RttEncryption failed!\n");
                return Status;
            }
        }

        Status = Connections[i]->SetShareUdpBinding();
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetShareUdpBinding failed!\n");
            return Status;
        }

        if (CibirIdLength) {
            Status = Connections[i]->SetCibirId(CibirId, CibirIdLength+1);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetCibirId failed!\n");
                return Status;
            }
        }

        if (SpecificLocalAddresses || i >= MaxLocalAddrCount) {
            Status = Connections[i]->SetLocalAddr(*(QuicAddr*)&LocalAddresses[i % MaxLocalAddrCount]);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetLocalAddr failed!\n");
                return Status;
            }
        }

        Status = Connections[i]->Start(Configuration, TargetFamily, Target.get(), TargetPort);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Start failed, 0x%x\n", Status);
            return Status;
        }

        if (!SpecificLocalAddresses && i < PERF_MAX_CLIENT_PORT_COUNT) {
            Status = Connections[i]->GetLocalAddr(*(QuicAddr*)&LocalAddresses[i]);
            if (QUIC_FAILED(Status)) {
                WriteOutput("GetLocalAddr failed!\n");
                return Status;
            }
        }
    }

    if (!CxPlatEventWaitWithTimeout(AllConnected.Handle, PERF_ALL_CONNECT_TIMEOUT)) {
        if (ActiveConnections == 0) {
            WriteOutput("Failed to connect to the server\n");
            return QUIC_STATUS_CONNECTION_TIMEOUT;
        }
        WriteOutput("WARNING: Only %u (of %u) connections connected successfully.\n", ActiveConnections, ConnectionCount);
    }

    WriteOutput("All Connected! Waiting for idle.\n");
    CxPlatSleep(PERF_IDLE_WAIT);

    WriteOutput("Start sending request...\n");
    for (uint32_t i = 0; i < StreamCount; ++i) {
        Connections[i % ConnectionCount]->Worker->QueueSendRequest();
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
PerfClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout == 0) {
        Timeout = RunTime;
    }

    CxPlatEventWaitWithTimeout(*CompletionEvent, Timeout);
    StopWorkers();

    WriteOutput("Completed %llu requests!\n", (unsigned long long)CompletedRequests);
    CachedCompletedRequests = CompletedRequests;
    return QUIC_STATUS_SUCCESS;
}

void
PerfClient::GetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Result
    )
{
    Result->TestType = PerfTestType::PerfClient;
    uint64_t DataLength = sizeof(RunTime) + sizeof(CachedCompletedRequests) + (CachedCompletedRequests * sizeof(uint32_t));
    CXPLAT_FRE_ASSERT(DataLength <= UINT32_MAX); // TODO Limit values properly
    Result->ExtraDataLength = (uint32_t)DataLength;
}

QUIC_STATUS
PerfClient::GetExtraData(
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
PerfClient::StartWorkers(
    )
{
    auto ThreadFlags = AffinitizeWorkers ? CXPLAT_THREAD_FLAG_SET_AFFINITIZE : CXPLAT_THREAD_FLAG_NONE;
    CXPLAT_THREAD_CONFIG ThreadConfig = {
        (uint16_t)ThreadFlags,
        0,
        "RPS Worker",
        PerfClientWorker::s_WorkerThread,
        nullptr
    };

    CXPLAT_DATAPATH* Datapath = nullptr;
    if (QUIC_FAILED(CxPlatDataPathInitialize(0, nullptr, nullptr, nullptr, &Datapath))) {
        WriteOutput("Failed to initialize datapath for resolution!\n");
        return Status;
    }
    if (QUIC_FAILED(CxPlatDataPathResolveAddress(Datapath, Worker->Target.get(), &Worker->RemoteAddr))) {
        WriteOutput("Failed to resolve remote address!\n");
        break;
    }
    CxPlatDataPathUninitialize(Datapath);

    for (uint32_t i = 0; i < WorkerCount; ++i) {
        while (!CxPlatProcIsActive(ThreadConfig.IdealProcessor)) {
            ++ThreadConfig.IdealProcessor;
        }
        Workers[i].Processor = ThreadConfig.IdealProcessor++;
        ThreadConfig.Context = &Workers[i];

        QUIC_STATUS Status = CxPlatThreadCreate(&ThreadConfig, &Workers[i].Thread);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
        Workers[i].ThreadStarted = true;
    }

    return QUIC_STATUS_SUCCESS;
}

void
PerfClient::StopWorkers(
    )
{
    Running = false;
    for (uint32_t i = 0; i < WorkerCount; ++i) {
        Workers[i].Uninitialize();
    }
}

QUIC_STATUS
PerfClientConnection::ConnectionCallback(
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
        if (Client->PrintStats) {
            QuicPrintConnectionStatistics(MsQuic, Handle);
        }
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
PerfClientConnection::StreamCallback(
    _In_ PerfClientStream* Stream,
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            uint64_t ToPlaceIndex = (uint64_t)InterlockedIncrement64((int64_t*)&Worker->Client->CompletedRequests) - 1;
            uint64_t EndTime = CxPlatTimeUs64();
            uint64_t Delta = CxPlatTimeDiff64(Stream->StartTime, EndTime);
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
        Worker->Client->StreamAllocator.Free(Stream);
        MsQuic->StreamClose(StreamHandle);
        Worker->QueueSendRequest();
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfClientConnection::SendRequest(bool DelaySend) {

    uint64_t StartTime = CxPlatTimeUs64();
    PerfClientStream* Stream = Worker->Client->StreamAllocator.Alloc(this, StartTime);

    HQUIC Handle = nullptr;
    if (QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            PerfClientStream::s_StreamCallback,
            Stream,
            &Handle))) {
        InterlockedIncrement64((int64_t*)&Worker->Client->StartedRequests);
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN;
        if (DelaySend) {
            Flags |= QUIC_SEND_FLAG_DELAY_SEND;
        }
        if (QUIC_FAILED(
            MsQuic->StreamSend(
                Handle,
                Worker->Client->RequestBuffer,
                1,
                Flags,
                nullptr))) {
            MsQuic->StreamClose(Handle);
            Worker->Client->StreamAllocator.Free(Stream);
        }
    } else {
        Worker->Client->StreamAllocator.Free(Stream);
    }
}

void
PerfClientWorker::WorkerThread() {
#ifdef QUIC_COMPARTMENT_ID
    if (Client->CompartmentId != UINT16_MAX) {
        NETIO_STATUS status;
        if (!NETIO_SUCCESS(status = QuicCompartmentIdSetCurrent(Client->CompartmentId))) {
            WriteOutput("Failed to set compartment ID = %d: 0x%x\n", Client->CompartmentId, status);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }
#endif

    while (Client->Running) {
        while (StreamCount != 0) {
            InterlockedDecrement((long*)&StreamCount);
            auto Connection = GetConnection();
            if (!Connection) break; // Means we're shutting down
            Connection->SendRequest(StreamCount != 0);
        }
        WakeEvent.WaitForever();
    }
}

void
PerfClientWorker::QueueSendRequest() {
    if (Client->Running) {
        if (ThreadStarted && !Client->SendInline) {
            InterlockedIncrement((long*)&StreamCount);
            CxPlatEventSet(WakeEvent);
        } else {
            GetConnection()->SendRequest(false); // Inline if thread isn't running
        }
    }
}
