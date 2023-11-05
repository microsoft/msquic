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

const char PERF_CLIENT_OPTIONS_TEXT[] =
"\n"
"Usage (client): secnetperf -target:<hostname/ip> [client options]\n"
"\n"
"Client Options:\n"
"\n"
"  Remote options:"
"  -ip:<0/4/6>              A hint for the resolving the hostname to an IP address. (def:0)\n"
"  -port:<####>             The UDP port of the server. (def:%u)\n"
"  -cibir:<hex_bytes>       A CIBIR well-known idenfitier.\n"
"  -incrementtarget:<0/1>   Append unique ID to target hostname for each worker (def:0).\n"
"\n"
"  Local options:"
"  -bind:<addr>             The local IP address(es)/port(s) to bind to.\n"
"  -addrs:<####>            The max number of local addresses to use. (def:%u)\n"
"  -threads:<####>          The max number of worker threads to use.\n"
"  -affinitize:<0/1>        Affinitizes worker threads to a core. (def:0)\n"
#ifdef QUIC_COMPARTMENT_ID
"  -comp:<####>             The network compartment ID to run in.\n"
#endif
"\n"
"  Config options:"
"  -encrypt:<0/1>           Disables/enables encryption. (def:1)\n"
"  -pacing:<0/1>            Disables/enables send pacing. (def:1)\n"
"  -sendbuf:<0/1>           Disables/enables send buffering. (def:0)\n"
"  -stats:<0/1>             Print connection stats on connection shutdown. (def:0)\n"
"  -sstats:<0/1>            Print stream stats on stream shutdown. (def:0)\n"
"  -latency<0/1>            Print latency stats at end of run. (def:0)\n"
"\n"
"  Scenario options:"
"  -conns:<####>            The number of connections to use. (def:1)\n"
"  -streams:<####>          The number of streams to send on at a time. (def:0)\n"
"  -upload:<####>           The length of bytes to send on each stream. (def:0)\n"
"  -download:<####>         The length of bytes to receive on each stream. (def:0)\n"
"  -timed:<0/1>             Indicates the upload/download args are times (in ms). (def:0)\n"
"  -wait:<####>             The time (in ms) to wait for handshakes to complete. (def:0)\n"
"  -inline:<0/1>            Create new streams on callbacks. (def:0)\n"
"  -repeatconn:<0/1>        Continue to loop the scenario at the connection level. (def:0)\n"
"  -repeatstream:<0/1>      Continue to loop the scenario at the stream level. (def:0)\n"
"  -runtime:<####>          The total runtime (in ms). Only relevant for repeat scenarios. (def:0)\n"
"\n";

static void PrintHelp() {
    WriteOutput(
        PERF_CLIENT_OPTIONS_TEXT,
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
    TryGetValue(argc, argv, "incrementtarget", &IncrementTarget);

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

static void AppendIntToString(char* String, uint8_t Value) {
    const char* Hex = "0123456789ABCDEF";
    String[0] = Hex[(Value >> 4) & 0xF];
    String[1] = Hex[Value & 0xF];
    String[2] = '\0';
}

QUIC_STATUS
PerfClient::Start(
    _In_ CXPLAT_EVENT* StopEvent
    ) {
    CompletionEvent = StopEvent;

    //
    // Resolve the remote address to connect to (to optimize the HPS metric).
    //
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath = nullptr;
    if (QUIC_FAILED(Status = CxPlatDataPathInitialize(0, nullptr, nullptr, nullptr, &Datapath))) {
        WriteOutput("Failed to initialize datapath for resolution!\n");
        return Status;
    }
    QUIC_ADDR RemoteAddr;
    Status = CxPlatDataPathResolveAddress(Datapath, Target.get(), &RemoteAddr);
    CxPlatDataPathUninitialize(Datapath);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed to resolve remote address!\n");
        return Status;
    }

    //
    // Configure and start all the workers.
    //
    CXPLAT_THREAD_CONFIG ThreadConfig = {
        (uint16_t)(AffinitizeWorkers ? CXPLAT_THREAD_FLAG_SET_AFFINITIZE : CXPLAT_THREAD_FLAG_NONE),
        0,
        "Perf Worker",
        PerfClientWorker::s_WorkerThread,
        nullptr
    };
    const size_t TargetLen = strlen(Target.get());
    for (uint32_t i = 0; i < WorkerCount; ++i) {
        while (!CxPlatProcIsActive(ThreadConfig.IdealProcessor)) {
            ++ThreadConfig.IdealProcessor;
        }

        auto Worker = &Workers[i];
        Worker->Processor = ThreadConfig.IdealProcessor++;
        ThreadConfig.Context = Worker;
        Worker->RemoteAddr.SockAddr = RemoteAddr;
        Worker->RemoteAddr.SetPort(TargetPort);

        // Build up target hostname.
        Worker->Target.reset(new(std::nothrow) char[TargetLen + 10]);
        CxPlatCopyMemory(Worker->Target.get(), Target.get(), TargetLen);
        if (IncrementTarget) {
            AppendIntToString(Worker->Target.get() + TargetLen, (uint8_t)Worker->Processor);
        } else {
            Worker->Target.get()[TargetLen] = '\0';
        }
        Worker->Target.get()[TargetLen] = '\0';

        Status = CxPlatThreadCreate(&ThreadConfig, &Workers[i].Thread);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Failed to start worker thread on processor %hu!\n", Worker->Processor);
            return Status;
        }
        Workers[i].ThreadStarted = true;
    }

    //
    // Queue the connections on the workers.
    //
    for (uint32_t i = 0; i < ConnectionCount; ++i) {
        Workers[i % WorkerCount].QueueNewConnection();
    }

    if (HandshakeWaitTime) {
        CxPlatSleep(HandshakeWaitTime);
        auto ConnectedConnections = GetConnectedConnections();
        if (ConnectedConnections == 0) {
            WriteOutput("Failed to connect to the server\n");
            return QUIC_STATUS_CONNECTION_TIMEOUT;
        }
        if (ConnectedConnections < ConnectionCount) {
            WriteOutput("WARNING: Only %u (of %u) connections connected successfully.\n", ConnectedConnections, ConnectionCount);
        }
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
    Running = false;
    for (uint32_t i = 0; i < WorkerCount; ++i) {
        Workers[i].Uninitialize();
    }

    auto CompletedRequests = GetCompletedRequests();
    WriteOutput("Completed %llu streams!\n", (unsigned long long)CompletedRequests);
    CachedCompletedRequests = CompletedRequests;
    return QUIC_STATUS_SUCCESS;
}

void
PerfClient::GetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Result
    )
{
    Result->TestType = PerfTestType::Client;
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
PerfClientConnection::ConnectionCallback(
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        InterlockedIncrement64((int64_t*)&Worker.ConnnectedConnectionCount);
        while (ActiveStreamCount < TotalStreamCount) {
            ActiveStreamCount++;
            StartNewStream();
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //WriteOutput("Connection died, 0x%x\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (Client.PrintStats) {
            QuicPrintConnectionStatistics(MsQuic, Handle);
        }
        InterlockedDecrement64((int64_t*)&Worker.ActiveConnectionCount);
        break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        /*if ((uint32_t)Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor >= Client.WorkerCount) {
            Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor = (uint16_t)(Client.WorkerCount - 1);
        }
        Client->Workers[Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor].UpdateConnection(this);*/
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
            uint64_t ToPlaceIndex = (uint64_t)InterlockedIncrement64((int64_t*)&Worker.CompletedRequests) - 1;
            uint64_t EndTime = CxPlatTimeUs64();
            uint64_t Delta = CxPlatTimeDiff64(Stream->StartTime, EndTime);
            if (ToPlaceIndex < Client.MaxLatencyIndex) {
                if (Delta > UINT32_MAX) {
                    Delta = UINT32_MAX;
                }
                Client.LatencyValues[(size_t)ToPlaceIndex] = (uint32_t)Delta;
            }
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        InterlockedIncrement64((int64_t*)&Worker.SendCompletedRequests);
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
        Worker.StreamAllocator.Free(Stream);
        MsQuic->StreamClose(StreamHandle);
        //Worker.QueueSendRequest();
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfClientWorker::WorkerThread() {
#ifdef QUIC_COMPARTMENT_ID
    if (Client->CompartmentId != UINT16_MAX) {
        NETIO_STATUS status;
        if (!NETIO_SUCCESS(status = QuicCompartmentIdSetCurrent(Client->CompartmentId))) {
            WriteOutput("Failed to set compartment ID = %d: 0x%x\n", Client->CompartmentId, status);
            return;
        }
    }
#endif

    while (Client->Running) {
        while (ActiveConnectionCount < TotalConnectionCount) {
            InterlockedIncrement((long*)&ActiveConnectionCount);
            StartNewConnection();
        }
        WakeEvent.WaitForever();
    }
}

void
PerfClientWorker::StartNewConnection() {
    auto Connection = ConnectionAllocator.Alloc(Client->Registration, *Client, *this); // TODO - Fix destructor part
    if (!Connection->IsValid()) {
        WriteOutput("ConnectionOpen failed, 0x%x\n", Connection->GetInitStatus());
        return;
    }

    QUIC_STATUS Status;
    if (!Client->UseEncryption) {
        Status = Connection->SetDisable1RttEncryption();
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetDisable1RttEncryption failed, 0x%x\n", Status);
            Connection->Close();
            return;
        }
    }

    Status = Connection->SetShareUdpBinding();
    if (QUIC_FAILED(Status)) {
        WriteOutput("SetShareUdpBinding failed, 0x%x\n", Status);
        Connection->Close();
        return;
    }

    if (Client->CibirIdLength) {
        Status = Connection->SetCibirId(Client->CibirId, Client->CibirIdLength+1);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetCibirId failed, 0x%x\n", Status);
            Connection->Close();
            return;
        }
    }

    /*if (Client->SpecificLocalAddresses || i >= Client->MaxLocalAddrCount) {
        Status = Connection->SetLocalAddr(*(QuicAddr*)&Client->LocalAddresses[i % Client->MaxLocalAddrCount]);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetLocalAddr failed!\n");
            Connection->Close();
            return;
        }
    }*/

    Status = Connection->Start(Client->Configuration, Client->TargetFamily, Target.get(), RemoteAddr.GetPort());
    if (QUIC_FAILED(Status)) {
        WriteOutput("Start failed, 0x%x\n", Status);
        Connection->Close();
        return;
    }

    /*if (!Client->SpecificLocalAddresses && i < PERF_MAX_CLIENT_PORT_COUNT) {
        Status = Connection->GetLocalAddr(*(QuicAddr*)&Client->LocalAddresses[i]);
        if (QUIC_FAILED(Status)) {
            WriteOutput("GetLocalAddr failed!\n");
            return;
        }
    }*/
}

void
PerfClientConnection::StartNewStream(bool DelaySend) {
    auto Stream = Worker.StreamAllocator.Alloc(this);
    if (QUIC_FAILED(
        MsQuic->StreamOpen(
            Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            PerfClientStream::s_StreamCallback,
            Stream,
            &Stream->Handle))) {
        Worker.StreamAllocator.Free(Stream);
        return;
    }

    InterlockedIncrement64((int64_t*)&Worker.StartedRequests);
    QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN;
    if (DelaySend) {
        Flags |= QUIC_SEND_FLAG_DELAY_SEND;
    }
    MsQuic->StreamSend(
        Stream->Handle,
        Client.RequestBuffer,
        1,
        Flags,
        nullptr);
}

void
PerfClientConnection::SendData(
    _In_ PerfClientStream* Stream
    )
{
    while (!Stream->Complete && Stream->OutstandingBytes < Stream->IdealSendBuffer) {

        uint64_t BytesLeftToSend =
            Client.Timed ? UINT64_MAX : (Client.Upload - Stream->BytesSent);
        uint32_t DataLength = Client.IoSize;
        QUIC_BUFFER* Buffer = Client.RequestBuffer;
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_START;

        if ((uint64_t)DataLength >= BytesLeftToSend) {
            DataLength = (uint32_t)BytesLeftToSend;
            Stream->LastBuffer.Buffer = Buffer->Buffer;
            Stream->LastBuffer.Length = DataLength;
            Buffer = &Stream->LastBuffer;
            Flags = QUIC_SEND_FLAG_FIN;
            Stream->Complete = TRUE;

        } else if (Client.Timed &&
                   CxPlatTimeDiff64(Stream->StartTime, CxPlatTimeUs64()) >= MS_TO_US(Client.Upload)) {
            Flags = QUIC_SEND_FLAG_FIN;
            Stream->Complete = TRUE;
        }

        Stream->BytesSent += DataLength;
        Stream->OutstandingBytes += DataLength;

        MsQuic->StreamSend(Stream->Handle, Buffer, 1, Flags, Buffer);
    }
}
