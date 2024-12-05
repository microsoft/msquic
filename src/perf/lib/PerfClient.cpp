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

const char* TimeUnits[] = { "m", "ms", "us", "s" };
const uint64_t TimeMult[] = { 60 * 1000 * 1000, 1000, 1, 1000 * 1000 };
const char* SizeUnits[] = { "gb", "mb", "kb", "b" };
const uint64_t SizeMult[] = { 1000 * 1000 * 1000, 1000 * 1000, 1000, 1 };
const char* CountUnits[] = { "cpu" };
uint64_t CountMult[] = { 1 };

_Success_(return != false)
template <typename T>
bool
TryGetVariableUnitValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char** names,
    _Out_ T* pValue,
    _Out_opt_ bool* isTimed = nullptr
    )
{
    if (isTimed) *isTimed = false; // Default

    // Search for the first matching name.
    char* value = nullptr;
    while (*names && (value = (char*)GetValue(argc, argv, *names)) == nullptr) {
        names++;
    }
    if (!value) { return false; }

    // Search to see if the value has a time unit specified at the end.
    for (uint32_t i = 0; i < ARRAYSIZE(TimeUnits); ++i) {
        size_t len = strlen(TimeUnits[i]);
        if (len < strlen(value) &&
            _strnicmp(value + strlen(value) - len, TimeUnits[i], len) == 0) {
            if (isTimed) *isTimed = true;
            value[strlen(value) - len] = '\0';
            *pValue = (T)(atoi(value) * TimeMult[i]);
            return true;
        }
    }

    // Search to see if the value has a size unit specified at the end.
    for (uint32_t i = 0; i < ARRAYSIZE(SizeUnits); ++i) {
        size_t len = strlen(SizeUnits[i]);
        if (len < strlen(value) &&
            _strnicmp(value + strlen(value) - len, SizeUnits[i], len) == 0) {
            value[strlen(value) - len] = '\0';
            *pValue = (T)(atoi(value) * SizeMult[i]);
            return true;
        }
    }

    // Search to see if the value has a count unit specified at the end.
    for (uint32_t i = 0; i < ARRAYSIZE(CountUnits); ++i) {
        size_t len = strlen(CountUnits[i]);
        if (len < strlen(value) &&
            _strnicmp(value + strlen(value) - len, CountUnits[i], len) == 0) {
            value[strlen(value) - len] = '\0';
            *pValue = (T)(atoi(value) * CountMult[i]);
            return true;
        }
    }

    // Default to bytes if no unit is specified.
    *pValue = (T)atoi(value);
    return true;
}

_Success_(return != false)
template <typename T>
bool
TryGetVariableUnitValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ T* pValue,
    _Out_opt_ bool* isTimed = nullptr
    )
{
    const char* names[] = { name, nullptr };
    return TryGetVariableUnitValue(argc, argv, names, pValue, isTimed);
}

QUIC_STATUS
PerfClient::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* target
    ) {
    if (!Configuration.IsValid()) {
        return Configuration.GetInitStatus();
    }

    CountMult[0] = CxPlatProcCount();

    //
    // Scenario profile sets new defauls for values below, that may then be
    // further overridden by command line arguments.
    //
    const char* ScenarioStr = GetValue(argc, argv, "scenario");
    if (ScenarioStr != nullptr) {
        if (IsValue(ScenarioStr, "upload")) {
            Upload = S_TO_US(12); // 12 seconds
            Timed = TRUE;
            PrintThroughput = TRUE;
        } else if (IsValue(ScenarioStr, "download")) {
            Download = S_TO_US(12); // 12 seconds
            Timed = TRUE;
            PrintThroughput = TRUE;
        } else if (IsValue(ScenarioStr, "hps")) {
            ConnectionCount = 16 * CxPlatProcCount();
            RunTime = S_TO_US(12); // 12 seconds
            RepeatConnections = TRUE;
            PrintIoRate = TRUE;
        } else if (IsValue(ScenarioStr, "rps-multi")) {
            Upload = 512;
            Download = 4000;
            ConnectionCount = 16 * CxPlatProcCount();
            StreamCount = 100;
            RunTime = S_TO_US(20); // 20 seconds
            RepeatStreams = TRUE;
            PrintLatency = TRUE;
        } else if (IsValue(ScenarioStr, "rps")) {
            Upload = 512;
            Download = 4000;
            StreamCount = 100;
            RunTime = S_TO_US(20); // 20 seconds
            RepeatStreams = TRUE;
            PrintLatency = TRUE;
        } else if (IsValue(ScenarioStr, "latency")) {
            Upload = 512;
            Download = 4000;
            RunTime = S_TO_US(20); // 20 seconds
            RepeatStreams = TRUE;
            PrintLatency = TRUE;
        } else {
            WriteOutput("Failed to parse scenario profile[%s]!\n", ScenarioStr);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    //
    // Remote target/server options
    //

    size_t Len = strlen(target);
    Target.reset(new(std::nothrow) char[Len + 1]);
    CxPlatCopyMemory(Target.get(), target, Len);
    Target[Len] = '\0';

    uint16_t Ip;
    if (TryGetValue(argc, argv, "ip", &Ip) ||
        TryGetValue(argc, argv, "af", &Ip)) {
        switch (Ip) {
        case 4: TargetFamily = QUIC_ADDRESS_FAMILY_INET; break;
        case 6: TargetFamily = QUIC_ADDRESS_FAMILY_INET6; break;
        }
    }

    TryGetValue(argc, argv, "port", &TargetPort);
    TryGetValue(argc, argv, "incrementtarget", &IncrementTarget);
    TryGetValue(argc, argv, "inctarget", &IncrementTarget);

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

    WorkerCount = CxPlatProcCount();
    TryGetVariableUnitValue(argc, argv, "threads", &WorkerCount);
    TryGetVariableUnitValue(argc, argv, "workers", &WorkerCount);

#ifdef QUIC_COMPARTMENT_ID
    TryGetValue(argc, argv, "comp", &CompartmentId);
#endif

    TryGetValue(argc, argv, "share", &SpecificLocalAddresses);

    char* LocalAddress = (char*)GetValue(argc, argv, "bind");
    if (LocalAddress != nullptr) {
        SpecificLocalAddresses = true;
        uint32_t Index = 0;
        while (LocalAddress && Index < WorkerCount) {
            char* AddrEnd = strchr(LocalAddress, ',');
            if (AddrEnd) {
                *AddrEnd = '\0';
                AddrEnd++;
            }
            if (!ConvertArgToAddress(LocalAddress, 0, &Workers[Index++].LocalAddr.SockAddr)) {
                WriteOutput("Failed to decode bind IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", LocalAddress);
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            LocalAddress = AddrEnd;
        }

        for (uint32_t i = Index; i < WorkerCount; ++i) {
            Workers[i].LocalAddr.SockAddr = Workers[(i-Index)%Index].LocalAddr.SockAddr;
        }
    }

    //
    // General configuration options
    //

    TryGetValue(argc, argv, "tcp", &UseTCP);
    TryGetValue(argc, argv, "encrypt", &UseEncryption);
    TryGetValue(argc, argv, "pacing", &UsePacing);
    TryGetValue(argc, argv, "sendbuf", &UseSendBuffering);
    TryGetValue(argc, argv, "ptput", &PrintThroughput);
    TryGetValue(argc, argv, "prate", &PrintIoRate);
    TryGetValue(argc, argv, "pconnection", &PrintConnections);
    TryGetValue(argc, argv, "pconn", &PrintConnections);
    TryGetValue(argc, argv, "pstream", &PrintStreams);
    TryGetValue(argc, argv, "platency", &PrintLatency);
    TryGetValue(argc, argv, "plat", &PrintLatency);

    //
    // Scenario options
    //

    TryGetVariableUnitValue(argc, argv, "conns", &ConnectionCount);
    TryGetVariableUnitValue(argc, argv, "requests", &StreamCount);
    TryGetVariableUnitValue(argc, argv, "streams", &StreamCount);
    TryGetValue(argc, argv, "iosize", &IoSize);
    if (IoSize < 256) {
        WriteOutput("'iosize' too small'!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    TryGetValue(argc, argv, "timed", &Timed);

    bool IsTimeUnit = false;
    const char* UploadVarNames[] = {"upload", "up", "request", nullptr};
    if (TryGetVariableUnitValue(argc, argv, UploadVarNames, &Upload, &IsTimeUnit)) {
        Timed = IsTimeUnit ? 1 : 0;
    }

    const char* DownloadVarNames[] = {"download", "down", "response", nullptr};
    if (TryGetVariableUnitValue(argc, argv, DownloadVarNames, &Download, &IsTimeUnit)) {
        Timed = IsTimeUnit ? 1 : 0;
    }
    const char* RunVarNames[] = {"runtime", "time", "run", nullptr};
    TryGetVariableUnitValue(argc, argv, RunVarNames, &RunTime, &IsTimeUnit);
    //TryGetValue(argc, argv, "inline", &SendInline);
    TryGetValue(argc, argv, "rconn", &RepeatConnections);
    TryGetValue(argc, argv, "rc", &RepeatConnections);
    TryGetValue(argc, argv, "rstream", &RepeatStreams);
    TryGetValue(argc, argv, "rs", &RepeatStreams);

    if ((RepeatConnections || RepeatStreams) && !RunTime) {
        WriteOutput("Must specify a 'runtime' if using a repeat parameter!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (UseTCP) {
        if (!UseEncryption) {
            WriteOutput("TCP mode doesn't support disabling encryption!\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (CibirBytes) {
            WriteOutput("TCP mode doesn't support CIBIR!\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if ((Upload || Download) && !StreamCount) {
        StreamCount = 1; // Just up/down args imply they want a stream
    }

    if (RepeatStreams && !StreamCount) {
        WriteOutput("Must specify a 'streams' if using 'rstream'!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Initialization
    //

    if (UseTCP) {
        Engine =
            UniquePtr<TcpEngine>(
            new(std::nothrow) TcpEngine(
                nullptr,
                PerfClientConnection::TcpConnectCallback,
                PerfClientConnection::TcpReceiveCallback,
                PerfClientConnection::TcpSendCompleteCallback,
                TcpDefaultExecutionProfile)); // Client defaults to using LowLatency profile
    } else {
        if (UseSendBuffering || !UsePacing) { // Update settings if non-default
            MsQuicSettings Settings;
            Configuration.GetSettings(Settings);
            if (UseSendBuffering) {
                Settings.SetSendBufferingEnabled(UseSendBuffering != 0);
            }
            if (!UsePacing) {
                Settings.SetPacingEnabled(UsePacing != 0);
            }
            Configuration.SetSettings(Settings);
        }
    }

    //
    // Resolve the remote address to connect to (to optimize the HPS metric).
    //
    QuicAddrSetFamily(&RemoteAddr, QuicAddrGetFamily(Workers[0].LocalAddr));
    QUIC_STATUS Status = CxPlatDataPathResolveAddress(Datapath, Target.get(), &RemoteAddr);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed to resolve remote address!\n");
        return Status;
    }

    RequestBuffer.Init(IoSize, Timed ? UINT64_MAX : Download);
    if (PrintLatency) {
        if (RunTime) {
            MaxLatencyIndex = ((uint64_t)RunTime / (1000 * 1000)) * PERF_MAX_REQUESTS_PER_SECOND;
            if (MaxLatencyIndex > (UINT32_MAX / sizeof(uint32_t))) {
                MaxLatencyIndex = UINT32_MAX / sizeof(uint32_t);
                WriteOutput("Warning! Limiting request latency tracking to %llu requests\n",
                    (unsigned long long)MaxLatencyIndex);
            }
        } else {
            MaxLatencyIndex = ConnectionCount * StreamCount;
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
    // Configure and start all the workers.
    //
    uint16_t ThreadFlags =
        PerfDefaultAffinitizeThreads ?
            (uint16_t)CXPLAT_THREAD_FLAG_SET_AFFINITIZE :
            (uint16_t)CXPLAT_THREAD_FLAG_SET_IDEAL_PROC;
    if (PerfDefaultHighPriority) {
        ThreadFlags |= CXPLAT_THREAD_FLAG_HIGH_PRIORITY;
    }
    CXPLAT_THREAD_CONFIG ThreadConfig = {
        ThreadFlags,
        0,
        "Perf Worker",
        PerfClientWorker::s_WorkerThread,
        nullptr
    };
    const size_t TargetLen = strlen(Target.get());
    for (uint32_t i = 0; i < WorkerCount; ++i) {
        auto Worker = &Workers[i];
        Worker->Processor = (uint16_t)i;
        Worker->RemoteAddr.SockAddr = RemoteAddr;
        Worker->RemoteAddr.SetPort(TargetPort);

        // Calculate how many connections this worker will be responsible for.
        Worker->ConnectionsQueued = ConnectionCount / WorkerCount;
        if (ConnectionCount % WorkerCount > i) {
            Worker->ConnectionsQueued++;
        }

        // Build up target hostname.
        Worker->Target.reset(new(std::nothrow) char[TargetLen + 10]);
        CxPlatCopyMemory(Worker->Target.get(), Target.get(), TargetLen);
        if (IncrementTarget) {
            AppendIntToString(Worker->Target.get() + TargetLen, (uint8_t)Worker->Processor);
        } else {
            Worker->Target.get()[TargetLen] = '\0';
        }

        // Start the worker thread.
        ThreadConfig.Context = Worker;
        ThreadConfig.IdealProcessor = (uint16_t)i;
        QUIC_STATUS Status = CxPlatThreadCreate(&ThreadConfig, &Workers[i].Thread);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Failed to start worker thread on processor %hu!\n", Worker->Processor);
            return Status;
        }
        Workers[i].ThreadStarted = true;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout == 0 && RunTime != 0) {
        Timeout = RunTime < 1000 ? 1 : (int)US_TO_MS(RunTime);
    }

    if (Timeout) {
        CxPlatEventWaitWithTimeout(*CompletionEvent, Timeout);
    } else {
        CxPlatEventWaitForever(*CompletionEvent);
    }

    Running = false;
    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

    for (uint32_t i = 0; i < WorkerCount; ++i) {
        Workers[i].Uninitialize();
    }

    if (GetConnectedConnections() == 0) {
        WriteOutput("Error: No Successful Connections!\n");
        return QUIC_STATUS_CONNECTION_REFUSED;
    }

    unsigned long long CompletedConnections = GetConnectionsCompleted();
    unsigned long long CompletedStreams = GetStreamsCompleted();

    if (PrintIoRate) {
        if (CompletedConnections) {
            unsigned long long HPS = CompletedConnections * 1000 * 1000 / RunTime;
            WriteOutput("Result: %llu HPS\n", HPS);
        }
        if (CompletedStreams) {
            unsigned long long RPS = CompletedStreams * 1000 * 1000 / RunTime;
            WriteOutput("Result: %llu RPS\n", RPS);
        }
    } else if (!PrintThroughput && !PrintLatency) {
        if (CompletedConnections && CompletedStreams) {
            WriteOutput(
                "Completed %llu connections and %llu streams!\n",
                CompletedConnections, CompletedStreams);
        } else if (CompletedConnections) {
            WriteOutput("Completed %llu connections!\n", CompletedConnections);
        } else if (CompletedStreams) {
            WriteOutput("Completed %llu streams!\n", CompletedStreams);
        } else {
            WriteOutput("No connections or streams completed!\n");
        }
    }

    return QUIC_STATUS_SUCCESS;
}

uint32_t
PerfClient::GetExtraDataLength(
    )
{
    if (!MaxLatencyIndex) {
       return 0; // Not capturing this extra data
    }
    return
        (uint32_t)(
        sizeof(RunTime) +
        sizeof(CurLatencyIndex) +
        (LatencyCount * sizeof(uint32_t)));
}

void
PerfClient::GetExtraData(
    _Out_writes_bytes_(Length) uint8_t* Data,
    _In_ uint32_t Length
    )
{
    CXPLAT_FRE_ASSERT(MaxLatencyIndex); // Shouldn't be called if we're not tracking latency
    CXPLAT_FRE_ASSERT(Length >= sizeof(RunTime) + sizeof(CurLatencyIndex));
    CxPlatCopyMemory(Data, &RunTime, sizeof(RunTime));
    Data += sizeof(RunTime);
    uint64_t Count = (Length - sizeof(RunTime) - sizeof(Count)) / sizeof(uint32_t);
    CxPlatCopyMemory(Data, &Count, sizeof(Count));
    Data += sizeof(CurLatencyIndex);
    CxPlatCopyMemory(Data, LatencyValues.get(), (size_t)(Count * sizeof(uint32_t)));
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
        while (Client->Running && ConnectionsCreated < ConnectionsQueued) {
            StartNewConnection();
        }
        WakeEvent.WaitForever();
    }
}

void
PerfClientWorker::StartNewConnection() {
    InterlockedIncrement64((int64_t*)&ConnectionsCreated);
    InterlockedIncrement64((int64_t*)&ConnectionsActive);
    ConnectionPool.Alloc(*Client, *this)->Initialize();
}

void
PerfClientWorker::OnConnectionComplete() {
    InterlockedIncrement64((int64_t*)&ConnectionsCompleted);
    InterlockedDecrement64((int64_t*)&ConnectionsActive);
    if (Client->RepeatConnections) {
        QueueNewConnection();
    } else {
        if (!ConnectionsActive && ConnectionsCreated == ConnectionsQueued) {
            Client->OnConnectionsComplete();
        }
    }
}

PerfClientConnection::~PerfClientConnection() {
    if (Client.UseTCP) {
        if (TcpConn) { TcpConn->Close(); TcpConn = nullptr; }
    } else {
        if (Handle) { MsQuic->ConnectionClose(Handle); }
    }
}

void
PerfClientConnection::Initialize() {
    if (Client.UseTCP) {
        auto CredConfig = MsQuicCredentialConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
        TcpConn = // TODO: replace new/delete with pool alloc/free
            new (std::nothrow) TcpConnection(Client.Engine.get(), &CredConfig, this);
        if (!TcpConn->IsInitialized()) {
            Worker.ConnectionPool.Free(this);
            return;
        }

        if (!TcpConn->Start(
                Client.TargetFamily,
                Worker.Target.get(),
                Worker.RemoteAddr.GetPort(),
                Worker.LocalAddr.GetFamily() != QUIC_ADDRESS_FAMILY_UNSPEC ? &Worker.LocalAddr.SockAddr : nullptr,
                &Worker.RemoteAddr.SockAddr)) {
            Worker.ConnectionPool.Free(this);
            return;
        }

    } else {
        if (QUIC_FAILED(
            MsQuic->ConnectionOpen(
                Client.Registration,
                PerfClientConnection::s_ConnectionCallback,
                this,
                &Handle))) {
            Worker.ConnectionPool.Free(this);
            return;
        }

        QUIC_STATUS Status;
        BOOLEAN Value;
        if (!Client.UseEncryption) {
            Value = TRUE;
            Status =
                MsQuic->SetParam(
                    Handle,
                    QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                    sizeof(Value),
                    &Value);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetDisable1RttEncryption failed, 0x%x\n", Status);
                Worker.ConnectionPool.Free(this);
                return;
            }
        }

        if (Client.CibirIdLength) {
            Status =
                MsQuic->SetParam(
                    Handle,
                    QUIC_PARAM_CONN_CIBIR_ID,
                    Client.CibirIdLength+1,
                    Client.CibirId);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetCibirId failed, 0x%x\n", Status);
                Worker.ConnectionPool.Free(this);
                return;
            }
        }

        if (Client.SpecificLocalAddresses) {
            Value = TRUE;
            Status =
                MsQuic->SetParam(
                    Handle,
                    QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                    sizeof(Value),
                    &Value);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetShareUdpBinding failed, 0x%x\n", Status);
                Worker.ConnectionPool.Free(this);
                return;
            }

            if (Worker.LocalAddr.GetFamily() != QUIC_ADDRESS_FAMILY_UNSPEC) {
                Status =
                    MsQuic->SetParam(
                        Handle,
                        QUIC_PARAM_CONN_LOCAL_ADDRESS,
                        sizeof(QUIC_ADDR),
                        &Worker.LocalAddr);
                if (QUIC_FAILED(Status)) {
                    WriteOutput("SetLocalAddr failed!\n");
                    Worker.ConnectionPool.Free(this);
                    return;
                }
            }
        }

        Status =
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_REMOTE_ADDRESS,
                sizeof(QUIC_ADDR),
                &Worker.RemoteAddr);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetRemoteAddr failed!\n");
            Worker.ConnectionPool.Free(this);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                Handle,
                Client.Configuration,
                Client.TargetFamily,
                Worker.Target.get(),
                Worker.RemoteAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            WriteOutput("Start failed, 0x%x\n", Status);
            Worker.ConnectionPool.Free(this);
            return;
        }

        if (Client.SpecificLocalAddresses && Worker.LocalAddr.GetFamily() == QUIC_ADDRESS_FAMILY_UNSPEC) {
            uint32_t Size = sizeof(QUIC_ADDR);
            Status = // FYI, this can race with ConnectionStart failing
                MsQuic->GetParam(
                    Handle,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    &Size,
                    &Worker.LocalAddr);
            if (QUIC_FAILED(Status)) {
                WriteOutput("GetLocalAddr failed!\n");
                return;
            }
        }
    }
}

void
PerfClientConnection::OnHandshakeComplete() {
    InterlockedIncrement64((int64_t*)&Worker.ConnectionsConnected);
    if (!Client.StreamCount) {
        Shutdown();
        WorkerConnComplete = true;
        Worker.OnConnectionComplete();
    } else {
        for (uint32_t i = 0; i < Client.StreamCount; ++i) {
            StartNewStream();
        }
    }
}

void
PerfClientConnection::OnShutdownComplete() {
    if (Client.UseTCP) {
        // Clean up leftover TCP streams
        CXPLAT_HASHTABLE_ENUMERATOR Enum;
        StreamTable.EnumBegin(&Enum);
        for (;;) {
            auto Stream = (PerfClientStream*)StreamTable.EnumNext(&Enum);
            if (Stream == NULL) {
                break;
            }
            StreamTable.Remove(&Stream->Entry);
            Worker.StreamPool.Free(Stream);
        }
        StreamTable.EnumEnd(&Enum);
    }

    if (!WorkerConnComplete) {
        Worker.OnConnectionComplete();
    }
    Worker.ConnectionPool.Free(this);
}

void
PerfClientConnection::StartNewStream() {
    StreamsCreated++;
    StreamsActive++;
    auto Stream = Worker.StreamPool.Alloc(*this);
    if (Client.UseTCP) {
        Stream->Entry.Signature = (uint32_t)Worker.StreamsStarted;
        StreamTable.Insert(&Stream->Entry);
    } else {
        if (QUIC_FAILED(
            MsQuic->StreamOpen(
                Handle,
                QUIC_STREAM_OPEN_FLAG_NONE,
                PerfClientStream::s_StreamCallback,
                Stream,
                &Stream->Handle))) {
            Worker.StreamPool.Free(Stream);
            return;
        }
    }

    InterlockedIncrement64((int64_t*)&Worker.StreamsStarted);
    Stream->Send();
}

PerfClientStream::PerfClientStream(_In_ PerfClientConnection& Connection)
    : Connection{Connection} {
    if (Connection.Client.UseSendBuffering) {
        IdealSendBuffer = 1; // Hack to only keep 1 outstanding send at a time
    }
}

PerfClientStream*
PerfClientConnection::GetTcpStream(uint32_t ID) {
    return (PerfClientStream*)StreamTable.Lookup(ID);
}

void
PerfClientConnection::OnStreamShutdown() {
    StreamsActive--;
    if (!Client.Running) {
        if (!StreamsActive) {
            Shutdown();
        }
    } else if (Client.RepeatStreams) {
        while (StreamsActive < Client.StreamCount) {
            StartNewStream();
        }
    } else {
        if (!StreamsActive && StreamsCreated == Client.StreamCount) {
            Shutdown();
        }
    }
}

void
PerfClientConnection::Shutdown() {
    if (Client.UseTCP) {
        if (Client.PrintConnections) {
            TcpPrintConnectionStatistics(TcpConn);
        }
        TcpConn->Close();
        TcpConn = nullptr;
        OnShutdownComplete();
    } else {
        MsQuic->ConnectionShutdown(Handle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

QUIC_STATUS
PerfClientConnection::ConnectionCallback(
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        OnHandshakeComplete();
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (Client.PrintConnections) {
            QuicPrintConnectionStatistics(MsQuic, Handle);
        }
        OnShutdownComplete();
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfClientConnection::TcpConnectCallback(
    _In_ TcpConnection* Connection,
    bool IsConnected
    ) {
    auto This = (PerfClientConnection*)Connection->Context;
    if (IsConnected) {
        This->OnHandshakeComplete();
    } else {
        This->OnShutdownComplete();
    }
}
void
PerfClientConnection::TcpSendCompleteCallback(
    _In_ TcpConnection* Connection,
    _In_ TcpSendData* SendDataChain
    ) {
    auto This = (PerfClientConnection*)Connection->Context;
    PerfClientStream* Stream = nullptr;
    while (SendDataChain) {
        auto Data = SendDataChain;
        SendDataChain = Data->Next;

        if (!Stream || Stream->Entry.Signature != Data->StreamId) {
            Stream = This->GetTcpStream(Data->StreamId);
        }
        if (Stream) {
            Stream->OnSendComplete(Data->Length, FALSE);
        }
        This->Worker.TcpSendDataPool.Free(Data);
    }
}

void
PerfClientConnection::TcpReceiveCallback(
    _In_ TcpConnection* Connection,
    uint32_t StreamID,
    bool /* Open */,
    bool Fin,
    bool Abort,
    uint32_t Length,
    _In_ uint8_t* /* Buffer */
    ) {
    auto This = (PerfClientConnection*)Connection->Context;
    auto Stream = This->GetTcpStream(StreamID);
    if (Stream) {
        if (Abort) {
            Stream->OnReceiveShutdown();
        } else {
            Stream->OnReceive(Length, Fin);
        }
    }
}

QUIC_STATUS
PerfClientStream::QuicStreamCallback(
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        OnReceive(Event->RECEIVE.TotalBufferLength, Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN);
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        OnSendComplete(((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length, Event->SEND_COMPLETE.Canceled);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        MsQuic->StreamShutdown(Handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        OnReceiveShutdown();
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        SendComplete = true;
        MsQuic->StreamShutdown(Handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, 0);
        OnSendShutdown();
        break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        OnSendShutdown();
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        OnSendShutdown();
        OnReceiveShutdown();
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        if (Connection.Client.Upload && !Connection.Client.UseSendBuffering &&
            IdealSendBuffer != Event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            IdealSendBuffer = Event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            Send();
        }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfClientStream::Send() {
    auto& Client = Connection.Client;
    while (!SendComplete && BytesOutstanding < IdealSendBuffer) {

        const uint64_t BytesLeftToSend =
            Client.Timed ?
                UINT64_MAX : // Timed sends forever
                (Client.Upload ? (Client.Upload - BytesSent) : sizeof(uint64_t));
        uint32_t DataLength = Client.IoSize;
        QUIC_BUFFER* Buffer = Client.RequestBuffer;
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_START;

        if ((uint64_t)DataLength >= BytesLeftToSend) {
            DataLength = (uint32_t)BytesLeftToSend;
            LastBuffer.Buffer = Buffer->Buffer;
            LastBuffer.Length = DataLength;
            Buffer = &LastBuffer;
            Flags |= QUIC_SEND_FLAG_FIN;
            SendComplete = true;

        } else if (Client.Timed &&
                   CxPlatTimeDiff64(StartTime, CxPlatTimeUs64()) >= Client.Upload) {
            Flags |= QUIC_SEND_FLAG_FIN;
            SendComplete = true;
        }

        BytesSent += DataLength;
        InterlockedExchangeAdd64((int64_t*)&BytesOutstanding, (int64_t)DataLength);

        if (Client.UseTCP) {
            auto SendData = Connection.Worker.TcpSendDataPool.Alloc();
            SendData->StreamId = (uint32_t)Entry.Signature;
            SendData->Open = BytesSent == DataLength ? TRUE : FALSE;
            SendData->Buffer = Buffer->Buffer;
            SendData->Length = DataLength;
            SendData->Fin = (Flags & QUIC_SEND_FLAG_FIN) ? TRUE : FALSE;
            Connection.TcpConn->Send(SendData);
        } else {
            MsQuic->StreamSend(Handle, Buffer, 1, Flags, Buffer);
        }
    }
}

void
PerfClientStream::OnSendComplete(
    _In_ uint32_t Length,
    _In_ bool Canceled
    ) {
    BytesOutstanding -= Length;
    if (!Canceled) {
        BytesAcked += Length;
        Send();
        if (SendComplete && BytesAcked == BytesSent) {
            OnSendShutdown();
        }
    }
}

void
PerfClientStream::OnSendShutdown(uint64_t Now) {
    if (SendEndTime) return; // Already shutdown
    SendEndTime = Now ? Now : CxPlatTimeUs64();
    if (Connection.Client.PrintStreams) {
        if (Connection.Client.UseTCP) {
            // TODO - Print TCP stream stats
        } else {
            QuicPrintStreamStatistics(MsQuic, Handle);
        }
    }
    if (RecvEndTime) {
        OnShutdown();
    }
}

void
PerfClientStream::OnReceiveShutdown(uint64_t Now) {
    if (RecvEndTime) return; // Already shutdown
    RecvEndTime = Now ? Now : CxPlatTimeUs64();
    if (SendEndTime) {
        OnShutdown();
    }
}

void
PerfClientStream::OnReceive(
    _In_ uint64_t Length,
    _In_ bool Finished
    ) {
    BytesReceived += Length;

    uint64_t Now = 0;
    if (!RecvStartTime) {
        Now = CxPlatTimeUs64();
        RecvStartTime = Now;
    }

    if (Finished) {
        OnReceiveShutdown(Now);
    } else if (Connection.Client.Timed) {
        if (Now == 0) Now = CxPlatTimeUs64();
        if (CxPlatTimeDiff64(RecvStartTime, Now) >= Connection.Client.Download) {
            if (Connection.Client.UseTCP) {
                auto SendData = Connection.Worker.TcpSendDataPool.Alloc();
                SendData->StreamId = (uint32_t)Entry.Signature;
                SendData->Abort = true;
                Connection.TcpConn->Send(SendData);
            } else {
                MsQuic->StreamShutdown(Handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE, 0);
            }
            OnReceiveShutdown(Now);
        }
    }
}

void
PerfClientStream::OnShutdown() {
    auto& Client = Connection.Client;
    auto SendSuccess = SendEndTime != 0;
    if (Client.Upload) {
        const auto TotalBytes = BytesAcked;
        if (TotalBytes < sizeof(uint64_t) || (!Client.Timed && TotalBytes < Client.Upload)) {
            SendSuccess = false;
        }

        if (Client.PrintThroughput && SendSuccess) {
            const auto ElapsedMicroseconds = CXPLAT_MAX(SendEndTime - StartTime, RecvEndTime - StartTime);
            const auto Rate = (uint32_t)((TotalBytes * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));
            WriteOutput(
                "Result: Upload %llu bytes @ %u kbps (%u.%03u ms).\n",
                (unsigned long long)TotalBytes,
                Rate,
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000));
        }
    }

    auto RecvSuccess = RecvStartTime != 0 && RecvEndTime != 0;
    if (Client.Download) {
        const auto TotalBytes = BytesReceived;
        if (TotalBytes == 0 || (!Client.Timed && TotalBytes < Client.Download)) {
            RecvSuccess = false;
        }

        if (Client.PrintThroughput && RecvSuccess) {
            //const auto ElapsedMicroseconds = RecvEndTime - (RecvEndTime == RecvStartTime ? StartTime : RecvStartTime);
            const auto ElapsedMicroseconds = RecvEndTime - StartTime;
            const auto Rate = (uint32_t)((TotalBytes * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));
            WriteOutput(
                "Result: Download %llu bytes @ %u kbps (%u.%03u ms).\n",
                (unsigned long long)TotalBytes,
                Rate,
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000));
        }
    }

    if (SendSuccess && RecvSuccess) {
        if (Client.Running) {
            const auto Index = (uint64_t)InterlockedIncrement64((int64_t*)&Connection.Client.CurLatencyIndex) - 1;
            if (Index < Client.MaxLatencyIndex) {
                const auto Latency = CxPlatTimeDiff64(StartTime, RecvEndTime);
                Client.LatencyValues[(size_t)Index] = Latency > UINT32_MAX ? UINT32_MAX : (uint32_t)Latency;
                InterlockedIncrement64((int64_t*)&Connection.Client.LatencyCount);
            }
        }
        InterlockedIncrement64((int64_t*)&Connection.Worker.StreamsCompleted);
    }

    auto& Conn = Connection;
    if (Connection.Client.UseTCP) {
        Connection.StreamTable.Remove(&Entry);
    } else {
        MsQuic->SetCallbackHandler(Handle, nullptr, nullptr); // Prevent further callbacks
    }
    Connection.Worker.StreamPool.Free(this);
    Conn.OnStreamShutdown();
}
