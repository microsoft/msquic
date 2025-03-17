/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    TCP (and TLS) abstraction layer helper.

--*/

#include "Tcp.h"

#ifdef QUIC_CLOG
#include "Tcp.cpp.clog.h"
#endif

extern CXPLAT_DATAPATH* Datapath;
extern CXPLAT_WORKER_POOL WorkerPool;

// ############################# HELPERS #############################

#define FRAME_TYPE_CRYPTO   0
#define FRAME_TYPE_STREAM   1

#pragma pack(push)
#pragma pack(1)
struct TcpFrame {
    uint8_t KeyType;
    uint8_t FrameType;
    uint16_t Length; // Of Data
    uint8_t Data[0];
    // uint8_t Tag[CXPLAT_ENCRYPTION_OVERHEAD];
};
struct TcpStreamFrame {
    uint32_t Id : 29;
    uint32_t Open : 1;
    uint32_t Fin : 1;
    uint32_t Abort : 1;
    uint8_t Data[0];
};
#pragma pack(pop)

const uint8_t FixedAlpnBuffer[] = {
    4, 'p', 'e', 'r', 'f'
};

const uint8_t FixedIv[CXPLAT_MAX_IV_LENGTH] = { 0 };

const QUIC_HKDF_LABELS TcpHkdfLabels = { "tcp key", "tcp iv", "tcp hp", "tcp ku" };

struct LoadSecConfigHelper {
    LoadSecConfigHelper() : SecConfig(nullptr) { CxPlatEventInitialize(&CallbackEvent, TRUE, FALSE); }
    ~LoadSecConfigHelper() { CxPlatEventUninitialize(CallbackEvent); }
    CXPLAT_SEC_CONFIG* Load(const QUIC_CREDENTIAL_CONFIG* CredConfig) {
        if (QUIC_FAILED(
            CxPlatTlsSecConfigCreate(
                CredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TcpEngine::TlsCallbacks,
                this,
                SecConfigCallback))) {
            return nullptr;
        }
        CxPlatEventWaitForever(CallbackEvent);
        return SecConfig;
    }
private:
    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
    void
    QUIC_API
    SecConfigCallback(
        _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
        _In_opt_ void* Context,
        _In_ QUIC_STATUS Status,
        _In_opt_ CXPLAT_SEC_CONFIG* SecurityConfig
        )
    {
        LoadSecConfigHelper* This = (LoadSecConfigHelper*)Context;
        if (QUIC_SUCCEEDED(Status)) {
            This->SecConfig = SecurityConfig;
        }
        CxPlatEventSet(This->CallbackEvent);
    }
    CXPLAT_EVENT CallbackEvent;
    CXPLAT_SEC_CONFIG* SecConfig;
};

// ############################# ENGINE #############################

const CXPLAT_TCP_DATAPATH_CALLBACKS TcpEngine::TcpCallbacks = {
    TcpServer::AcceptCallback,
    TcpConnection::ConnectCallback,
    TcpConnection::ReceiveCallback,
    TcpConnection::SendCompleteCallback
};

const CXPLAT_TLS_CALLBACKS TcpEngine::TlsCallbacks = {
    TcpConnection::TlsReceiveTpCallback,
    TcpConnection::TlsReceiveTicketCallback
};

TcpEngine::TcpEngine(
    TcpAcceptHandler AcceptHandler,
    TcpConnectHandler ConnectHandler,
    TcpReceiveHandler ReceiveHandler,
    TcpSendCompleteHandler SendCompleteHandler,
    TCP_EXECUTION_PROFILE TcpExecutionProfile) noexcept :
    ProcCount((uint16_t)CxPlatProcCount()), Workers(new(std::nothrow) TcpWorker[ProcCount]),
    AcceptHandler(AcceptHandler), ConnectHandler(ConnectHandler),
    ReceiveHandler(ReceiveHandler), SendCompleteHandler(SendCompleteHandler),
    TcpExecutionProfile(TcpExecutionProfile)
{
    CxPlatListInitializeHead(&Connections);
    for (uint16_t i = 0; i < ProcCount; ++i) {
        if (!Workers[i].Initialize(this, i)) {
            return;
        }
    }
    Initialized = true;
}

TcpEngine::~TcpEngine() noexcept
{
    // Loop over all connections and shut them down.
    ShuttingDown = true;
    ConnectionLock.Acquire();
    CXPLAT_LIST_ENTRY* Entry = Connections.Flink;
    while (Entry != &Connections) {
        auto Connection = (TcpConnection*)Entry;
        Entry = Entry->Flink;
        Connection->Shutdown = true;
        Connection->TotalSendCompleteOffset = UINT64_MAX;
        Connection->Queue();
    }
    ConnectionLock.Release();
    Rundown.ReleaseAndWait();

    Shutdown = true;
    for (uint16_t i = 0; i < ProcCount; ++i) {
        Workers[i].Shutdown();
    }
    delete [] Workers;
}

bool TcpEngine::AddConnection(TcpConnection* Connection, uint16_t PartitionIndex)
{
    bool Added = false;
    CXPLAT_DBG_ASSERT(PartitionIndex < ProcCount);
    CXPLAT_DBG_ASSERT(!Connection->Worker);
    Connection->PartitionIndex = PartitionIndex;
    Connection->Worker = &Workers[PartitionIndex];
    if (Rundown.Acquire()) {
        Connection->HasRundownRef = true;
        ConnectionLock.Acquire();
        if (!ShuttingDown) {
            CxPlatListInsertTail(&Connections, &Connection->EngineEntry);
            Added = true;
        }
        ConnectionLock.Release();
    }
    return Added;
}

void TcpEngine::RemoveConnection(TcpConnection* Connection)
{
    ConnectionLock.Acquire();
    if (Connection->EngineEntry.Flink) {
        CxPlatListEntryRemove(&Connection->EngineEntry);
    }
    ConnectionLock.Release();
    if (Connection->HasRundownRef) {
        Rundown.Release();
    }
}

// ############################# WORKER #############################

TcpWorker::TcpWorker()
{
    CxPlatEventInitialize(&WakeEvent, FALSE, FALSE);
    CxPlatEventInitialize(&DoneEvent, TRUE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
}

TcpWorker::~TcpWorker()
{
    CXPLAT_FRE_ASSERT(!Connections);
    CXPLAT_FRE_ASSERT(!Initialized); // Shutdown should have been called
    CxPlatDispatchLockUninitialize(&Lock);
    CxPlatEventUninitialize(DoneEvent);
    CxPlatEventUninitialize(WakeEvent);
}

bool TcpWorker::Initialize(TcpEngine* _Engine, uint16_t PartitionIndex)
{
    Engine = _Engine;
    ExecutionContext.Callback = DoWork;
    ExecutionContext.Context = this;
    InterlockedFetchAndSetBoolean(&ExecutionContext.Ready); // TODO - Use WriteBooleanNoFence equivalent instead?
    ExecutionContext.NextTimeUs = UINT64_MAX;

    #ifndef _KERNEL_MODE // Not supported on kernel mode
    if (Engine->TcpExecutionProfile == TCP_EXECUTION_PROFILE_LOW_LATENCY) {
        CxPlatAddExecutionContext(&WorkerPool, &ExecutionContext, PartitionIndex);
        Initialized = true;
        IsExternal = true;
        return true;
    }
    #endif

    uint16_t ThreadFlags = CXPLAT_THREAD_FLAG_SET_IDEAL_PROC;
    if (PerfDefaultHighPriority) {
        ThreadFlags |= CXPLAT_THREAD_FLAG_HIGH_PRIORITY;
    }
    CXPLAT_THREAD_CONFIG Config = { ThreadFlags, PartitionIndex, "TcpPerfWorker", WorkerThread, this };
    if (QUIC_FAILED(
        CxPlatThreadCreate(
            &Config,
            &Thread))) {
        WriteOutput("CxPlatThreadCreate FAILED\n");
        return false;
    }
    Initialized = true;
    return true;
}

void TcpWorker::Shutdown()
{
    if (Initialized) {
        WakeWorkerThread();
        if (IsExternal) {
            CxPlatEventWaitForever(DoneEvent);
            CxPlatThreadDelete(&Thread);
        } else {
            CxPlatThreadWait(&Thread);
        }
        Initialized = false;
    }
}

void TcpWorker::WakeWorkerThread() {
    if (!InterlockedFetchAndSetBoolean(&ExecutionContext.Ready)) {
        if (IsExternal) {
            CxPlatWakeExecutionContext(&ExecutionContext);
        } else {
            CxPlatEventSet(WakeEvent);
        }
    }
}

//
// Runs one iteration of the worker loop. Returns FALSE when it's time to exit.
//
BOOLEAN
TcpWorker::DoWork(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    TcpWorker* This = (TcpWorker*)Context;
    if (This->Engine->Shutdown) {
        CxPlatEventSet(This->DoneEvent);
        return FALSE;
    }

    TcpConnection* Connection = nullptr;
    CxPlatDispatchLockAcquire(&This->Lock);
    if (This->Connections) {
        Connection = This->Connections;
        This->Connections = Connection->Next;
        if (This->ConnectionsTail == &Connection->Next) {
            This->ConnectionsTail = &This->Connections;
        }
        Connection->QueuedOnWorker = false;
        Connection->Next = NULL;
    }
    CxPlatDispatchLockRelease(&This->Lock);

    if (Connection) {
        Connection->Process();
        Connection->Release();
        InterlockedFetchAndSetBoolean(&This->ExecutionContext.Ready); // We just did work, let's keep this thread hot.
        State->NoWorkCount = 0;
    }

    return TRUE;
}

CXPLAT_THREAD_CALLBACK(TcpWorker::WorkerThread, Context)
{
    TcpWorker* This = (TcpWorker*)Context;
    CXPLAT_EXECUTION_STATE DummyState = {
        0, 0, 0, UINT32_MAX, 0, CxPlatCurThreadID()
    };
    while (DoWork(This, &DummyState)) {
        if (!InterlockedFetchAndClearBoolean(&This->ExecutionContext.Ready)) {
            CxPlatEventWaitForever(This->WakeEvent); // Wait for more work
        }
    }
    CXPLAT_THREAD_RETURN(0);
}

bool TcpWorker::QueueConnection(TcpConnection* Connection)
{
    bool Result = true;
    CxPlatDispatchLockAcquire(&Lock);
    //
    // Try to queue the connection if we can add a ref. If we're shutting down
    // the socket, it's possible a receive happens that would fail to add ref.
    //
    if (!Connection->QueuedOnWorker) {
        if (Connection->TryAddRef()) {
            Connection->QueuedOnWorker = true;
            *ConnectionsTail = Connection;
            ConnectionsTail = &Connection->Next;
            WakeWorkerThread();
        } else {
            Result = false;
        }
    }
    CxPlatDispatchLockRelease(&Lock);
    return Result;
}

// ############################# SERVER #############################

TcpServer::TcpServer(TcpEngine* Engine, const QUIC_CREDENTIAL_CONFIG* CredConfig, void* Context) :
    Initialized(false), Engine(Engine), SecConfig(nullptr), Listener(nullptr), Context(Context)
{
    if (!Engine->IsInitialized()) {
        return;
    }
    LoadSecConfigHelper Helper;
    if ((SecConfig = Helper.Load(CredConfig)) == nullptr) {
        return;
    }
    Initialized = true;
}

TcpServer::~TcpServer()
{
    if (Listener) {
        CxPlatSocketDelete(Listener);
    }
    if (SecConfig) {
        CxPlatTlsSecConfigDelete(SecConfig); // TODO - Ref counted instead?
    }
}

bool TcpServer::Start(const QUIC_ADDR* LocalAddress)
{
    if (!Initialized ||
        QUIC_FAILED(
        CxPlatSocketCreateTcpListener(
            Datapath,
            LocalAddress,
            this,
            &Listener))) {
        return false;
    }
    return true;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
QUIC_STATUS
TcpServer::AcceptCallback(
    _In_ CXPLAT_SOCKET* /* ListenerSocket */,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    )
{
    auto This = (TcpServer*)ListenerContext;
    auto Connection = new(std::nothrow) TcpConnection(This->Engine, This->SecConfig, AcceptSocket, This);
    *AcceptClientContext = Connection;
    return QUIC_STATUS_SUCCESS;
}

// ############################ CONNECTION ############################

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    const QUIC_CREDENTIAL_CONFIG* CredConfig,
    void* Context) :
    IsServer(false), Engine(Engine), Context(Context)
{
    CxPlatRefInitialize(&Ref);
    CxPlatEventInitialize(&CloseComplete, TRUE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatZeroMemory(&TlsState, sizeof(TlsState));
    QuicTraceLogVerbose(
        PerfTcpCreateClient,
        "[perf][tcp][%p] Client created",
        this);
    if (!Engine->IsInitialized()) {
        return;
    }
    LoadSecConfigHelper Helper;
    if ((SecConfig = Helper.Load(CredConfig)) == nullptr) {
        WriteOutput("SecConfig load FAILED\n");
        return;
    }
    Initialized = true;
}

bool
TcpConnection::Start(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_or_z_opt_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort,
    const QUIC_ADDR* LocalAddress,
    const QUIC_ADDR* RemoteAddress
    )
{
    if (!Engine->AddConnection(this, (uint16_t)CxPlatProcCurrentNumber())) {
        return false;
    }
    if (LocalAddress) {
        Family = QuicAddrGetFamily(LocalAddress);
    }
    if (RemoteAddress) {
        Route.RemoteAddress = *RemoteAddress;
    } else {
        QuicAddrSetFamily(&Route.RemoteAddress, Family);
        if (QUIC_FAILED(
            CxPlatDataPathResolveAddress(
                Datapath,
                ServerName,
                &Route.RemoteAddress))) {
            WriteOutput("CxPlatDataPathResolveAddress FAILED\n");
            return false;
        }
    }
    QuicAddrSetPort(&Route.RemoteAddress, ServerPort);
    if (QUIC_FAILED(
        CxPlatSocketCreateTcp(
            Datapath,
            LocalAddress,
            &Route.RemoteAddress,
            this,
            &Socket))) {
        return false;
    }
    Queue();
    return true;
}

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    CXPLAT_SEC_CONFIG* SecConfig,
    CXPLAT_SOCKET* Socket,
    void* Context) :
    IsServer(true), Engine(Engine), Socket(Socket), SecConfig(SecConfig), Context(Context)
{
    CxPlatRefInitialize(&Ref);
    CxPlatEventInitialize(&CloseComplete, TRUE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatZeroMemory(&TlsState, sizeof(TlsState));
    QuicTraceLogVerbose(
        PerfTcpCreateServer,
        "[perf][tcp][%p] Server created",
        this);
    Initialized = true;
    IndicateAccept = true;
    CXPLAT_FRE_ASSERT(Engine->AddConnection(this, (uint16_t)CxPlatProcCurrentNumber()));
    Queue();
}

TcpConnection::~TcpConnection()
{
    CXPLAT_DBG_ASSERT(Shutdown || !Initialized);
    QuicTraceLogVerbose(
        PerfTcpDestroyed,
        "[perf][tcp][%p] Destroyed",
        this);
    for (uint32_t i = 0; i < ARRAYSIZE(TlsState.ReadKeys); ++i) {
        QuicPacketKeyFree(TlsState.ReadKeys[i]);
        QuicPacketKeyFree(TlsState.WriteKeys[i]);
    }
    if (Tls) {
        CxPlatTlsUninitialize(Tls);
    }
    if (Socket) {
        CxPlatDispatchLockAcquire(&Lock);
        CXPLAT_RECV_DATA* RecvDataChain = ReceiveData;
        ReceiveData = nullptr;
        CxPlatDispatchLockRelease(&Lock);
        CxPlatRecvDataReturn(RecvDataChain);

        if (BatchedSendData) {
            CxPlatSendDataFree(BatchedSendData);
            BatchedSendData = nullptr;
        }

        CxPlatSocketDelete(Socket);
    }
    if (!IsServer && SecConfig) {
        CxPlatTlsSecConfigDelete(SecConfig);
    }
    CXPLAT_DBG_ASSERT(!QueuedOnWorker);
    Engine->RemoveConnection(this);
    CxPlatEventUninitialize(CloseComplete);
    CxPlatDispatchLockUninitialize(&Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_CONNECT_CALLBACK)
void
TcpConnection::ConnectCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ BOOLEAN Connected
    )
{
    TcpConnection* This = (TcpConnection*)Context;
    QuicTraceLogVerbose(
        PerfTcpConnectCallback,
        "[perf][tcp][%p] Connect callback %hhu",
        This,
        Connected);
    if (Connected) {
        This->StartTls = true;
        This->Queue();
    } else if (!This->Shutdown) {
        This->Shutdown = true;
        This->Queue();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
TcpConnection::ReceiveCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    TcpConnection* This = (TcpConnection*)Context;
    QuicTraceLogVerbose(
        PerfTcpReceiveCallback,
        "[perf][tcp][%p] Receive callback",
        This);
    CxPlatDispatchLockAcquire(&This->Lock);
    if (!This->Shutdown) {
        CXPLAT_RECV_DATA** Tail = &This->ReceiveData;
        while (*Tail) {
            Tail = &(*Tail)->Next;
        }
        *Tail = RecvDataChain;
        RecvDataChain = nullptr;
    }
    CxPlatDispatchLockRelease(&This->Lock);
    if (RecvDataChain) {
        CxPlatRecvDataReturn(RecvDataChain);
    } else if (!This->Queue()) {
        CxPlatDispatchLockAcquire(&This->Lock);
        RecvDataChain = This->ReceiveData;
        This->ReceiveData = nullptr;
        CxPlatDispatchLockRelease(&This->Lock);
        CxPlatRecvDataReturn(RecvDataChain);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK)
void
TcpConnection::SendCompleteCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_ uint32_t ByteCount
    )
{
    TcpConnection* This = (TcpConnection*)Context;
    bool QueueWork = false;
    QuicTraceLogVerbose(
        PerfTcpSendCompleteCallback,
        "[perf][tcp][%p] SendComplete callback, %u",
        This,
        (uint32_t)Status);
    CxPlatDispatchLockAcquire(&This->Lock);
    if (QUIC_FAILED(Status)) {
        if (!This->Shutdown) {
            This->Shutdown = true;
            QueueWork = true;
        }
    } else if (This->TotalSendCompleteOffset != UINT64_MAX) {
        This->TotalSendCompleteOffset += ByteCount;
        This->IndicateSendComplete = true;
        QueueWork = true;
    }
    CxPlatDispatchLockRelease(&This->Lock);
    if (QueueWork) {
        This->Queue();
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
TcpConnection::TlsReceiveTpCallback(
    _In_ QUIC_CONNECTION* /* Context */,
    _In_ uint16_t TPLength,
    _In_reads_(TPLength) const uint8_t* /* TPBuffer */
    )
{
    UNREFERENCED_PARAMETER(TPLength);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
TcpConnection::TlsReceiveTicketCallback(
    _In_ QUIC_CONNECTION* /* Context */,
    _In_ uint32_t TicketLength,
    _In_reads_(TicketLength) const uint8_t* /* Ticket */
    )
{
    UNREFERENCED_PARAMETER(TicketLength);
    return TRUE;
}

void TcpConnection::Process()
{
    if (IndicateAccept) {
        IndicateAccept = false;
        TcpServer* Server = (TcpServer*)Context;
        Context = nullptr;
        QuicTraceLogVerbose(
            PerfTcpAppAccept,
            "[perf][tcp][%p] App Accept",
            this);
        WorkerThreadID = CxPlatCurThreadID();
        Engine->AcceptHandler(Server, this);
        WorkerThreadID = 0;
        StartTls = true;
    }
    if (StartTls && !Shutdown) {
        StartTls = false;
        QuicTraceLogVerbose(
            PerfTcpStartTls,
            "[perf][tcp][%p] Start TLS",
            this);
        if (!InitializeTls()) {
            Shutdown = true;
        }
    }
    if (ReceiveData && !Shutdown) {
        if (!ProcessReceive()) {
            Shutdown = true;
        }
    }
    if (IndicateConnect && !Shutdown) {
        IndicateConnect = false;
        QuicTraceLogVerbose(
            PerfTcpAppConnect,
            "[perf][tcp][%p] App Connect",
            this);
        WorkerThreadID = CxPlatCurThreadID();
        Engine->ConnectHandler(this, true);
        WorkerThreadID = 0;
    }
    if (TlsState.WriteKey >= QUIC_PACKET_KEY_1_RTT && SendData && !Shutdown) {
        if (!ProcessSend()) {
            Shutdown = true;
        }
    }
    if (BatchedSendData && !Shutdown) {
        CxPlatSocketSend(Socket, &Route, BatchedSendData);
        BatchedSendData = nullptr;
    }
    if (IndicateSendComplete) {
        ProcessSendComplete();
    }
    if (Shutdown && !ShutdownComplete) {
        ShutdownComplete = true;
        CxPlatDispatchLockAcquire(&Lock);
        TotalSendCompleteOffset = UINT64_MAX;
        CxPlatDispatchLockRelease(&Lock);
        ProcessSendComplete();
        CXPLAT_DBG_ASSERT(!SentData);
        CXPLAT_DBG_ASSERT(!SendData);
        if (!ClosedByApp) {
            QuicTraceLogVerbose(
                PerfTcpAppDisconnect,
                "[perf][tcp][%p] App Disconnect",
                this);
            WorkerThreadID = CxPlatCurThreadID();
            Engine->ConnectHandler(this, false);
            WorkerThreadID = 0;
        }
    }
    if (ClosedByApp && !Closed) {
        CXPLAT_DBG_ASSERT(Shutdown);
        ShutdownComplete = true;
        Closed = true;
        ProcessSendComplete();
        CXPLAT_DBG_ASSERT(!SentData);
        CXPLAT_DBG_ASSERT(!SendData);
        CxPlatEventSet(CloseComplete);
    }
}

bool TcpConnection::InitializeTls()
{
    const uint32_t LocalTPLength = 2;
    uint8_t* LocalTP = (uint8_t*)CXPLAT_ALLOC_NONPAGED(CxPlatTlsTPHeaderSize + LocalTPLength, QUIC_POOL_TLS_TRANSPARAMS);
    CxPlatZeroMemory(LocalTP, LocalTPLength);

    CXPLAT_TLS_CONFIG Config;
    CxPlatZeroMemory(&Config, sizeof(Config));
    Config.IsServer = IsServer ? TRUE : FALSE;
    Config.Connection = (QUIC_CONNECTION*)(void*)this;
    Config.SecConfig = SecConfig;
    Config.HkdfLabels = &TcpHkdfLabels;
    Config.AlpnBuffer = FixedAlpnBuffer;
    Config.AlpnBufferLength = sizeof(FixedAlpnBuffer);
    Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
    Config.ServerName = "localhost";
    Config.LocalTPBuffer = LocalTP;
    Config.LocalTPLength = CxPlatTlsTPHeaderSize + LocalTPLength;
    if (IsServer) {
        TlsState.NegotiatedAlpn = FixedAlpnBuffer;
    }

    if (QUIC_FAILED(
        CxPlatTlsInitialize(&Config, &TlsState, &Tls))) {
        CXPLAT_FREE(LocalTP, QUIC_POOL_TLS_TRANSPARAMS);
        WriteOutput("CxPlatTlsInitialize FAILED\n");
        return false;
    }

    return IsServer || ProcessTls(NULL, 0);
}

bool TcpConnection::ProcessTls(const uint8_t* Buffer, uint32_t BufferLength)
{
    //printf("ProcessTls %u bytes\n", BufferLength);
    auto BaseOffset = TlsState.BufferTotalLength;
    TlsState.Buffer = TlsOutput;
    TlsState.BufferAllocLength = TLS_BLOCK_SIZE - sizeof(TcpFrame) - CXPLAT_ENCRYPTION_OVERHEAD;
    TlsState.BufferLength = 0;

    auto Results =
        CxPlatTlsProcessData(
            Tls,
            CXPLAT_TLS_CRYPTO_DATA,
            Buffer,
            &BufferLength,
            &TlsState);
    if (Results & CXPLAT_TLS_RESULT_ERROR) {
        WriteOutput("CxPlatTlsProcessData FAILED\n");
        return false;
    }

    //printf("CxPlatTlsProcessData produced %hu bytes (%u, %u)\n", TlsState.BufferLength, TlsState.BufferOffsetHandshake, TlsState.BufferOffset1Rtt);

    CXPLAT_DBG_ASSERT(BaseOffset + TlsState.BufferLength == TlsState.BufferTotalLength);

    if (Results & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE) {
        IndicateConnect = true;
    }

    while (!Shutdown && BaseOffset < TlsState.BufferTotalLength) {
        if (TlsState.BufferOffsetHandshake) {
            if (BaseOffset < TlsState.BufferOffsetHandshake) {
                uint16_t Length = (uint16_t)(TlsState.BufferOffsetHandshake - BaseOffset);
                if (!SendTlsData(TlsState.Buffer, Length, QUIC_PACKET_KEY_INITIAL)) {
                    return false;
                }
                BaseOffset += Length;
                TlsState.Buffer += Length;
                TlsState.BufferLength -= Length;
            } else if (TlsState.BufferOffset1Rtt) {
                if (BaseOffset < TlsState.BufferOffset1Rtt) {
                    uint16_t Length = (uint16_t)(TlsState.BufferOffset1Rtt - BaseOffset);
                    if (!SendTlsData(TlsState.Buffer, Length, QUIC_PACKET_KEY_HANDSHAKE)) {
                        return false;
                    }
                    BaseOffset += Length;
                    TlsState.Buffer += Length;
                    TlsState.BufferLength -= Length;
                } else {
                    return SendTlsData(TlsState.Buffer, TlsState.BufferLength, QUIC_PACKET_KEY_1_RTT);
                }
            } else {
                return SendTlsData(TlsState.Buffer, TlsState.BufferLength, QUIC_PACKET_KEY_HANDSHAKE);
            }
        } else {
            return SendTlsData(TlsState.Buffer, TlsState.BufferLength, QUIC_PACKET_KEY_INITIAL);
        }
    }

    return true;
}

bool TcpConnection::SendTlsData(const uint8_t* Buffer, uint16_t BufferLength, uint8_t KeyType)
{
    auto SendBuffer = NewSendBuffer();
    if (!SendBuffer) {
        //WriteOutput("NewSendBuffer FAILED\n");
        return false;
    }

    auto Frame = (TcpFrame*)SendBuffer->Buffer;
    Frame->FrameType = FRAME_TYPE_CRYPTO;
    Frame->Length = BufferLength;
    Frame->KeyType = KeyType;
    CxPlatCopyMemory(Frame->Data, Buffer, BufferLength);

    if (!EncryptFrame(Frame)) {
        WriteOutput("EncryptFrame FAILED\n");
        FreeSendBuffer(SendBuffer);
        return false;
    }

    SendBuffer->Length = sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
    FinalizeSendBuffer(SendBuffer);

    return true;
}

bool TcpConnection::ProcessReceive()
{
    CxPlatDispatchLockAcquire(&Lock);
    CXPLAT_RECV_DATA* RecvDataChain = ReceiveData;
    ReceiveData = nullptr;
    CxPlatDispatchLockRelease(&Lock);

    bool Result = true;
    auto NextRecvData = RecvDataChain;
    while (NextRecvData) {
        if (!ProcessReceiveData(NextRecvData->Buffer, NextRecvData->BufferLength)) {
            Result = false;
            goto Exit;
        }
        NextRecvData = NextRecvData->Next;
    }

Exit:

    CxPlatRecvDataReturn(RecvDataChain);

    return Result;
}

bool TcpConnection::ProcessReceiveData(const uint8_t* Buffer, uint32_t BufferLength)
{
    if (BufferedDataLength) {
        if (BufferedDataLength < sizeof(TcpFrame)) {
            if (BufferedDataLength + BufferLength < sizeof(TcpFrame)) {
                goto BufferData;
            }
            auto ExtraLength = (uint32_t)(sizeof(TcpFrame) - BufferedDataLength);
            CxPlatCopyMemory(BufferedData+BufferedDataLength, Buffer, ExtraLength);
            BufferedDataLength += ExtraLength;
            Buffer += ExtraLength;
            BufferLength -= ExtraLength;
        }

        auto Frame = (TcpFrame*)BufferedData;
        auto FrameLength = (uint32_t)sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
        auto BytesNeeded = FrameLength - BufferedDataLength;
        if (BufferLength < BytesNeeded) {
            goto BufferData;
        }
        CxPlatCopyMemory(
            BufferedData+BufferedDataLength,
            Buffer,
            BytesNeeded);
        Buffer += BytesNeeded;
        BufferLength -= BytesNeeded;

        if (!ProcessReceiveFrame(Frame)) {
            return false;
        }
        BufferedDataLength = 0;
    }

    while (BufferLength) {
        auto Frame = (TcpFrame*)Buffer;
        if (BufferLength < sizeof(TcpFrame) ||
            BufferLength < sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD) {
            goto BufferData;
        }

        if (!ProcessReceiveFrame(Frame)) {
            return false;
        }

        Buffer += sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
        BufferLength -= sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
    }

    return true;

BufferData:

    CxPlatCopyMemory(BufferedData+BufferedDataLength, Buffer, BufferLength);
    BufferedDataLength += BufferLength;

    return true;
}

bool TcpConnection::ProcessReceiveFrame(TcpFrame* Frame)
{
    if (Frame->KeyType != QUIC_PACKET_KEY_INITIAL) {
        if (Frame->KeyType > TlsState.ReadKey) {
            WriteOutput("Invalid Key Type\n");
            return false; // Shouldn't be possible
        }
        CXPLAT_DBG_ASSERT(TlsState.ReadKeys[Frame->KeyType]->PacketKey);
        if (QUIC_FAILED(
            CxPlatDecrypt(
                TlsState.ReadKeys[Frame->KeyType]->PacketKey,
                FixedIv,
                sizeof(TcpFrame),
                (uint8_t*)Frame,
                Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD,
                Frame->Data))) {
            WriteOutput("CxPlatDecrypt FAILED\n");
            return false;
        }
    }

    switch (Frame->FrameType) {
    case FRAME_TYPE_CRYPTO:
        if (!ProcessTls(Frame->Data, Frame->Length)) {
            return false;
        }
        break;
    case FRAME_TYPE_STREAM: {
        auto StreamFrame = (TcpStreamFrame*)Frame->Data;
        QuicTraceLogVerbose(
            PerfTcpAppReceive,
            "[perf][tcp][%p] App Receive %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu",
            this,
            (uint16_t)(Frame->Length - sizeof(TcpStreamFrame)),
            (uint8_t)StreamFrame->Open,
            (uint8_t)StreamFrame->Fin,
            (uint8_t)StreamFrame->Abort);
        if (!Shutdown) {
            WorkerThreadID = CxPlatCurThreadID();
            Engine->ReceiveHandler(
                this,
                StreamFrame->Id,
                StreamFrame->Open,
                StreamFrame->Fin,
                StreamFrame->Abort,
                Frame->Length - sizeof(TcpStreamFrame),
                StreamFrame->Data);
            WorkerThreadID = 0;
        }
        break;
    }
    default:
        return false;
    }

    return true;
}

bool TcpConnection::ProcessSend()
{
    CxPlatDispatchLockAcquire(&Lock);
    TcpSendData* SendDataChain = SendData;
    SendData = nullptr;
    CxPlatDispatchLockRelease(&Lock);

    TcpSendData** SentDataTail = &SentData;
    while (*SentDataTail != NULL) {
        SentDataTail = &((*SentDataTail)->Next);
    }
    *SentDataTail = SendDataChain;

    auto NextSendData = SendDataChain;
    while (NextSendData) {
        uint32_t Offset = 0;
        do {
            auto SendBuffer = NewSendBuffer();
            if (!SendBuffer) {
                //WriteOutput("NewSendBuffer FAILED\n");
                return false;
            }

            uint32_t StreamLength = TLS_BLOCK_SIZE - sizeof(TcpFrame) - sizeof(TcpStreamFrame) - CXPLAT_ENCRYPTION_OVERHEAD;
            if (NextSendData->Length - Offset < StreamLength) {
                StreamLength = NextSendData->Length - Offset;
            }

            auto Frame = (TcpFrame*)SendBuffer->Buffer;
            Frame->FrameType = FRAME_TYPE_STREAM;
            Frame->Length = (uint16_t)(sizeof(TcpStreamFrame) + StreamLength);
            Frame->KeyType = QUIC_PACKET_KEY_1_RTT;

            auto StreamFrame = (TcpStreamFrame*)Frame->Data;
            StreamFrame->Id = NextSendData->StreamId;
            StreamFrame->Open = Offset == 0 ? NextSendData->Open : FALSE;
            StreamFrame->Fin = (Offset + StreamLength == NextSendData->Length) ? NextSendData->Fin : FALSE;
            StreamFrame->Abort = (Offset + StreamLength == NextSendData->Length) ? NextSendData->Abort : FALSE;
            CxPlatCopyMemory(StreamFrame->Data, NextSendData->Buffer + Offset, StreamLength);
            Offset += StreamLength;

            QuicTraceLogVerbose(
                PerfTcpSendFrame,
                "[perf][tcp][%p] Send frame %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu",
                this,
                (uint16_t)StreamLength,
                (uint8_t)StreamFrame->Open,
                (uint8_t)StreamFrame->Fin,
                (uint8_t)StreamFrame->Abort);

            if (!EncryptFrame(Frame)) {
                WriteOutput("EncryptFrame FAILED\n");
                FreeSendBuffer(SendBuffer);
                return false;
            }

            SendBuffer->Length = sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
            FinalizeSendBuffer(SendBuffer);

        } while (!Shutdown && NextSendData->Length > Offset);

        NextSendData->Offset = TotalSendOffset;
        NextSendData = NextSendData->Next;
    }

    return true;
}

void TcpConnection::ProcessSendComplete()
{
    TcpSendData* CompleteData = nullptr;
    TcpSendData** Tail = &CompleteData;
    CxPlatDispatchLockAcquire(&Lock);
    while (SentData && SentData->Offset <= TotalSendCompleteOffset) {
        TcpSendData* Data = SentData;
        SentData = Data->Next;
        Data->Next = NULL;
        *Tail = Data;
        Tail = &Data->Next;
    }
    if (Shutdown) {
        *Tail = SendData;
        SendData = nullptr;
    }
    IndicateSendComplete = false;
    CxPlatDispatchLockRelease(&Lock);

    while (CompleteData) {
        TcpSendData* Data = CompleteData;
        CompleteData = Data->Next;
        Data->Next = NULL;
        QuicTraceLogVerbose(
            PerfTcpAppSendComplete,
            "[perf][tcp][%p] App Send complete %u bytes",
            this,
            Data->Length);
        WorkerThreadID = CxPlatCurThreadID();
        Engine->SendCompleteHandler(this, Data);
        WorkerThreadID = 0;
        Release();
    }
}

bool TcpConnection::EncryptFrame(TcpFrame* Frame)
{
    return
        Frame->KeyType == QUIC_PACKET_KEY_INITIAL ||
        QUIC_SUCCEEDED(
        CxPlatEncrypt(
            TlsState.WriteKeys[Frame->KeyType]->PacketKey,
            FixedIv,
            sizeof(TcpFrame),
            (uint8_t*)Frame,
            Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD,
            Frame->Data));
}

QUIC_BUFFER* TcpConnection::NewSendBuffer()
{
    if (Shutdown || !Socket) { // Queue (from Engine shutdown) happened before socket creation finished
        return nullptr;
    }
    if (!BatchedSendData) {
        CXPLAT_SEND_CONFIG SendConfig = { &Route, TLS_BLOCK_SIZE, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0 };
        BatchedSendData = CxPlatSendDataAlloc(Socket, &SendConfig);
        if (!BatchedSendData) { return nullptr; }
    }
    return CxPlatSendDataAllocBuffer(BatchedSendData, TLS_BLOCK_SIZE);
}

void TcpConnection::FreeSendBuffer(QUIC_BUFFER* SendBuffer)
{
    CxPlatSendDataFreeBuffer(BatchedSendData, SendBuffer);
}

void TcpConnection::FinalizeSendBuffer(QUIC_BUFFER* SendBuffer)
{
    TotalSendOffset += SendBuffer->Length;
    if (SendBuffer->Length != TLS_BLOCK_SIZE ||
        CxPlatSendDataIsFull(BatchedSendData)) {
        CxPlatSocketSend(Socket, &Route, BatchedSendData);
        BatchedSendData = nullptr;
    }
}

bool TcpConnection::Send(TcpSendData* Data)
{
    QuicTraceLogVerbose(
        PerfTcpAppSend,
        "[perf][tcp][%p] App Send %u bytes, Open=%hhu Fin=%hhu Abort=%hhu",
        this,
        Data->Length,
        (uint8_t)Data->Open,
        (uint8_t)Data->Fin,
        (uint8_t)Data->Abort);

    CxPlatDispatchLockAcquire(&Lock);
    bool QueueSend = !Shutdown;
    if (QueueSend) {
        CXPLAT_FRE_ASSERT(TryAddRef());
        TcpSendData** Tail = &SendData;
        while (*Tail) {
            Tail = &((*Tail)->Next);
        }
        *Tail = Data;
    }
    CxPlatDispatchLockRelease(&Lock);

    if (QueueSend && TlsState.WriteKey >= QUIC_PACKET_KEY_1_RTT) {
        Queue();
    }

    return QueueSend;
}

void TcpConnection::Close()
{
    QuicTraceLogVerbose(
        PerfTcpAppClose,
        "[perf][tcp][%p] App Close",
        this);
    if (!Initialized) {
        ClosedByApp = true;
        Closed = true;
    } else if (WorkerThreadID == CxPlatCurThreadID()) {
        ClosedByApp = true;
        Shutdown = true;
        TotalSendCompleteOffset = UINT64_MAX;
        ProcessSendComplete();
    } else {
        CxPlatDispatchLockAcquire(&Lock);
        ClosedByApp = true;
        Shutdown = true;
        TotalSendCompleteOffset = UINT64_MAX;
        CxPlatDispatchLockRelease(&Lock);
        Queue();
        CxPlatEventWaitForever(CloseComplete);
    }
    Release();
}
