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

// ############################# HELPERS #############################

struct LoadSecConfigHelper {
    LoadSecConfigHelper() : SecConfig(nullptr) { CxPlatEventInitialize(&CallbackEvent, TRUE, FALSE); }
    ~LoadSecConfigHelper() { CxPlatEventUninitialize(&CallbackEvent, TRUE, FALSE); }
    CXPLAT_SEC_CONFIG* Load(const QUIC_CREDENTIAL_CONFIG* CredConfig) {
        if (QUIC_FAILED(
            CxPlatTlsSecConfigCreate(
                CredConfig,
                &TcpEngine::TlsCallbacks,
                this,
                SecConfigCallback))) {
            return;
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
    TcpConnection::ReceiveCallback
};

const CXPLAT_TLS_CALLBACKS TcpEngine::TlsCallbacks = {
    TcpConnection::TlsProcessCompleteCallback,
    TcpConnection::TlsReceiveTpCallback,
    TcpConnection::TlsReceiveTicketCallback
};

TcpEngine::TcpEngine(TcpAcceptCallback* AcceptHandler, TcpConnectCallback* ConnectHandler) :
    Initialized(false), Shutdown(false), ProcCount((uint16_t)CxPlatProcActiveCount()),
    Workers(new TcpWorker[ProcCount]), Datapath(nullptr),
    AcceptHandler(AcceptHandler), ConnectHandler(ConnectHandler)
{
    if (QUIC_FAILED(
        CxPlatDataPathInitialize(
            0, // TODO
            nullptr,
            &TcpCallbacks,
            &Datapath))) {
        return;
    }
    for (uint16_t i = 0; i < ProcCount; ++i) {
        if (!Workers[i].Initialize(this)) {
            return;
        }
    }
    Initialized = true;
}

TcpEngine::~TcpEngine()
{
    Shutdown = true;
    for (uint16_t i = 0; i < ProcCount; ++i) {
        Workers[i].Shutdown();
    }
    if (Datapath) {
        CxPlatDataPathUninitialize(Datapath);
    }
    delete [] Workers;
}

void TcpEngine::AddConnection(TcpConnection* Connection, uint16_t PartitionIndex)
{
    CXPLAT_DBG_ASSERT(PartitionIndex < ProcCount);
    CXPLAT_DBG_ASSERT(!Connection->Worker);
    Connection->Worker = &Workers[PartitionIndex];
}

// ############################# WORKER #############################

TcpWorker::TcpWorker() : Initialized(false), Engine(nullptr), Thread(nullptr)
{
    CxPlatEventInitialize(&WakeEvent, FALSE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatListInitializeHead(&Connections);
}

TcpWorker::~TcpWorker()
{
    if (Initialized) {
        CxPlatThreadDelete(&Thread);
        while (!CxPlatListIsEmpty(&Connections)) {
            auto Connection =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Connections),
                    TcpConnection,
                    Entry);
            Connection->Entry.Flink = nullptr;
            // TODO - What?!
            Connection->Release();
        }
    }
    CxPlatDispatchLockUninitialize(&Lock);
    CxPlatEventUninitialize(WakeEvent);
}

bool TcpWorker::Initialize(TcpEngine* _Engine)
{
    Engine = _Engine;
    CXPLAT_THREAD_CONFIG Config = { 0, 0, "TcpPerfWorker", WorkerThread, this };
    if (QUIC_FAILED(
        CxPlatThreadCreate(
            &Config,
            &Thread))) {
        return false;
    }
    Initialized = true;
    return true;
}

void TcpWorker::Shutdown()
{
    if (Initialized) {
        CxPlatEventSet(WakeEvent);
        CxPlatThreadWait(&Thread);
    }
}

CXPLAT_THREAD_CALLBACK(TcpWorker::WorkerThread, Context)
{
    TcpWorker* This = (TcpWorker*)Context;

    while (!This->Engine->Shutdown) {
        TcpConnection* Connection;
        CxPlatDispatchLockAcquire(&This->Lock);
        if (CxPlatListIsEmpty(&This->Connections)) {
            Connection = nullptr;
        } else {
            Connection =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&This->Connections),
                    TcpConnection,
                    Entry);
            Connection->Entry.Flink = nullptr;
        }
        CxPlatDispatchLockRelease(&This->Lock);
        if (Connection) {
            Connection->Process();
            Connection->Release();
        } else {
            CxPlatEventWaitForever(This->WakeEvent);
        }
    }

    CXPLAT_THREAD_RETURN(0);
}

void TcpWorker::QueueConnection(TcpConnection* Connection)
{
    CxPlatDispatchLockAcquire(&Lock);
    if (!Connection->Entry.Flink) {
        Connection->AddRef();
        CxPlatListInsertTail(&Connections, &Connection->Entry);
        CxPlatEventSet(WakeEvent);
    }
    CxPlatDispatchLockRelease(&Lock);
}

// ############################# SERVER #############################

TcpServer::TcpServer(TcpEngine* Engine, const QUIC_CREDENTIAL_CONFIG* CredConfig) :
    Initialized(false), Engine(Engine), SecConfig(nullptr), Listener(nullptr)
{
    LoadSecConfigHelper Helper;
    if (!(SecConfig = Helper.Load(CredConfig))) {
        return;
    }
    if (QUIC_FAILED(
        CxPlatSocketCreateTcpListener(
            Engine->Datapath,
            nullptr,
            this,
            &Listener))) {
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

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
void
TcpServer::AcceptCallback(
    _In_ CXPLAT_SOCKET* /* ListenerSocket */,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    )
{
    TcpServer* This = (TcpServer*)ListenerContext;
    *AcceptClientContext = new TcpConnection(This->Engine, This->SecConfig, AcceptSocket);
}

// ############################ CONNECTION ############################

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    const QUIC_CREDENTIAL_CONFIG* CredConfig,
    const QUIC_ADDR* RemoteAddress,
    const QUIC_ADDR* LocalAddress) :
    Server(false), Initialized(false), IndicateAccept(false), IndicateConnect(false),
    IndicateDisconnect(false), StartConnection(false),
    Engine(Engine), Worker(nullptr), Socket(nullptr), SecConfig(nullptr), Tls(nullptr),
    ReceiveData(nullptr), SendData(nullptr)
{
    Entry.Flink = NULL;
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    LoadSecConfigHelper Helper;
    if (!(SecConfig = Helper.Load(CredConfig))) {
        return;
    }
    if (QUIC_FAILED(
        CxPlatSocketCreateTcp(
            Engine->Datapath,
            LocalAddress,
            RemoteAddress,
            this,
            &Socket))) {
        return;
    }
    Initialized = true;
    StartConnection = true;
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    CXPLAT_SEC_CONFIG* SecConfig,
    CXPLAT_SOCKET* Socket) :
    Server(true), Initialized(false), IndicateAccept(false), IndicateConnect(false),
    IndicateDisconnect(false), StartConnection(false),
    Engine(Engine), Worker(nullptr), Socket(Socket), SecConfig(SecConfig), Tls(nullptr),
    ReceiveData(nullptr), SendData(nullptr)
{
    Entry.Flink = NULL;
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    Initialized = true;
    IndicateAccept = true;
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::~TcpConnection()
{
    if (Socket) {
        CxPlatSocketDelete(Socket);
    }
    if (Server && SecConfig) {
        CxPlatTlsSecConfigDelete(SecConfig);
    }
    CXPLAT_DBG_ASSERT(Entry.Flink == NULL);
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
    if (Connected) {
        This->IndicateConnect = true;
    } else {
        This->IndicateDisconnect = true;
    }
    This->Queue();
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
    CxPlatDispatchLockAcquire(&This->Lock);
    CXPLAT_RECV_DATA** Tail = &This->ReceiveData;
    while (*Tail) {
        Tail = &(*Tail)->Next;
    }
    *Tail = RecvDataChain;
    CxPlatDispatchLockRelease(&This->Lock);
    This->Queue();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
TcpConnection::TlsProcessCompleteCallback(
    _In_ QUIC_CONNECTION* Context
    )
{
    TcpConnection* This = (TcpConnection*)(void*)Context;
    // TODO
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
TcpConnection::TlsReceiveTpCallback(
    _In_ QUIC_CONNECTION* Context,
    _In_ uint16_t TPLength,
    _In_reads_(TPLength) const uint8_t* TPBuffer
    )
{
    TcpConnection* This = (TcpConnection*)(void*)Context;
    // TODO
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
TcpConnection::TlsReceiveTicketCallback(
    _In_ QUIC_CONNECTION* Context,
    _In_ uint32_t TicketLength,
    _In_reads_(TicketLength) const uint8_t* Ticket
    )
{
    TcpConnection* This = (TcpConnection*)(void*)Context;
    // TODO
    return TRUE;
}

void TcpConnection::Process()
{
    if (IndicateAccept) {
        IndicateAccept = false;
        Engine->AcceptHandler(this);
    }
    if (IndicateConnect) {
        IndicateConnect = false;
        Engine->ConnectHandler(this, true);
    }
    if (IndicateDisconnect) {
        IndicateDisconnect = false;
        Engine->ConnectHandler(this, false);
    }
    if (StartConnection) {
        StartConnection = false;
    }
    if (ReceiveData) {
        ProcessReceive();
    }
    if (SendData) {
        ProcessSend();
    }
}

void TcpConnection::ProcessReceive()
{
    CxPlatDispatchLockAcquire(&Lock);
    CXPLAT_RECV_DATA* RecvDataChain = ReceiveData;
    ReceiveData = nullptr;
    CxPlatDispatchLockRelease(&Lock);

    // TODO ..

    CxPlatRecvDataReturn(RecvDataChain);
}

void TcpConnection::ProcessSend()
{
    CxPlatDispatchLockAcquire(&Lock);
    TcpSendData* SendDataChain = SendData;
    SendData = nullptr;
    CxPlatDispatchLockRelease(&Lock);

    // TODO ..

    // free SendData?
}
