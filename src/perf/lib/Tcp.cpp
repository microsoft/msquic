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

TcpEngine::TcpEngine(TcpAcceptCallback* AcceptHandler, TcpConnectCallback* ConnectHandler) :
    Shutdown(false), ProcCount((uint16_t)CxPlatProcActiveCount()),
    Workers(new TcpWorker[ProcCount]), AcceptHandler(AcceptHandler), ConnectHandler(ConnectHandler)
{
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        TcpServer::AcceptCallback,
        TcpConnection::ConnectCallback,
        TcpConnection::ReceiveCallback
    };
    if (QUIC_FAILED(
        InitStatus =
            CxPlatDataPathInitialize(
                0, // TODO
                nullptr,
                &TcpCallbacks,
                &Datapath))) {
        return;
    }
    for (uint16_t i = 0; i < ProcCount; ++i) {
        if (FAILED(InitStatus = Workers[i].Init(this))) {
            return;
        }
    }
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

TcpWorker::TcpWorker() : Engine(nullptr), Thread(nullptr)
{
    CxPlatEventInitialize(&WakeEvent, FALSE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatListInitializeHead(&Connections);
}

TcpWorker::~TcpWorker()
{
    if (Engine) {
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

QUIC_STATUS TcpWorker::Init(TcpEngine* _Engine)
{
    Engine = _Engine;
    CXPLAT_THREAD_CONFIG Config = { 0, 0, "TcpPerfWorker", WorkerThread, this };
    QUIC_STATUS Status =
        CxPlatThreadCreate(
            &Config,
            &Thread);
    if (QUIC_FAILED(Status)) {
        Engine = nullptr;
        return Status;
    }
    return Status;
}

void TcpWorker::Shutdown()
{
    if (Engine) {
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

TcpServer::TcpServer(TcpEngine* Engine) : Engine(Engine), Listener(nullptr)
{
    InitStatus =
        CxPlatSocketCreateTcpListener(
            Engine->Datapath,
            nullptr,
            this,
            &Listener);
}

TcpServer::~TcpServer()
{
    if (Listener) {
        CxPlatSocketDelete(Listener);
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
    *AcceptClientContext = new TcpConnection(This->Engine, AcceptSocket);
}

TcpConnection::TcpConnection(TcpEngine* Engine, const QUIC_ADDR* RemoteAddress, const QUIC_ADDR* LocalAddress) :
    Engine(Engine), Worker(nullptr), Socket(nullptr), Tls(nullptr),
    ReceiveData(nullptr), SendData(nullptr), IndicateAccept(false), IndicateConnect(false),
    IndicateDisconnect(false), StartConnection(true)
{
    Entry.Flink = NULL;
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    InitStatus =
        CxPlatSocketCreateTcp(
            Engine->Datapath,
            LocalAddress,
            RemoteAddress,
            this,
            &Socket);
    if (QUIC_FAILED(InitStatus)) {
        return;
    }
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::TcpConnection(TcpEngine* Engine, CXPLAT_SOCKET* Socket) :
    InitStatus(QUIC_STATUS_SUCCESS), Engine(Engine), Worker(nullptr), Socket(Socket),
    Tls(nullptr), ReceiveData(nullptr), SendData(nullptr), IndicateAccept(true),
    IndicateConnect(false), IndicateDisconnect(false), StartConnection(false)
{
    Entry.Flink = NULL;
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::~TcpConnection()
{
    if (Socket) {
        CxPlatSocketDelete(Socket);
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
