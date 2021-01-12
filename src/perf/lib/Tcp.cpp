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
    Shutdown(false), ProcCount((uint16_t)QuicProcActiveCount()),
    Workers(new TcpWorker[ProcCount]), AcceptHandler(AcceptHandler), ConnectHandler(ConnectHandler)
{
    const QUIC_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        TcpServer::AcceptCallback,
        TcpConnection::ConnectCallback,
        TcpConnection::ReceiveCallback
    };
    if (QUIC_FAILED(
        InitStatus =
            QuicDataPathInitialize(
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
        QuicDataPathUninitialize(Datapath);
    }
    delete [] Workers;
}

void TcpEngine::AddConnection(TcpConnection* Connection, uint16_t PartitionIndex)
{
    QUIC_DBG_ASSERT(PartitionIndex < ProcCount);
    QUIC_DBG_ASSERT(!Connection->Worker);
    Connection->Worker = &Workers[PartitionIndex];
}

TcpWorker::TcpWorker() : Engine(nullptr), Thread(nullptr)
{
    QuicEventInitialize(&WakeEvent, FALSE, FALSE);
    QuicDispatchLockInitialize(&Lock);
    QuicListInitializeHead(&Connections);
}

TcpWorker::~TcpWorker()
{
    if (Engine) {
        QuicThreadDelete(&Thread);
        while (!QuicListIsEmpty(&Connections)) {
            auto Connection =
                QUIC_CONTAINING_RECORD(
                    QuicListRemoveHead(&Connections),
                    TcpConnection,
                    Entry);
            Connection->Entry.Flink = nullptr;
            // TODO - What?!
            Connection->Release();
        }
    }
    QuicDispatchLockUninitialize(&Lock);
    QuicEventUninitialize(WakeEvent);
}

QUIC_STATUS TcpWorker::Init(TcpEngine* _Engine)
{
    Engine = _Engine;
    QUIC_THREAD_CONFIG Config = { 0, 0, "TcpPerfWorker", WorkerThread, this };
    QUIC_STATUS Status =
        QuicThreadCreate(
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
        QuicEventSet(WakeEvent);
        QuicThreadWait(&Thread);
    }
}

QUIC_THREAD_CALLBACK(TcpWorker::WorkerThread, Context)
{
    TcpWorker* This = (TcpWorker*)Context;

    while (!This->Engine->Shutdown) {
        TcpConnection* Connection;
        QuicDispatchLockAcquire(&This->Lock);
        if (QuicListIsEmpty(&This->Connections)) {
            Connection = nullptr;
        } else {
            Connection =
                QUIC_CONTAINING_RECORD(
                    QuicListRemoveHead(&This->Connections),
                    TcpConnection,
                    Entry);
            Connection->Entry.Flink = nullptr;
        }
        QuicDispatchLockRelease(&This->Lock);
        if (Connection) {
            Connection->Process();
            Connection->Release();
        } else {
            QuicEventWaitForever(This->WakeEvent);
        }
    }

    QUIC_THREAD_RETURN(0);
}

void TcpWorker::QueueConnection(TcpConnection* Connection)
{
    QuicDispatchLockAcquire(&Lock);
    if (!Connection->Entry.Flink) {
        Connection->AddRef();
        QuicListInsertTail(&Connections, &Connection->Entry);
        QuicEventSet(WakeEvent);
    }
    QuicDispatchLockRelease(&Lock);
}

TcpServer::TcpServer(TcpEngine* Engine) : Engine(Engine), Listener(nullptr)
{
    InitStatus =
        QuicSocketCreateTcpListener(
            Engine->Datapath,
            nullptr,
            this,
            &Listener);
}

TcpServer::~TcpServer()
{
    if (Listener) {
        QuicSocketDelete(Listener);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_ACCEPT_CALLBACK)
void
TcpServer::AcceptCallback(
    _In_ QUIC_SOCKET* /* ListenerSocket */,
    _In_ void* ListenerContext,
    _In_ QUIC_SOCKET* AcceptSocket,
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
    QuicRefInitialize(&Ref);
    QuicDispatchLockInitialize(&Lock);
    InitStatus =
        QuicSocketCreateTcp(
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

TcpConnection::TcpConnection(TcpEngine* Engine, QUIC_SOCKET* Socket) :
    InitStatus(QUIC_STATUS_SUCCESS), Engine(Engine), Worker(nullptr), Socket(Socket),
    Tls(nullptr), ReceiveData(nullptr), SendData(nullptr), IndicateAccept(true),
    IndicateConnect(false), IndicateDisconnect(false), StartConnection(false)
{
    Entry.Flink = NULL;
    QuicRefInitialize(&Ref);
    QuicDispatchLockInitialize(&Lock);
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::~TcpConnection()
{
    if (Socket) {
        QuicSocketDelete(Socket);
    }
    QUIC_DBG_ASSERT(Entry.Flink == NULL);
    QuicDispatchLockUninitialize(&Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_CONNECT_CALLBACK)
void
TcpConnection::ConnectCallback(
    _In_ QUIC_SOCKET* /* Socket */,
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
_Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
void
TcpConnection::ReceiveCallback(
    _In_ QUIC_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ QUIC_RECV_DATA* RecvDataChain
    )
{
    TcpConnection* This = (TcpConnection*)Context;
    QuicDispatchLockAcquire(&This->Lock);
    QUIC_RECV_DATA** Tail = &This->ReceiveData;
    while (*Tail) {
        Tail = &(*Tail)->Next;
    }
    *Tail = RecvDataChain;
    QuicDispatchLockRelease(&This->Lock);
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
    QuicDispatchLockAcquire(&Lock);
    QUIC_RECV_DATA* RecvDataChain = ReceiveData;
    ReceiveData = nullptr;
    QuicDispatchLockRelease(&Lock);

    // TODO ..

    QuicRecvDataReturn(RecvDataChain);
}

void TcpConnection::ProcessSend()
{
    QuicDispatchLockAcquire(&Lock);
    TcpSendData* SendDataChain = SendData;
    SendData = nullptr;
    QuicDispatchLockRelease(&Lock);

    // TODO ..

    // free SendData?
}
