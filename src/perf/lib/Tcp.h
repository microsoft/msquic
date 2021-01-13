/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    TCP (and TLS) abstraction layer helper.

--*/

#pragma once

#include "PerfHelpers.h"
#include <quic_datapath.h>
#include <quic_tls.h>

class TcpConnection;
class TcpWorker;

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpAcceptCallback)
void
(TcpAcceptCallback)(
    _In_ TcpConnection* Connection
    );

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpAcceptCallback)
void
(TcpConnectCallback)(
    _In_ TcpConnection* Connection,
    bool IsConnected
    );

class TcpEngine {
    friend class TcpWorker;
    QUIC_STATUS InitStatus;
    TcpWorker* Workers;
    bool Shutdown;
public:
    const uint16_t ProcCount;
    CXPLAT_DATAPATH* Datapath;
    const TcpAcceptCallback* AcceptHandler;
    const TcpConnectCallback* ConnectHandler;
    TcpEngine(TcpAcceptCallback* AcceptHandler, TcpConnectCallback* ConnectHandler);
    ~TcpEngine();
    void AddConnection(TcpConnection* Connection, uint16_t PartitionIndex);
};

class TcpWorker {
    friend class TcpEngine;
    friend class TcpConnection;
    TcpEngine* Engine;
    CXPLAT_THREAD Thread;
    CXPLAT_EVENT WakeEvent;
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_LIST_ENTRY Connections;
    TcpWorker();
    ~TcpWorker();
    QUIC_STATUS Init(TcpEngine* _Engine);
    void Shutdown();
    static CXPLAT_THREAD_CALLBACK(WorkerThread, Context);
    void QueueConnection(TcpConnection* Connection);
};

class TcpServer {
    friend class TcpEngine;
    QUIC_STATUS InitStatus;
    TcpEngine* Engine;
    CXPLAT_SOCKET* Listener;
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
    void
    AcceptCallback(
        _In_ CXPLAT_SOCKET* ListenerSocket,
        _In_ void* ListenerContext,
        _In_ CXPLAT_SOCKET* AcceptSocket,
        _Out_ void** AcceptClientContext
        );
public:
    TcpServer(TcpEngine* Engine);
    ~TcpServer();
    QUIC_STATUS GetInitStatus() const { return InitStatus; }
};

struct TcpSendData {
    TcpSendData* Next;
    uint32_t Length;
    uint8_t* Buffer;
};

class TcpConnection {
    friend class TcpEngine;
    friend class TcpWorker;
    CXPLAT_LIST_ENTRY Entry;
    QUIC_STATUS InitStatus;
    TcpEngine* Engine;
    TcpWorker* Worker;
    CXPLAT_REF_COUNT Ref;
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_SOCKET* Socket;
    CXPLAT_TLS* Tls;
    CXPLAT_RECV_DATA* ReceiveData;
    TcpSendData* SendData;
    bool IndicateAccept;
    bool IndicateConnect;
    bool IndicateDisconnect;
    bool StartConnection;
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(CXPLAT_DATAPATH_CONNECT_CALLBACK)
    void
    ConnectCallback(
        _In_ CXPLAT_SOCKET* Socket,
        _In_ void* Context,
        _In_ BOOLEAN Connected
        );
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
    void
    ReceiveCallback(
        _In_ CXPLAT_SOCKET* Socket,
        _In_ void* Context,
        _In_ CXPLAT_RECV_DATA* RecvDataChain
        );
    ~TcpConnection();
    void Queue() { Worker->QueueConnection(this); }
    void Process();
    void ProcessReceive();
    void ProcessSend();
public:
    TcpConnection(TcpEngine* Engine, const QUIC_ADDR* RemoteAddress, const QUIC_ADDR* LocalAddress = nullptr);
    TcpConnection(TcpEngine* Engine, CXPLAT_SOCKET* Socket);
    void AddRef() { CxPlatRefIncrement(&Ref); }
    void Release() { if (CxPlatRefDecrement(&Ref)) delete this; }
};
