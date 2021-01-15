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

#define TLS_BLOCK_SIZE 0x4000

class TcpWorker;
class TcpServer;
class TcpConnection;
struct TcpFrame;

struct TcpSendData {
    TcpSendData* Next;
    uint32_t StreamId : 30;
    uint32_t Open : 1;
    uint32_t Fin : 1;
    uint32_t Length;
    uint8_t* Buffer;
};

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpAcceptCallback)
void
(TcpAcceptCallback)(
    _In_ TcpServer* Server,
    _In_ TcpConnection* Connection
    );
typedef TcpAcceptCallback* TcpAcceptHandler;

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpConnectCallback)
void
(TcpConnectCallback)(
    _In_ TcpConnection* Connection,
    bool IsConnected
    );
typedef TcpConnectCallback* TcpConnectHandler;

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpReceiveCallback)
void
(TcpReceiveCallback)(
    _In_ TcpConnection* Connection,
    uint32_t StreamID,
    bool Open,
    bool Fin,
    uint32_t Length,
    uint8_t* Buffer
    );
typedef TcpReceiveCallback* TcpReceiveHandler;

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpSendCompleteCallback)
void
(TcpSendCompleteCallback)(
    _In_ TcpConnection* Connection,
    TcpSendData* SendDataChain
    );
typedef TcpSendCompleteCallback* TcpSendCompleteHandler;

class TcpEngine {
    friend class TcpWorker;
    bool Initialized;
    bool Shutdown;
    const uint16_t ProcCount;
    TcpWorker* Workers;
public:
    static const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks;
    static const CXPLAT_TLS_CALLBACKS TlsCallbacks;
    CXPLAT_DATAPATH* Datapath;
    const TcpAcceptHandler AcceptHandler;
    const TcpConnectHandler ConnectHandler;
    const TcpReceiveHandler ReceiveHandler;
    const TcpSendCompleteHandler SendCompleteHandler;
public:
    TcpEngine(
        TcpAcceptHandler AcceptHandler,
        TcpConnectHandler ConnectHandler,
        TcpReceiveHandler ReceiveHandler,
        TcpSendCompleteHandler SendCompleteHandler);
    ~TcpEngine();
    bool IsInitialized() const { return Initialized; }
    void AddConnection(TcpConnection* Connection, uint16_t PartitionIndex);
};

class TcpWorker {
    friend class TcpEngine;
    friend class TcpConnection;
    bool Initialized;
    TcpEngine* Engine;
    CXPLAT_THREAD Thread;
    CXPLAT_EVENT WakeEvent;
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_LIST_ENTRY Connections;
    TcpWorker();
    ~TcpWorker();
    bool Initialize(TcpEngine* _Engine);
    void Shutdown();
    static CXPLAT_THREAD_CALLBACK(WorkerThread, Context);
    void QueueConnection(TcpConnection* Connection);
};

class TcpServer {
    friend class TcpEngine;
    bool Initialized;
    TcpEngine* Engine;
    CXPLAT_SEC_CONFIG* SecConfig;
    CXPLAT_SOCKET* Listener;
    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
    void
    QUIC_API
    SecConfigCallback(
        _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
        _In_opt_ void* Context,
        _In_ QUIC_STATUS Status,
        _In_opt_ CXPLAT_SEC_CONFIG* SecurityConfig
        );
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
    void* Context; // App context
    TcpServer(TcpEngine* Engine, const QUIC_CREDENTIAL_CONFIG* CredConfig, void* Context = nullptr);
    ~TcpServer();
    bool IsInitialized() const { return Initialized; }
};

class TcpConnection {
    friend class TcpEngine;
    friend class TcpWorker;
    friend class TcpServer;
    bool IsServer;
    bool Initialized;
    bool StartTls;
    bool IndicateAccept;
    bool IndicateConnect;
    bool IndicateDisconnect;
    CXPLAT_LIST_ENTRY Entry;
    TcpEngine* Engine;
    TcpWorker* Worker;
    CXPLAT_REF_COUNT Ref;
    CXPLAT_DISPATCH_LOCK Lock;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;
    CXPLAT_SOCKET* Socket;
    CXPLAT_SEC_CONFIG* SecConfig;
    CXPLAT_TLS* Tls;
    CXPLAT_TLS_PROCESS_STATE TlsState;
    CXPLAT_RECV_DATA* ReceiveData;
    TcpSendData* SendData;
    CXPLAT_SEND_DATA* BatchedSendData;
    uint8_t BufferedData[TLS_BLOCK_SIZE];
    uint32_t BufferedDataLength;
    TcpConnection(TcpEngine* Engine, CXPLAT_SEC_CONFIG* SecConfig, CXPLAT_SOCKET* Socket);
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
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    void
    TlsProcessCompleteCallback(
        _In_ QUIC_CONNECTION* Connection
        );
    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    TlsReceiveTpCallback(
        _In_ QUIC_CONNECTION* Connection,
        _In_ uint16_t TPLength,
        _In_reads_(TPLength) const uint8_t* TPBuffer
        );
    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    TlsReceiveTicketCallback(
        _In_ QUIC_CONNECTION* Connection,
        _In_ uint32_t TicketLength,
        _In_reads_(TicketLength) const uint8_t* Ticket
        );
    ~TcpConnection();
    void Queue() { Worker->QueueConnection(this); }
    void Process();
    bool InitializeTls();
    bool ProcessTls(const uint8_t* Buffer, uint32_t BufferLength);
    void ProcessReceive();
    bool ProcessReceiveData(const uint8_t* Buffer, uint32_t BufferLength);
    bool ProcessReceiveFrame(TcpFrame* Frame);
    void ProcessSend();
    bool EncryptFrame(TcpFrame* Frame);
    QUIC_BUFFER* NewSendBuffer();
    void FreeSendBuffer(QUIC_BUFFER* SendBuffer);
    void FinalizeSendBuffer(QUIC_BUFFER* SendBuffer);
public:
    void* Context; // App context
    TcpConnection(
        TcpEngine* Engine,
        const QUIC_CREDENTIAL_CONFIG* CredConfig,
        const QUIC_ADDR* RemoteAddress,
        const QUIC_ADDR* LocalAddress = nullptr,
        void* Context = nullptr);
    bool IsInitialized() const { return Initialized; }
    void AddRef() { CxPlatRefIncrement(&Ref); }
    void Release() { if (CxPlatRefDecrement(&Ref)) delete this; }
    void Send(TcpSendData* Data);
};
