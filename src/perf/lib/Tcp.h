/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    TCP (and TLS) abstraction layer helper.

--*/

#pragma once

#include "SecNetPerf.h"
#include "quic_tls.h"

#define TLS_BLOCK_SIZE 0x4000

class TcpWorker;
class TcpServer;
class TcpConnection;
struct TcpFrame;

struct TcpSendData {
    TcpSendData* Next;
    uint32_t StreamId : 29;
    uint32_t Open : 1;
    uint32_t Fin : 1;
    uint32_t Abort : 1;
    uint32_t Length;
    uint8_t* Buffer;
    uint64_t Offset; // Used internally only
    TcpSendData() { CxPlatZeroMemory(this, sizeof(TcpSendData)); }
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
    bool Abort,
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
    bool Initialized{false};
    bool ShuttingDown{false};
    bool Shutdown{false};
    const uint16_t ProcCount;
    TcpWorker* Workers;
    CxPlatRundown Rundown;
    CxPlatLockDispatch ConnectionLock;
    CXPLAT_LIST_ENTRY Connections;
public:
    static const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks;
    static const CXPLAT_TLS_CALLBACKS TlsCallbacks;
    const TcpAcceptHandler AcceptHandler;
    const TcpConnectHandler ConnectHandler;
    const TcpReceiveHandler ReceiveHandler;
    const TcpSendCompleteHandler SendCompleteHandler;
public:
    TcpEngine(
        TcpAcceptHandler AcceptHandler,
        TcpConnectHandler ConnectHandler,
        TcpReceiveHandler ReceiveHandler,
        TcpSendCompleteHandler SendCompleteHandler) noexcept;
    ~TcpEngine() noexcept;
    bool IsInitialized() const { return Initialized; }
    bool AddConnection(TcpConnection* Connection, uint16_t PartitionIndex);
    void RemoveConnection(TcpConnection* Connection);
};

class TcpWorker {
    friend class TcpEngine;
    friend class TcpConnection;
    bool Initialized{false};
    TcpEngine* Engine{nullptr};
    CXPLAT_THREAD Thread;
    CXPLAT_EVENT WakeEvent;
    CXPLAT_DISPATCH_LOCK Lock;
    TcpConnection* Connections{nullptr};
    TcpConnection** ConnectionsTail{&Connections};
    TcpWorker();
    ~TcpWorker();
    bool Initialize(TcpEngine* _Engine);
    void Shutdown();
    static CXPLAT_THREAD_CALLBACK(WorkerThread, Context);
    bool QueueConnection(TcpConnection* Connection);
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
    bool Start(const QUIC_ADDR* LocalAddress);
};

class TcpConnection {
    friend class TcpEngine;
    friend class TcpWorker;
    friend class TcpServer;
    CXPLAT_LIST_ENTRY EngineEntry{nullptr,nullptr}; // Must be first
    bool IsServer;
    bool Initialized{false};
    bool Shutdown{false};
    bool ShutdownComplete{false};
    bool ClosedByApp{false};
    bool Closed{false};
    bool QueuedOnWorker{false};
    bool StartTls{false};
    bool IndicateAccept{false};
    bool IndicateConnect{false};
    bool IndicateSendComplete{false};
    bool HasRundownRef{false};
    TcpConnection* Next{nullptr};
    TcpEngine* Engine;
    TcpWorker* Worker{nullptr};
    CXPLAT_THREAD_ID WorkerThreadID{0};
    uint16_t PartitionIndex;
    CXPLAT_EVENT CloseComplete;
    CXPLAT_REF_COUNT Ref;
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_ROUTE Route{0};
    CXPLAT_SOCKET* Socket{nullptr};
    CXPLAT_SEC_CONFIG* SecConfig{nullptr};
    CXPLAT_TLS* Tls{nullptr};
    CXPLAT_TLS_PROCESS_STATE TlsState;
    CXPLAT_RECV_DATA* ReceiveData{nullptr};
    TcpSendData* SendData{nullptr};
    TcpSendData* SentData{nullptr};
    uint64_t TotalSendOffset{0};
    uint64_t TotalSendCompleteOffset{0};
    CXPLAT_SEND_DATA* BatchedSendData{nullptr};
    uint8_t TlsOutput[TLS_BLOCK_SIZE];
    uint8_t BufferedData[TLS_BLOCK_SIZE];
    uint32_t BufferedDataLength{0};
    TcpConnection(TcpEngine* Engine, CXPLAT_SEC_CONFIG* SecConfig, CXPLAT_SOCKET* Socket, void* Context);
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
    _Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK)
    void
    SendCompleteCallback(
        _In_ CXPLAT_SOCKET* Socket,
        _In_ void* Context,
        _In_ QUIC_STATUS Status,
        _In_ uint32_t ByteCount
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
    bool Queue() { return Worker->QueueConnection(this); }
    void Process();
    bool InitializeTls();
    bool ProcessTls(const uint8_t* Buffer, uint32_t BufferLength);
    bool SendTlsData(const uint8_t* Buffer, uint16_t BufferLength, uint8_t KeyType);
    bool ProcessReceive();
    bool ProcessReceiveData(const uint8_t* Buffer, uint32_t BufferLength);
    bool ProcessReceiveFrame(TcpFrame* Frame);
    bool ProcessSend();
    void ProcessSendComplete();
    bool EncryptFrame(TcpFrame* Frame);
    QUIC_BUFFER* NewSendBuffer();
    void FreeSendBuffer(QUIC_BUFFER* SendBuffer);
    bool FinalizeSendBuffer(QUIC_BUFFER* SendBuffer);
    bool TryAddRef() { return CxPlatRefIncrementNonZero(&Ref, 1) != FALSE; }
    void Release() { if (CxPlatRefDecrement(&Ref)) delete this; }
public:
    void* Context{nullptr}; // App context
    TcpConnection(
        _In_ TcpEngine* Engine,
        _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
        _In_ void* Context = nullptr);
    bool IsInitialized() const { return Initialized; }
    void Close();
    bool Start(
        _In_ QUIC_ADDRESS_FAMILY Family,
        _In_reads_or_z_opt_(QUIC_MAX_SNI_LENGTH)
            const char* ServerName,
        _In_ uint16_t ServerPort,
        _In_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_ const QUIC_ADDR* RemoteAddress = nullptr);
    bool Send(TcpSendData* Data);
    bool GetStats(CXPLAT_TCP_STATISTICS* Stats) {
        return QUIC_SUCCEEDED(CxPlatSocketGetTcpStatistics(Socket, Stats));
    }
};

inline
void
TcpPrintConnectionStatistics(
    _In_ TcpConnection* Conn
    )
{
    CXPLAT_TCP_STATISTICS Stats;
    if (!Conn->GetStats(&Stats)) {
        return;
    }

    WriteOutput(
        "Connection Statistics:\n"
        "  RTT                       %u us\n"
        "  MinRTT                    %u us\n"
        "  TimestampsEnabled         %hhu\n"
        "  BytesOut                  %llu\n"
        "  BytesIn                   %llu\n"
        "  BytesReordered            %u\n"
        "  BytesRetrans              %u\n"
        "  FastRetrans               %u\n"
        "  DupAcksIn                 %u\n"
        "  TimeoutEpisodes           %u\n"
        "  SynRetrans                %hhu\n"
        "  SndLimTransRwin           %u\n"
        "  SndLimTimeRwin            %u\n"
        "  SndLimBytesRwin           %llu\n"
        "  SndLimTransCwnd           %u\n"
        "  SndLimTimeCwnd            %u\n"
        "  SndLimBytesCwnd           %llu\n"
        "  SndLimTransSnd            %u\n"
        "  SndLimTimeSnd             %u\n"
        "  SndLimBytesSnd            %llu\n",
        Stats.RttUs,
        Stats.MinRttUs,
        Stats.TimestampsEnabled,
        (unsigned long long)Stats.BytesOut,
        (unsigned long long)Stats.BytesIn,
        Stats.BytesReordered,
        Stats.BytesRetrans,
        Stats.FastRetrans,
        Stats.DupAcksIn,
        Stats.TimeoutEpisodes,
        Stats.SynRetrans,
        Stats.SndLimTransRwin,
        Stats.SndLimTimeRwin,
        (unsigned long long)Stats.SndLimBytesRwin,
        Stats.SndLimTransCwnd,
        Stats.SndLimTimeCwnd,
        (unsigned long long)Stats.SndLimBytesCwnd,
        Stats.SndLimTransSnd,
        Stats.SndLimTimeSnd,
        (unsigned long long)Stats.SndLimBytesSnd);
}
