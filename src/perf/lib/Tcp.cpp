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

#define FRAME_TYPE_CRYTPO   0
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
    uint32_t Id : 30;
    uint32_t Open : 1;
    uint32_t Fin : 1;
    uint8_t Data[0];
};
#pragma pack(pop)

const uint8_t FixedAlpnBuffer[] = {
    4, 'p', 'e', 'r', 'f'
};

const uint8_t FixedIv[CXPLAT_MAX_IV_LENGTH] = { 0 };

struct LoadSecConfigHelper {
    LoadSecConfigHelper() : SecConfig(nullptr) { CxPlatEventInitialize(&CallbackEvent, TRUE, FALSE); }
    ~LoadSecConfigHelper() { CxPlatEventUninitialize(CallbackEvent); }
    CXPLAT_SEC_CONFIG* Load(const QUIC_CREDENTIAL_CONFIG* CredConfig) {
        if (QUIC_FAILED(
            CxPlatTlsSecConfigCreate(
                CredConfig,
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
    TcpConnection::ReceiveCallback
};

const CXPLAT_TLS_CALLBACKS TcpEngine::TlsCallbacks = {
    TcpConnection::TlsProcessCompleteCallback,
    TcpConnection::TlsReceiveTpCallback,
    TcpConnection::TlsReceiveTicketCallback
};

TcpEngine::TcpEngine(
    TcpAcceptHandler AcceptHandler,
    TcpConnectHandler ConnectHandler,
    TcpReceiveHandler ReceiveHandler,
    TcpSendCompleteHandler SendCompleteHandler) :
    Initialized(false), Shutdown(false), ProcCount((uint16_t)CxPlatProcActiveCount()),
    Workers(new TcpWorker[ProcCount]), Datapath(nullptr),
    AcceptHandler(AcceptHandler), ConnectHandler(ConnectHandler),
    ReceiveHandler(ReceiveHandler), SendCompleteHandler(SendCompleteHandler)
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

TcpWorker::TcpWorker() : Initialized(false), Engine(nullptr)
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
    auto This = (TcpServer*)ListenerContext;
    auto Connection = new TcpConnection(This->Engine, This->SecConfig, AcceptSocket);
    Connection->Context = This;
    *AcceptClientContext = Connection;
}

// ############################ CONNECTION ############################

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    const QUIC_CREDENTIAL_CONFIG* CredConfig,
    const QUIC_ADDR* RemoteAddress,
    const QUIC_ADDR* LocalAddress,
    void* Context) :
    IsServer(false), Initialized(false), StartTls(false), IndicateAccept(false),
    IndicateConnect(false), IndicateDisconnect(false),
    Engine(Engine), Worker(nullptr), Socket(nullptr), SecConfig(nullptr), Tls(nullptr),
    ReceiveData(nullptr), SendData(nullptr), BatchedSendData(nullptr),
    BufferedDataLength(0), Context(Context)
{
    Entry.Flink = NULL;
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatZeroMemory(&TlsState, sizeof(TlsState));
    if (!Engine->IsInitialized()) {
        return;
    }
    LoadSecConfigHelper Helper;
    if ((SecConfig = Helper.Load(CredConfig)) == nullptr) {
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
    StartTls = true;
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    CXPLAT_SEC_CONFIG* SecConfig,
    CXPLAT_SOCKET* Socket) :
    IsServer(true), Initialized(false), StartTls(false), IndicateAccept(false),
    IndicateConnect(false), IndicateDisconnect(false),
    Engine(Engine), Worker(nullptr), Socket(Socket), SecConfig(SecConfig), Tls(nullptr),
    ReceiveData(nullptr), SendData(nullptr), BatchedSendData(nullptr),
    BufferedDataLength(0), Context(nullptr)
{
    Entry.Flink = NULL;
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatZeroMemory(&TlsState, sizeof(TlsState));
    Initialized = true;
    StartTls = true;
    IndicateAccept = true;
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::~TcpConnection()
{
    if (Socket) {
        CxPlatSocketDelete(Socket);
    }
    if (IsServer && SecConfig) {
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
    _In_ QUIC_CONNECTION* /* Context */
    )
{
    // Unsupported
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
        Engine->AcceptHandler(Server, this);
    }
    if (IndicateConnect) {
        IndicateConnect = false;
        Engine->ConnectHandler(this, true);
    }
    if (IndicateDisconnect) {
        IndicateDisconnect = false;
        Engine->ConnectHandler(this, false);
    }
    if (StartTls) {
        StartTls = false;
        InitializeTls();
    }
    if (ReceiveData) {
        ProcessReceive();
    }
    if (TlsState.WriteKey >= QUIC_PACKET_KEY_1_RTT && SendData) {
        ProcessSend();
    }
    if (BatchedSendData) {
        CxPlatSocketSend(Socket, &LocalAddress, &RemoteAddress, BatchedSendData);
        BatchedSendData = nullptr;
    }
}

bool TcpConnection::InitializeTls()
{
    const uint32_t LocalTPLength = 2;
    uint8_t* LocalTP = (uint8_t*)CXPLAT_ALLOC_NONPAGED(LocalTPLength, QUIC_POOL_GENERIC);
    CxPlatZeroMemory(LocalTP, LocalTPLength);

    CXPLAT_TLS_CONFIG Config;
    CxPlatZeroMemory(&Config, sizeof(Config));
    Config.IsServer = IsServer ? TRUE : FALSE;
    Config.Connection = (QUIC_CONNECTION*)(void*)this;
    Config.SecConfig = SecConfig;
    Config.AlpnBuffer = FixedAlpnBuffer;
    Config.AlpnBufferLength = sizeof(FixedAlpnBuffer);
    Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
    Config.ServerName = "localhost";
    Config.LocalTPBuffer = LocalTP;
    Config.LocalTPLength = LocalTPLength;

    if (QUIC_FAILED(
        CxPlatTlsInitialize(&Config, &TlsState, &Tls))) {
        return false;
    }

    return IsServer || ProcessTls(NULL, 0);
}

bool TcpConnection::ProcessTls(const uint8_t* Buffer, uint32_t BufferLength)
{
    auto SendBuffer = NewSendBuffer();
    if (!SendData) {
        return false;
    }

    TlsState.Buffer = SendBuffer->Buffer + sizeof(TcpFrame) - CXPLAT_ENCRYPTION_OVERHEAD;
    TlsState.BufferAllocLength = TLS_BLOCK_SIZE - sizeof(TcpFrame) - CXPLAT_ENCRYPTION_OVERHEAD;
    TlsState.BufferLength = 0;

    auto Results =
        CxPlatTlsProcessData(
            Tls,
            CXPLAT_TLS_CRYPTO_DATA,
            Buffer,
            &BufferLength,
            &TlsState);
    if (Results & CXPLAT_TLS_RESULT_PENDING) {
        // TODO - Not supported yet
        FreeSendBuffer(SendBuffer);
        return false;
    }
    if (Results & CXPLAT_TLS_RESULT_ERROR) {
        FreeSendBuffer(SendBuffer);
        return false;
    }

    auto Frame = (TcpFrame*)SendBuffer->Buffer;
    Frame->FrameType = FRAME_TYPE_CRYTPO;
    Frame->Length = TlsState.BufferLength;

    if (!EncryptFrame(Frame)) {
        FreeSendBuffer(SendBuffer);
        return false;
    }

    SendBuffer->Length = sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
    FinalizeSendBuffer(SendBuffer);

    return true;
}

void TcpConnection::ProcessReceive()
{
    CxPlatDispatchLockAcquire(&Lock);
    CXPLAT_RECV_DATA* RecvDataChain = ReceiveData;
    ReceiveData = nullptr;
    CxPlatDispatchLockRelease(&Lock);

    auto NextRecvData = RecvDataChain;
    while (NextRecvData) {
        if (!ProcessReceiveData(NextRecvData->Buffer, NextRecvData->BufferLength)) {
            goto Exit;
        }
        NextRecvData = NextRecvData->Next;
    }

Exit:

    CxPlatRecvDataReturn(RecvDataChain);
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
        if ((uint32_t)Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD > BufferLength) {
            goto BufferData;
        }
        CxPlatCopyMemory(
            BufferedData+BufferedDataLength,
            Buffer,
            Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD);

        ProcessReceiveFrame(Frame);
    }

    while (BufferLength) {
        auto Frame = (TcpFrame*)Buffer;
        if (BufferLength < sizeof(TcpFrame) ||
            BufferLength < sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD) {
            goto BufferData;
        }

        ProcessReceiveFrame(Frame);

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
            return false; // Shouldn't be possible
        }
        if (QUIC_FAILED(
            CxPlatDecrypt(
                TlsState.ReadKeys[Frame->KeyType]->PacketKey,
                FixedIv,
                sizeof(TcpFrame),
                (uint8_t*)Frame,
                Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD,
                Frame->Data))) {
            return false;
        }
    }

    switch (Frame->FrameType) {
    case FRAME_TYPE_CRYTPO:
        if (!ProcessTls(Frame->Data, Frame->Length)) {
            return false;
        }
        break;
    case FRAME_TYPE_STREAM: {
        auto StreamFrame = (TcpStreamFrame*)Frame->Data;
        Engine->ReceiveHandler(
            this,
            StreamFrame->Id,
            StreamFrame->Open,
            StreamFrame->Fin,
            Frame->Length - sizeof(TcpStreamFrame),
            StreamFrame->Data);
        break;
    }
    default:
        return false;
    }

    return true;
}

void TcpConnection::ProcessSend()
{
    CxPlatDispatchLockAcquire(&Lock);
    TcpSendData* SendDataChain = SendData;
    SendData = nullptr;
    CxPlatDispatchLockRelease(&Lock);

    auto NextSendData = SendDataChain;
    while (NextSendData) {
        uint32_t Offset = 0;
        while (NextSendData->Length > Offset) {
            auto SendBuffer = NewSendBuffer();
            if (!SendData) {
                goto Exit;
            }

            uint32_t StreamLength = TLS_BLOCK_SIZE - sizeof(TcpFrame) - sizeof(TcpStreamFrame) - CXPLAT_ENCRYPTION_OVERHEAD;
            if (NextSendData->Length - Offset < StreamLength) {
                StreamLength = NextSendData->Length - Offset;
            }

            auto Frame = (TcpFrame*)SendBuffer->Buffer;
            Frame->FrameType = FRAME_TYPE_STREAM;
            Frame->Length = (uint16_t)(sizeof(TcpStreamFrame) + StreamLength);

            auto StreamFrame = (TcpStreamFrame*)Frame->Data;
            StreamFrame->Id = NextSendData->StreamId;
            StreamFrame->Open = NextSendData->Open;
            StreamFrame->Fin = NextSendData->Fin;
            CxPlatCopyMemory(StreamFrame->Data, NextSendData->Buffer + Offset, StreamLength);
            Offset += StreamLength;

            if (!EncryptFrame(Frame)) {
                FreeSendBuffer(SendBuffer);
                goto Exit;
            }

            SendBuffer->Length = sizeof(TcpFrame) + Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD;
            FinalizeSendBuffer(SendBuffer);
        }

        NextSendData = NextSendData->Next;
    }

Exit:

    Engine->SendCompleteHandler(this, SendDataChain);
}

bool TcpConnection::EncryptFrame(TcpFrame* Frame)
{
    Frame->KeyType = (uint8_t)TlsState.WriteKey;
    return
        TlsState.WriteKey == QUIC_PACKET_KEY_INITIAL ||
        QUIC_SUCCEEDED(
        CxPlatEncrypt(
            TlsState.WriteKeys[TlsState.WriteKey]->PacketKey,
            FixedIv,
            sizeof(TcpFrame),
            (uint8_t*)Frame,
            Frame->Length + CXPLAT_ENCRYPTION_OVERHEAD,
            Frame->Data));
}

QUIC_BUFFER* TcpConnection::NewSendBuffer()
{
    if (!BatchedSendData) {
        BatchedSendData = CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, TLS_BLOCK_SIZE);
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
    if (SendBuffer->Length != TLS_BLOCK_SIZE ||
        CxPlatSendDataIsFull(BatchedSendData)) {
        if (QUIC_FAILED(
            CxPlatSocketSend(Socket, &LocalAddress, &RemoteAddress, BatchedSendData))) {
            // FATAL
        }
        BatchedSendData = nullptr;
    }
}

void TcpConnection::Send(TcpSendData* Data)
{
    CxPlatDispatchLockAcquire(&Lock);
    TcpSendData** Tail = &SendData;
    while (*Tail) {
        Tail = &(*Tail)->Next;
    }
    *Tail = Data;
    CxPlatDispatchLockRelease(&Lock);
    if (TlsState.WriteKey >= QUIC_PACKET_KEY_1_RTT) {
        Queue();
    }
}
