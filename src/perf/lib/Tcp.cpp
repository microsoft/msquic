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
    TcpSendCompleteHandler SendCompleteHandler) :
    ProcCount((uint16_t)CxPlatProcActiveCount()), Workers(new(std::nothrow) TcpWorker[ProcCount]),
    AcceptHandler(AcceptHandler), ConnectHandler(ConnectHandler),
    ReceiveHandler(ReceiveHandler), SendCompleteHandler(SendCompleteHandler)
{
#ifndef QUIC_NO_SHARED_DATAPATH
    for (uint16_t i = 0; i < ProcCount; ++i) {
        if (!Workers[i].Initialize(this)) {
            return;
        }
    }
    Initialized = true;
#endif
}

TcpEngine::~TcpEngine()
{
    Shutdown = true;
    for (uint16_t i = 0; i < ProcCount; ++i) {
        Workers[i].Shutdown();
    }
    delete [] Workers;
}

void TcpEngine::AddConnection(TcpConnection* Connection, uint16_t PartitionIndex)
{
    CXPLAT_DBG_ASSERT(PartitionIndex < ProcCount);
    CXPLAT_DBG_ASSERT(!Connection->Worker);
    Connection->PartitionIndex = PartitionIndex;
    Connection->Worker = &Workers[PartitionIndex];
}

// ############################# WORKER #############################

TcpWorker::TcpWorker()
{
    CxPlatEventInitialize(&WakeEvent, FALSE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
}

TcpWorker::~TcpWorker()
{
    if (Initialized) {
        CxPlatThreadDelete(&Thread);
        while (Connections) {
            auto Connection = Connections;
            Connections = Connections->Next;
            Connection->QueuedOnWorker = false;
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
        WriteOutput("CxPlatThreadCreate FAILED\n");
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
        if (!This->Connections) {
            Connection = nullptr;
        } else {
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
        } else {
            CxPlatEventWaitForever(This->WakeEvent);
        }
    }

    CXPLAT_THREAD_RETURN(0);
}

void TcpWorker::QueueConnection(TcpConnection* Connection)
{
    CxPlatDispatchLockAcquire(&Lock);
    if (!Connection->QueuedOnWorker) {
        Connection->QueuedOnWorker = true;
        Connection->AddRef();
        *ConnectionsTail = Connection;
        ConnectionsTail = &Connection->Next;
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
void
TcpServer::AcceptCallback(
    _In_ CXPLAT_SOCKET* /* ListenerSocket */,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    )
{
    auto This = (TcpServer*)ListenerContext;
    auto Connection = new(std::nothrow) TcpConnection(This->Engine, This->SecConfig, AcceptSocket);
    Connection->Context = This;
    *AcceptClientContext = Connection;
}

// ############################ CONNECTION ############################

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_or_z_opt_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort,
    const QUIC_ADDR* LocalAddress,
    void* Context) :
    IsServer(false), Engine(Engine), Context(Context)
{
    CxPlatRefInitialize(&Ref);
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
    if (LocalAddress) {
        Family = QuicAddrGetFamily(LocalAddress);
    }
    QuicAddrSetFamily(&Route.RemoteAddress, Family);
    if (QUIC_FAILED(
        CxPlatDataPathResolveAddress(
            Datapath,
            ServerName,
            &Route.RemoteAddress))) {
        WriteOutput("CxPlatDataPathResolveAddress FAILED\n");
        return;
    }
    QuicAddrSetPort(&Route.RemoteAddress, ServerPort);
    Engine->AddConnection(this, 0); // TODO - Correct index
    Initialized = true;
    if (QUIC_FAILED(
        CxPlatSocketCreateTcp(
            Datapath,
            LocalAddress,
            &Route.RemoteAddress,
            this,
            &Socket))) {
        Initialized = false;
        return;
    }
    Queue();
}

TcpConnection::TcpConnection(
    TcpEngine* Engine,
    CXPLAT_SEC_CONFIG* SecConfig,
    CXPLAT_SOCKET* Socket) :
    IsServer(true), Engine(Engine), Socket(Socket), SecConfig(SecConfig)
{
    CxPlatRefInitialize(&Ref);
    CxPlatDispatchLockInitialize(&Lock);
    CxPlatZeroMemory(&TlsState, sizeof(TlsState));
    QuicTraceLogVerbose(
        PerfTcpCreateServer,
        "[perf][tcp][%p] Server created",
        this);
    Initialized = true;
    IndicateAccept = true;
    Engine->AddConnection(this, 0); // TODO - Correct index
    Queue();
}

TcpConnection::~TcpConnection()
{
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
        CxPlatSocketDelete(Socket);
    }
    if (!IsServer && SecConfig) {
        CxPlatTlsSecConfigDelete(SecConfig);
    }
    CXPLAT_DBG_ASSERT(!QueuedOnWorker);
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
    QuicTraceLogVerbose(
        PerfTcpReceiveCallback,
        "[perf][tcp][%p] Receive callback",
        This);
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
    _Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK)
void
TcpConnection::SendCompleteCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ QUIC_STATUS /* Status */,
    _In_ uint32_t ByteCount
    )
{
    TcpConnection* This = (TcpConnection*)Context;
    QuicTraceLogVerbose(
        PerfTcpSendCompleteCallback,
        "[perf][tcp][%p] SendComplete callback",
        This);
    CxPlatDispatchLockAcquire(&This->Lock);
    This->TotalSendCompleteOffset += ByteCount;
    This->IndicateSendComplete = true;
    CxPlatDispatchLockRelease(&This->Lock);
    This->Queue();
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
        Engine->AcceptHandler(Server, this);
        StartTls = true;
    }
    if (IndicateConnect) {
        IndicateConnect = false;
        QuicTraceLogVerbose(
            PerfTcpAppConnect,
            "[perf][tcp][%p] App Connect",
            this);
        Engine->ConnectHandler(this, true);
        StartTls = true;
    }
    if (StartTls) {
        StartTls = false;
        QuicTraceLogVerbose(
            PerfTcpStartTls,
            "[perf][tcp][%p] Start TLS",
            this);
        if (!InitializeTls()) {
            IndicateDisconnect = true;
        }
    }
    if (ReceiveData) {
        if (!ProcessReceive()) {
            IndicateDisconnect = true;
        }
    }
    if (TlsState.WriteKey >= QUIC_PACKET_KEY_1_RTT && SendData) {
        if (!ProcessSend()) {
            IndicateDisconnect = true;
        }
    }
    if (BatchedSendData) {
        if (QUIC_FAILED(
            CxPlatSocketSend(Socket, &Route, BatchedSendData, PartitionIndex))) {
            IndicateDisconnect = true;
        }
        BatchedSendData = nullptr;
    }
    if (IndicateSendComplete) {
        IndicateSendComplete = false;
        ProcessSendComplete();
    }
    if (IndicateDisconnect && !ClosedByApp) {
        QuicTraceLogVerbose(
            PerfTcpAppDisconnect,
            "[perf][tcp][%p] App Disconnect",
            this);
        IndicateDisconnect = false;
        Engine->ConnectHandler(this, false);
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

    while (BaseOffset < TlsState.BufferTotalLength) {
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
        WriteOutput("NewSendBuffer FAILED\n");
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
    return FinalizeSendBuffer(SendBuffer);
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

        ProcessReceiveFrame(Frame);
        BufferedDataLength = 0;
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
        Engine->ReceiveHandler(
            this,
            StreamFrame->Id,
            StreamFrame->Open,
            StreamFrame->Fin,
            StreamFrame->Abort,
            Frame->Length - sizeof(TcpStreamFrame),
            StreamFrame->Data);
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
                WriteOutput("NewSendBuffer FAILED\n");
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
            if (!FinalizeSendBuffer(SendBuffer)) {
                return false;
            }

        } while (NextSendData->Length > Offset);

        NextSendData->Offset = TotalSendOffset;
        NextSendData = NextSendData->Next;
    }

    return true;
}

void TcpConnection::ProcessSendComplete()
{
    uint64_t Offset = TotalSendCompleteOffset;
    while (SentData && SentData->Offset <= Offset) {
        TcpSendData* Data = SentData;
        SentData = Data->Next;
        Data->Next = NULL;
        QuicTraceLogVerbose(
            PerfTcpAppSendComplete,
            "[perf][tcp][%p] App Send complete %u bytes",
            this,
            Data->Length);
        Engine->SendCompleteHandler(this, Data);
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
    if (!BatchedSendData) {
        BatchedSendData = CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, TLS_BLOCK_SIZE, &Route);
        if (!BatchedSendData) { return nullptr; }
    }
    return CxPlatSendDataAllocBuffer(BatchedSendData, TLS_BLOCK_SIZE);
}

void TcpConnection::FreeSendBuffer(QUIC_BUFFER* SendBuffer)
{
    CxPlatSendDataFreeBuffer(BatchedSendData, SendBuffer);
}

bool TcpConnection::FinalizeSendBuffer(QUIC_BUFFER* SendBuffer)
{
    TotalSendOffset += SendBuffer->Length;
    if (SendBuffer->Length != TLS_BLOCK_SIZE ||
        CxPlatSendDataIsFull(BatchedSendData)) {
        if (QUIC_FAILED(
            CxPlatSocketSend(Socket, &Route, BatchedSendData, PartitionIndex))) {
            WriteOutput("CxPlatSocketSend FAILED\n");
            return false;
        }
        BatchedSendData = nullptr;
    }
    return true;
}

void TcpConnection::Send(TcpSendData* Data)
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
    TcpSendData** Tail = &SendData;
    while (*Tail) {
        Tail = &((*Tail)->Next);
    }
    *Tail = Data;
    CxPlatDispatchLockRelease(&Lock);
    if (TlsState.WriteKey >= QUIC_PACKET_KEY_1_RTT) {
        Queue();
    }
}

void TcpConnection::Close()
{
    QuicTraceLogVerbose(
        PerfTcpAppClose,
        "[perf][tcp][%p] App Close",
        this);
    ClosedByApp = true;
    Release();
}
