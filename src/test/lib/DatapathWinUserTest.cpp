/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests for the Windows user-mode datapath layer (datapath_winuser.c).
    Exercises CxPlat* datapath APIs: initialization, feature queries, address
    resolution, socket creation/deletion, send/receive, and lifecycle management.

--*/

#include "precomp.h"

extern "C" {
#include "quic_datapath.h"
}

#ifndef _KERNEL_MODE
extern CXPLAT_WORKER_POOL* WorkerPool;
#else
static CXPLAT_WORKER_POOL* WorkerPool;
#endif

//
// ---- Callback Helpers ----
//

struct DatapathTestRecvContext {
    CXPLAT_EVENT RecvEvent;
    QUIC_ADDR SourceAddress;
    uint16_t RecvBufLen;
    uint8_t RecvBuf[512];
    BOOLEAN Received;
};

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
static void
DatapathTestUdpRecvCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    auto Ctx = (DatapathTestRecvContext*)Context;
    if (Ctx != nullptr && !Ctx->Received) {
        CXPLAT_RECV_DATA* Data = RecvDataChain;
        if (Data != nullptr && Data->BufferLength <= sizeof(Ctx->RecvBuf)) {
            memcpy(Ctx->RecvBuf, Data->Buffer, Data->BufferLength);
            Ctx->RecvBufLen = Data->BufferLength;
            if (Data->Route != nullptr) {
                Ctx->SourceAddress = Data->Route->RemoteAddress;
            }
            Ctx->Received = TRUE;
            CxPlatEventSet(Ctx->RecvEvent);
        }
    }
    CxPlatRecvDataReturn(RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
static void
DatapathTestUdpRecvCallbackSimple(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* /* Context */,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatRecvDataReturn(RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
static void
DatapathTestUdpUnreachCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* /* Context */,
    _In_ const QUIC_ADDR* /* RemoteAddress */
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
static QUIC_STATUS
DatapathTestTcpAcceptCallback(
    _In_ CXPLAT_SOCKET* /* ListenerSocket */,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* /* AcceptSocket */,
    _Out_ void** AcceptClientContext
    )
{
    *AcceptClientContext = ListenerContext;
    if (ListenerContext != nullptr) {
        auto Event = (CXPLAT_EVENT*)ListenerContext;
        CxPlatEventSet(*Event);
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_CONNECT_CALLBACK)
static void
DatapathTestTcpConnectCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ BOOLEAN Connected
    )
{
    if (Connected && Context != nullptr) {
        auto Event = (CXPLAT_EVENT*)Context;
        CxPlatEventSet(*Event);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
static void
DatapathTestTcpRecvCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* /* Context */,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatRecvDataReturn(RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK)
static void
DatapathTestTcpSendCompleteCallback(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* /* Context */,
    _In_ QUIC_STATUS /* Status */,
    _In_ uint32_t /* ByteCount */
    )
{
}

struct DatapathTestTcpRecvContext {
    CXPLAT_EVENT RecvEvent;
    uint16_t RecvBufLen;
    uint8_t RecvBuf[512];
    BOOLEAN Received;
};

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
static void
DatapathTestTcpRecvCallbackWithContext(
    _In_ CXPLAT_SOCKET* /* Socket */,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    auto Ctx = (DatapathTestTcpRecvContext*)Context;
    if (Ctx != nullptr && !Ctx->Received) {
        CXPLAT_RECV_DATA* Data = RecvDataChain;
        if (Data != nullptr && Data->BufferLength <= sizeof(Ctx->RecvBuf)) {
            memcpy(Ctx->RecvBuf, Data->Buffer, Data->BufferLength);
            Ctx->RecvBufLen = Data->BufferLength;
            Ctx->Received = TRUE;
            CxPlatEventSet(Ctx->RecvEvent);
        }
    }
    CxPlatRecvDataReturn(RecvDataChain);
}

struct DatapathTestTcpAcceptRecvContext {
    CXPLAT_EVENT AcceptEvent;
    DatapathTestTcpRecvContext* RecvCtx;
};

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
static QUIC_STATUS
DatapathTestTcpAcceptCallbackWithRecv(
    _In_ CXPLAT_SOCKET* /* ListenerSocket */,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* /* AcceptSocket */,
    _Out_ void** AcceptClientContext
    )
{
    auto Ctx = (DatapathTestTcpAcceptRecvContext*)ListenerContext;
    *AcceptClientContext = Ctx->RecvCtx;
    CxPlatEventSet(Ctx->AcceptEvent);
    return QUIC_STATUS_SUCCESS;
}

//
// ---- Static Callback Constants ----
//

static const CXPLAT_UDP_DATAPATH_CALLBACKS DefaultUdpCallbacks = {
    DatapathTestUdpRecvCallbackSimple,
    DatapathTestUdpUnreachCallback,
};

static const CXPLAT_TCP_DATAPATH_CALLBACKS DefaultTcpCallbacks = {
    DatapathTestTcpAcceptCallback,
    DatapathTestTcpConnectCallback,
    DatapathTestTcpRecvCallback,
    DatapathTestTcpSendCompleteCallback,
};

//
// ---- RAII Scope Helpers ----
//

struct EventScope {
    CXPLAT_EVENT Event;
    EventScope() { CxPlatEventInitialize(&Event, FALSE, FALSE); }
    ~EventScope() { CxPlatEventUninitialize(Event); }
};

struct DatapathScope {
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathScope() {
        CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
        TEST_QUIC_SUCCEEDED(
            CxPlatDataPathInitialize(
                0, &DefaultUdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));
    }

    explicit DatapathScope(const CXPLAT_TCP_DATAPATH_CALLBACKS& TcpCallbacks) {
        CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
        TEST_QUIC_SUCCEEDED(
            CxPlatDataPathInitialize(
                0, &DefaultUdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
    }

    DatapathScope(
        uint32_t ClientRecvDataLength,
        const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
        const CXPLAT_DATAPATH_INIT_CONFIG& Config
        )
    {
        CXPLAT_DATAPATH_INIT_CONFIG InitConfig = Config;
        TEST_QUIC_SUCCEEDED(
            CxPlatDataPathInitialize(
                ClientRecvDataLength, &DefaultUdpCallbacks, TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
    }

    ~DatapathScope() {
        if (Datapath) { CxPlatDataPathUninitialize(Datapath); }
    }

    CXPLAT_DATAPATH* get() const { return Datapath; }
    operator CXPLAT_DATAPATH*() const { return Datapath; }
};

struct UdpSocketScope {
    CXPLAT_SOCKET* Socket = nullptr;

    UdpSocketScope(
        _In_ CXPLAT_DATAPATH* Datapath,
        _In_ const CXPLAT_UDP_CONFIG* Config
        )
    {
        TEST_QUIC_SUCCEEDED(CxPlatSocketCreateUdp(Datapath, Config, &Socket));
    }

    ~UdpSocketScope() {
        if (Socket) { CxPlatSocketDelete(Socket); }
    }

    CXPLAT_SOCKET* get() const { return Socket; }
    operator CXPLAT_SOCKET*() const { return Socket; }
};

struct TcpSocketScope {
    CXPLAT_SOCKET* Socket = nullptr;
    bool Owned = true;

    TcpSocketScope() = default;

    ~TcpSocketScope() {
        if (Socket && Owned) { CxPlatSocketDelete(Socket); }
    }

    CXPLAT_SOCKET* get() const { return Socket; }
    operator CXPLAT_SOCKET*() const { return Socket; }
    CXPLAT_SOCKET* release() { Owned = false; return Socket; }
};

struct SendDataScope {
    CXPLAT_SEND_DATA* SendData = nullptr;

    SendDataScope(
        _In_ CXPLAT_SOCKET* Socket,
        _In_ CXPLAT_SEND_CONFIG* Config
        )
    {
        SendData = CxPlatSendDataAlloc(Socket, Config);
        TEST_NOT_EQUAL(nullptr, SendData);
    }

    ~SendDataScope() {
        if (SendData) { CxPlatSendDataFree(SendData); }
    }

    CXPLAT_SEND_DATA* get() const { return SendData; }
    operator CXPLAT_SEND_DATA*() const { return SendData; }

    CXPLAT_SEND_DATA* release() {
        CXPLAT_SEND_DATA* Tmp = SendData;
        SendData = nullptr;
        return Tmp;
    }
};

//
// ---- Shared UDP Loopback Helpers ----
//
// Extracts the repeated setup/teardown/send/verify pattern used by most
// send/receive tests. Tests create a UdpLoopbackContext, call SetupUdpLoopback
// to initialize datapath + server + client sockets, then SendAndVerifyPayload
// for the actual send/receive, and TeardownUdpLoopback for cleanup.
//

struct UdpLoopbackContext {
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* ServerSocket = nullptr;
    CXPLAT_SOCKET* ClientSocket = nullptr;
    DatapathTestRecvContext RecvCtx = {};
    QUIC_ADDR RemoteAddr = {};
    CXPLAT_ROUTE Route = {};
};

static void
SetupUdpLoopback(
    _Inout_ UdpLoopbackContext* Ctx,
    _In_ const char* LoopbackAddr,
    _In_opt_ const CXPLAT_DATAPATH_INIT_CONFIG* CustomConfig = nullptr
    )
{
    CxPlatEventInitialize(&Ctx->RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig =
        CustomConfig ? *CustomConfig : CXPLAT_DATAPATH_INIT_CONFIG{};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Ctx->Datapath));

    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString(LoopbackAddr, 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &Ctx->RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Ctx->Datapath, &ServerConfig, &Ctx->ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(Ctx->ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    QuicAddrFromString(LoopbackAddr, ServerPort, &Ctx->RemoteAddr);

    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &Ctx->RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Ctx->Datapath, &ClientConfig, &Ctx->ClientSocket));

    CxPlatSocketGetLocalAddress(Ctx->ClientSocket, &Ctx->Route.LocalAddress);
    Ctx->Route.RemoteAddress = Ctx->RemoteAddr;
}

static void
TeardownUdpLoopback(
    _Inout_ UdpLoopbackContext* Ctx
    )
{
    if (Ctx->ClientSocket) { CxPlatSocketDelete(Ctx->ClientSocket); }
    if (Ctx->ServerSocket) { CxPlatSocketDelete(Ctx->ServerSocket); }
    CxPlatEventUninitialize(Ctx->RecvCtx.RecvEvent);
    if (Ctx->Datapath) { CxPlatDataPathUninitialize(Ctx->Datapath); }
}

static void
SendAndVerifyPayload(
    _Inout_ UdpLoopbackContext* Ctx,
    _In_reads_(PayloadLen) const uint8_t* Payload,
    _In_ uint16_t PayloadLen,
    uint8_t Ecn = CXPLAT_ECN_NON_ECT,
    uint8_t SendFlags = CXPLAT_SEND_FLAGS_NONE,
    uint8_t Dscp = CXPLAT_DSCP_CS0
    )
{
    CXPLAT_SEND_CONFIG SendConfig = {
        &Ctx->Route, PayloadLen, Ecn, SendFlags, Dscp
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Ctx->ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(Ctx->ClientSocket, &Ctx->Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(Ctx->RecvCtx.RecvEvent, 2000));
    TEST_EQUAL(TRUE, (BOOLEAN)Ctx->RecvCtx.Received);
    TEST_EQUAL(PayloadLen, Ctx->RecvCtx.RecvBufLen);
    TEST_EQUAL(0, memcmp(Ctx->RecvCtx.RecvBuf, Payload, PayloadLen));
}

//
// ---- Shared Server-Send Helper ----
//
// For tests where a "server" socket (no fixed remote) sends to a receiver.
//

struct ServerSendContext {
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* SenderSocket = nullptr;
    CXPLAT_SOCKET* RecvSocket = nullptr;
    DatapathTestRecvContext RecvCtx = {};
    CXPLAT_ROUTE Route = {};
};

static void
SetupServerSend(
    _Inout_ ServerSendContext* Ctx,
    _In_ const char* LoopbackAddr
    )
{
    CxPlatEventInitialize(&Ctx->RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Ctx->Datapath));

    QUIC_ADDR RecvLocalAddr = {};
    QuicAddrFromString(LoopbackAddr, 0, &RecvLocalAddr);

    CXPLAT_UDP_CONFIG RecvConfig = {};
    RecvConfig.LocalAddress = &RecvLocalAddr;
    RecvConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    RecvConfig.CallbackContext = &Ctx->RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Ctx->Datapath, &RecvConfig, &Ctx->RecvSocket));

    QUIC_ADDR BoundRecvAddr = {};
    CxPlatSocketGetLocalAddress(Ctx->RecvSocket, &BoundRecvAddr);
    uint16_t RecvPort = QuicAddrGetPort(&BoundRecvAddr);
    TEST_NOT_EQUAL(0, RecvPort);

    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString(LoopbackAddr, 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.RemoteAddress = nullptr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Ctx->Datapath, &ServerConfig, &Ctx->SenderSocket));

    QUIC_ADDR TargetAddr = {};
    QuicAddrFromString(LoopbackAddr, RecvPort, &TargetAddr);

    CxPlatSocketGetLocalAddress(Ctx->SenderSocket, &Ctx->Route.LocalAddress);
    Ctx->Route.RemoteAddress = TargetAddr;
    Ctx->Route.Queue = nullptr;
}

static void
ServerSendAndVerify(
    _Inout_ ServerSendContext* Ctx,
    _In_reads_(PayloadLen) const uint8_t* Payload,
    _In_ uint16_t PayloadLen
    )
{
    CXPLAT_SEND_CONFIG SendConfig = {
        &Ctx->Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Ctx->SenderSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(Ctx->SenderSocket, &Ctx->Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(Ctx->RecvCtx.RecvEvent, 2000));
    TEST_EQUAL(TRUE, (BOOLEAN)Ctx->RecvCtx.Received);
    TEST_EQUAL(PayloadLen, Ctx->RecvCtx.RecvBufLen);
    TEST_EQUAL(0, memcmp(Ctx->RecvCtx.RecvBuf, Payload, PayloadLen));
}

static void
TeardownServerSend(
    _Inout_ ServerSendContext* Ctx
    )
{
    if (Ctx->SenderSocket) { CxPlatSocketDelete(Ctx->SenderSocket); }
    if (Ctx->RecvSocket) { CxPlatSocketDelete(Ctx->RecvSocket); }
    CxPlatEventUninitialize(Ctx->RecvCtx.RecvEvent);
    if (Ctx->Datapath) { CxPlatDataPathUninitialize(Ctx->Datapath); }
}

//
// ---- Shared TCP Helper ----
//

static bool
HasFeature(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_DATAPATH_FEATURES Feature
    )
{
    return (CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE) & Feature) != 0;
}

static void
CreateTcpListenerOnLoopback(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const char* Addr,
    _In_opt_ void* Context,
    _Out_ CXPLAT_SOCKET** Listener,
    _Out_ uint16_t* Port
    )
{
    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString(Addr, 0, &ListenerAddr);
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(Datapath, &ListenerAddr, Context, Listener));
    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(*Listener, &BoundAddr);
    *Port = QuicAddrGetPort(&BoundAddr);
}

//
// =========================================================================
// Category 1: Spec-Conformance — Initialization Validation
// Coupling: Public API only. Tests precondition checks per API contract.
// =========================================================================
//

//
// Scenario: UDP-only datapath initialization with default config.
// Code path: DataPathInitialize — WSAStartup, UdpCallbacks copy, partition pool init, success path.
// Assertions: CxPlatDataPathInitialize returns QUIC_STATUS_SUCCESS (via DatapathScope).
//             Supported features contain only known flags.
//             TCP feature is reported (always available on Windows user-mode).
//
void
QuicTestDataPathInitUdp(
    )
{
    DatapathScope Datapath;

    //
    // Verify the datapath is usable by querying supported features.
    //
    uint32_t Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    uint32_t AllKnownFeatures =
        CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING |
        CXPLAT_DATAPATH_FEATURE_RECV_COALESCING |
        CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION |
        CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING |
        CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS |
        CXPLAT_DATAPATH_FEATURE_TCP |
        CXPLAT_DATAPATH_FEATURE_RAW |
        CXPLAT_DATAPATH_FEATURE_TTL |
        CXPLAT_DATAPATH_FEATURE_SEND_DSCP |
        CXPLAT_DATAPATH_FEATURE_RECV_DSCP;
    TEST_EQUAL(0u, (Features & ~AllKnownFeatures));

    //
    // On Windows user-mode, TCP is always available.
    //
    TEST_TRUE((Features & CXPLAT_DATAPATH_FEATURE_TCP) != 0);
}

//
// Scenario: Datapath initialization with both UDP and TCP callbacks.
// Code path: DataPathInitialize — TcpCallbacks copy branch.
// Assertions: CxPlatDataPathInitialize returns QUIC_STATUS_SUCCESS.
//             Supported features contain only known flags.
//
void
QuicTestDataPathInitUdpTcp(
    )
{
    DatapathScope Datapath(DefaultTcpCallbacks);

    uint32_t Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    uint32_t AllKnownFeatures =
        CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING |
        CXPLAT_DATAPATH_FEATURE_RECV_COALESCING |
        CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION |
        CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING |
        CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS |
        CXPLAT_DATAPATH_FEATURE_TCP |
        CXPLAT_DATAPATH_FEATURE_RAW |
        CXPLAT_DATAPATH_FEATURE_TTL |
        CXPLAT_DATAPATH_FEATURE_SEND_DSCP |
        CXPLAT_DATAPATH_FEATURE_RECV_DSCP;
    TEST_EQUAL(0u, (Features & ~AllKnownFeatures));
}

//
// Scenario: Initialization with NULL output pointer must fail.
// Code path: DataPathInitialize — NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitNullOutput(
    )
{
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, nullptr));
}

//
// Scenario: Initialization with NULL WorkerPool must fail.
// Code path: DataPathInitialize — NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitNullWorkerPool(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, nullptr, &InitConfig, &Datapath));
}

//
// Scenario: UDP callbacks with NULL Receive handler must fail.
// Code path: DataPathInitialize — UdpCallbacks->Receive NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitUdpMissingRecv(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {};
    UdpCallbacks.Unreachable = DatapathTestUdpUnreachCallback;
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));
}

//
// Scenario: UDP callbacks with NULL Unreachable handler must fail.
// Code path: DataPathInitialize — UdpCallbacks->Unreachable NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitUdpMissingUnreach(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {};
    UdpCallbacks.Receive = DatapathTestUdpRecvCallbackSimple;
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));
}

//
// Scenario: TCP callbacks with NULL Accept handler must fail.
// Code path: DataPathInitialize — TcpCallbacks->Accept NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitTcpMissingAccept(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {};
    TcpCallbacks.Connect = DatapathTestTcpConnectCallback;
    TcpCallbacks.Receive = DatapathTestTcpRecvCallback;
    TcpCallbacks.SendComplete = DatapathTestTcpSendCompleteCallback;
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
}

//
// Scenario: TCP callbacks with NULL Connect handler must fail.
// Code path: DataPathInitialize — TcpCallbacks->Connect NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitTcpMissingConnect(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {};
    TcpCallbacks.Accept = DatapathTestTcpAcceptCallback;
    TcpCallbacks.Receive = DatapathTestTcpRecvCallback;
    TcpCallbacks.SendComplete = DatapathTestTcpSendCompleteCallback;
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
}

//
// Scenario: TCP callbacks with NULL Receive handler must fail.
// Code path: DataPathInitialize — TcpCallbacks->Receive NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitTcpMissingRecv(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {};
    TcpCallbacks.Accept = DatapathTestTcpAcceptCallback;
    TcpCallbacks.Connect = DatapathTestTcpConnectCallback;
    TcpCallbacks.SendComplete = DatapathTestTcpSendCompleteCallback;
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
}

//
// Scenario: TCP callbacks with NULL SendComplete handler must fail.
// Code path: DataPathInitialize — TcpCallbacks->SendComplete NULL check.
// Assertions: Returns QUIC_STATUS_INVALID_PARAMETER.
//
void
QuicTestDataPathInitTcpMissingSendComplete(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {};
    TcpCallbacks.Accept = DatapathTestTcpAcceptCallback;
    TcpCallbacks.Connect = DatapathTestTcpConnectCallback;
    TcpCallbacks.Receive = DatapathTestTcpRecvCallback;
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
}

//
// Scenario: Initialization with EnableDscpOnRecv config flag set.
// Code path: DataPathInitialize + CxPlatDataPathQuerySockoptSupport DSCP recv path.
// Assertions: Initialization succeeds.
//
void
QuicTestDataPathInitDscpOnRecv(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    InitConfig.EnableDscpOnRecv = TRUE;
    DatapathScope Datapath(0, nullptr, InitConfig);
}

//
// Scenario: Initialization with non-zero ClientRecvDataLength affecting RecvPayloadOffset calculation.
// Code path: DataPathInitialize — DatagramStride computation at lines 708-712.
// Assertions: Initialization succeeds; socket creation works with custom context length.
//
void
QuicTestDataPathInitWithClientRecvContextLength(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    DatapathScope Datapath(64, nullptr, InitConfig);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

//
// =========================================================================
// Category 2: Feature Query
// Coupling: Public API only. Exercises feature enumeration interfaces.
// =========================================================================
//

//
// Scenario: Query supported features and validate bitmask.
// Code path: DataPathGetSupportedFeatures — returns Datapath->Features.
// Assertions: Returned features contain only known defined bits.
//
void
QuicTestDataPathFeatureQuery(
    )
{
    DatapathScope Datapath;

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);

    const uint32_t AllKnownFeatures =
        CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING |
        CXPLAT_DATAPATH_FEATURE_RECV_COALESCING |
        CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION |
        CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING |
        CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS |
        CXPLAT_DATAPATH_FEATURE_TCP |
        CXPLAT_DATAPATH_FEATURE_RAW |
        CXPLAT_DATAPATH_FEATURE_TTL |
        CXPLAT_DATAPATH_FEATURE_SEND_DSCP |
        CXPLAT_DATAPATH_FEATURE_RECV_DSCP;
    TEST_EQUAL(0u, ((uint32_t)Features & ~AllKnownFeatures));
}

//
// Scenario: Query padding preference based on segmentation support.
// Code path: DataPathIsPaddingPreferred — checks SEND_SEGMENTATION flag.
// Assertions: Returns TRUE when segmentation is supported, FALSE otherwise.
//
void
QuicTestDataPathIsPaddingPreferred(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 12345, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    BOOLEAN IsPadded = CxPlatDataPathIsPaddingPreferred(Datapath, SendData);
    if (HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        TEST_EQUAL(TRUE, (BOOLEAN)IsPadded);
    } else {
        TEST_EQUAL(FALSE, (BOOLEAN)IsPadded);
    }
}

//
// Scenario: Feature queries with different socket flags return identical results.
// Code path: DataPathGetSupportedFeatures — Windows ignores socket flags.
// Assertions: Features from NONE, PCP, and SHARE flags are all equal; all bits are in known range.
//
void
QuicTestDataPathFeatureQueryWithFlags(
    )
{
    DatapathScope Datapath;

    CXPLAT_DATAPATH_FEATURES FeaturesNone =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    CXPLAT_DATAPATH_FEATURES FeaturesPcp =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_PCP);
    CXPLAT_DATAPATH_FEATURES FeaturesShare =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_SHARE);

    const uint32_t AllKnownFeatures =
        CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING |
        CXPLAT_DATAPATH_FEATURE_RECV_COALESCING |
        CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION |
        CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING |
        CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS |
        CXPLAT_DATAPATH_FEATURE_TCP |
        CXPLAT_DATAPATH_FEATURE_RAW |
        CXPLAT_DATAPATH_FEATURE_TTL |
        CXPLAT_DATAPATH_FEATURE_SEND_DSCP |
        CXPLAT_DATAPATH_FEATURE_RECV_DSCP;
    TEST_EQUAL(0u, ((uint32_t)FeaturesNone & ~AllKnownFeatures));
    TEST_EQUAL(0u, ((uint32_t)FeaturesPcp & ~AllKnownFeatures));
    TEST_EQUAL(0u, ((uint32_t)FeaturesShare & ~AllKnownFeatures));
    TEST_EQUAL((uint32_t)FeaturesNone, (uint32_t)FeaturesPcp);
    TEST_EQUAL((uint32_t)FeaturesNone, (uint32_t)FeaturesShare);
}

//
// =========================================================================
// Category 3: Address Resolution
// Coupling: Public API only. Exercises hostname/address resolution paths.
// =========================================================================
//

//
// Scenario: Resolve "localhost" with INET hint.
// Code path: CxPlatDataPathResolveAddress -> getaddrinfo with AF_INET hint.
// Assertions: Returns success; family equals QUIC_ADDRESS_FAMILY_INET.
//
void
QuicTestDataPathResolveLocalhostV4(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "localhost", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&Address));
}

//
// Scenario: Resolve "localhost" with INET6 hint.
// Code path: CxPlatDataPathResolveAddress -> getaddrinfo with AF_INET6 hint.
// Assertions: Returns success; family equals QUIC_ADDRESS_FAMILY_INET6.
//
void
QuicTestDataPathResolveLocalhostV6(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET6);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "localhost", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&Address));
}

//
// Scenario: Resolve numeric "127.0.0.1" with UNSPEC family.
// Code path: CxPlatDataPathResolveAddress + CxPlatDataPathPopulateTargetAddress.
// Assertions: Returns success; resolved family is INET.
//
void
QuicTestDataPathResolveNumericV4(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "127.0.0.1", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&Address));
}

//
// Scenario: Resolve numeric "::1" with INET6 hint.
// Code path: CxPlatDataPathResolveAddress.
// Assertions: Returns success; family is INET6.
//
void
QuicTestDataPathResolveNumericV6(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET6);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "::1", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&Address));
}

//
// Scenario: Resolve a non-existent hostname must fail.
// Code path: CxPlatDataPathResolveAddress -> getaddrinfo failure.
// Assertions: Returns a failure status.
//
void
QuicTestDataPathResolveInvalidHost(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QUIC_STATUS Status =
        CxPlatDataPathResolveAddress(
            Datapath, "this.host.does.not.exist.invalid", &Address);
    TEST_TRUE(QUIC_FAILED(Status));
}

//
// Scenario: Resolve "localhost" with UNSPEC family accepts either v4 or v6.
// Code path: CxPlatDataPathPopulateTargetAddress UNSPEC branch.
// Assertions: Returns success; family is INET or INET6.
//
void
QuicTestDataPathResolveUnspecFamily(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "localhost", &Address));
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Address);
    TEST_TRUE(
        Family == QUIC_ADDRESS_FAMILY_INET ||
        Family == QUIC_ADDRESS_FAMILY_INET6);
}

//
// =========================================================================
// Category 4: Address Enumeration
// Coupling: Public API only. Exercises local/gateway address enumeration.
// =========================================================================
//

//
// Scenario: Enumerate local unicast addresses.
// Code path: CxPlatDataPathGetLocalAddresses -> GetAdaptersAddresses.
// Assertions: Returns success; at least one address returned; output pointer is non-null.
//
void
QuicTestDataPathGetLocalAddresses(
    )
{
    DatapathScope Datapath;

    CXPLAT_ADAPTER_ADDRESS* Addresses = nullptr;
    uint32_t AddressCount = 0;

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathGetLocalAddresses(Datapath, &Addresses, &AddressCount));
    TEST_TRUE(AddressCount > 0);
    TEST_NOT_EQUAL(nullptr, Addresses);

    CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
}

//
// Scenario: Enumerate gateway addresses (may not exist in all environments).
// Code path: CxPlatDataPathGetGatewayAddresses -> GetAdaptersAddresses with GAA_FLAG_INCLUDE_GATEWAYS.
// Assertions: Returns success or QUIC_STATUS_NOT_FOUND.
//
void
QuicTestDataPathGetGatewayAddresses(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR* GatewayAddresses = nullptr;
    uint32_t GatewayAddressCount = 0;

    QUIC_STATUS Status =
        CxPlatDataPathGetGatewayAddresses(
            Datapath, &GatewayAddresses, &GatewayAddressCount);
    TEST_TRUE(QUIC_SUCCEEDED(Status) || Status == QUIC_STATUS_NOT_FOUND);

    if (QUIC_SUCCEEDED(Status) && GatewayAddresses != nullptr) {
        CXPLAT_FREE(GatewayAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }
}

//
// =========================================================================
// Category 5: UDP Socket Lifecycle
// Coupling: Public API only. Tests socket creation, binding, and queries.
// =========================================================================
//

//
// Scenario: Create a server socket with no local/remote address.
// Code path: SocketCreateUdp — wildcard bind path.
// Assertions: Socket creation succeeds (via UdpSocketScope).
//             Assigned port is non-zero; address is valid.
//
void
QuicTestDataPathUdpServerSocket(
    )
{
    DatapathScope Datapath;

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR LocalAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &LocalAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&LocalAddr));
    TEST_TRUE(QuicAddrIsValid(&LocalAddr));
}

//
// Scenario: Create a client socket with a remote address (connected UDP).
// Code path: SocketCreateUdp — connect path with HasFixedRemoteAddress=TRUE.
// Assertions: Socket creation succeeds.
//
void
QuicTestDataPathUdpClientSocket(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 9999, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

//
// Scenario: Query the OS-assigned local address after socket creation.
// Code path: CxPlatSocketGetLocalAddress -> getsockname.
// Assertions: Assigned port is non-zero.
//
void
QuicTestDataPathUdpGetLocalAddress(
    )
{
    DatapathScope Datapath;

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR LocalAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &LocalAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&LocalAddr));
}

//
// Scenario: Query remote address on a connected UDP socket.
// Code path: CxPlatSocketGetRemoteAddress -> getpeername.
// Assertions: Remote port equals the specified 8888.
//
void
QuicTestDataPathUdpGetRemoteAddress(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 8888, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR RetrievedRemote = {};
    CxPlatSocketGetRemoteAddress(Socket, &RetrievedRemote);
    TEST_EQUAL(8888, QuicAddrGetPort(&RetrievedRemote));
}

//
// Scenario: Query local MTU for a route.
// Code path: CxPlatSocketGetLocalMtu.
// Assertions: MTU is at least 1280 (minimum IPv6 MTU).
//
void
QuicTestDataPathUdpGetMtu(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 7777, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    uint16_t Mtu = CxPlatSocketGetLocalMtu(Socket, &Route);
    TEST_TRUE(Mtu >= 1280);
}

//
// Scenario: Bind a UDP socket to an explicit IPv4 loopback address.
// Code path: SocketCreateUdp — explicit local address bind.
// Assertions: Bound port is non-zero; address family is INET.
//
void
QuicTestDataPathUdpBindV4(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&BoundAddr));
}

//
// Scenario: Bind a UDP socket to an explicit IPv6 loopback address.
// Code path: SocketCreateUdp — IPv6 bind path.
// Assertions: Bound port is non-zero; address family is INET6.
//
void
QuicTestDataPathUdpBindV6(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("::1", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&BoundAddr));
}

//
// Scenario: Create a UDP socket with CXPLAT_SOCKET_FLAG_PCP.
// Code path: SocketCreateUdp — PCP flag handling.
// Assertions: Socket creation succeeds.
//
void
QuicTestDataPathUdpPcpSocket(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 5351, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_PCP;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

//
// Scenario: Create a server socket bound to [::] (wildcard IPv6).
// Code path: SocketCreateUdp — IPv6 wildcard dual-stack bind.
// Assertions: Bound port is non-zero.
//
void
QuicTestDataPathServerSocketV6(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("::", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
}

//
// Scenario: Create a UDP socket with CXPLAT_SOCKET_FLAG_SHARE (SO_REUSEADDR).
// Code path: SocketCreateUdp — SO_REUSEADDR setsockopt.
// Assertions: Socket creation succeeds.
//
void
QuicTestDataPathUdpShareFlag(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_SHARE;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

//
// Scenario: Bind to a specific high port number.
// Code path: SocketCreateUdp — explicit port bind.
// Assertions: If port is available, bound port equals the requested port.
//
void
QuicTestDataPathUdpBindSpecificPort(
    )
{
    DatapathScope Datapath;

    const uint16_t SpecificPort = 49152 + (uint16_t)(CxPlatCurThreadID() % 1000);

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", SpecificPort, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    QUIC_STATUS Status =
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket);
    if (QUIC_SUCCEEDED(Status)) {
        QUIC_ADDR BoundAddr = {};
        CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
        TEST_EQUAL(SpecificPort, QuicAddrGetPort(&BoundAddr));
        CxPlatSocketDelete(Socket);
    }
}

//
// Scenario: Create a socket with both explicit local and remote addresses.
// Code path: SocketCreateUdp — bind + connect combined path.
// Assertions: Local port is non-zero; local family is INET; remote port equals 9999.
//
void
QuicTestDataPathUdpSocketWithLocalAndRemote(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 9999, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundLocal = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundLocal);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundLocal));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&BoundLocal));

    QUIC_ADDR BoundRemote = {};
    CxPlatSocketGetRemoteAddress(Socket, &BoundRemote);
    TEST_EQUAL(9999, QuicAddrGetPort(&BoundRemote));
}

//
// =========================================================================
// Category 6: Send Data Management
// Coupling: Public API only. Tests send buffer alloc/free/query lifecycle.
// =========================================================================
//

//
// Scenario: Allocate and free send data context without sending.
// Code path: SendDataAlloc + SendDataAllocBuffer + IsFull + SendDataFree pool operations.
// Assertions: Allocation succeeds (via SendDataScope); send data is not yet full;
//             buffer allocation produces non-null buffer with sufficient length.
//
void
QuicTestDataPathSendDataAllocFree(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);
    TEST_EQUAL(FALSE, (BOOLEAN)CxPlatSendDataIsFull(SendData));

    //
    // Allocate a buffer and verify it is usable.
    //
    const uint16_t BufferSize = 100;
    QUIC_BUFFER* Buffer =
        CxPlatSendDataAllocBuffer(SendData, BufferSize);
    TEST_NOT_EQUAL(nullptr, Buffer);
    TEST_NOT_EQUAL(nullptr, Buffer->Buffer);
    TEST_TRUE(Buffer->Length >= BufferSize);
}

//
// Scenario: Allocate a packet buffer from send data.
// Code path: SendDataAllocBuffer -> CxPlatSendDataAllocPacketBuffer.
// Assertions: Buffer pointer is non-null; buffer data pointer is non-null; buffer length >= requested.
//
void
QuicTestDataPathSendDataAllocBuffer(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
    TEST_NOT_EQUAL(nullptr, Buffer);
    TEST_NOT_EQUAL(nullptr, Buffer->Buffer);
    TEST_TRUE(Buffer->Length >= 100);
}

//
// Scenario: Allocate then free a send buffer.
// Code path: SendDataAllocBuffer + SendDataFreeBuffer.
// Assertions: Alloc succeeds; free does not crash.
//
void
QuicTestDataPathSendDataFreeBuffer(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
    TEST_NOT_EQUAL(nullptr, Buffer);

    CxPlatSendDataFreeBuffer(SendData, Buffer);
}

//
// Scenario: Check IsFull before and after allocating a max-sized buffer.
// Code path: SendDataIsFull — checks WsaBufferCount vs MaxSendBatchSize.
// Assertions: Not full initially (FALSE); full after one max buffer on non-segmented (TRUE), not full on segmented (FALSE).
//
void
QuicTestDataPathSendDataIsFull(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    TEST_EQUAL(FALSE, (BOOLEAN)CxPlatSendDataIsFull(SendData));

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 1200);
    TEST_NOT_EQUAL(nullptr, Buffer);

    if (HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        TEST_EQUAL(FALSE, (BOOLEAN)CxPlatSendDataIsFull(SendData));
    } else {
        TEST_EQUAL(TRUE, (BOOLEAN)CxPlatSendDataIsFull(SendData));
    }
}

//
// Scenario: Allocate multiple small buffers sequentially.
// Code path: SendDataAllocBuffer — repeated alloc/finalize cycle.
// Assertions: At least one allocation succeeds.
//
void
QuicTestDataPathSendDataAllocMultiple(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    int AllocCount = 0;
    for (int i = 0; i < 5; i++) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
        if (Buffer == nullptr) {
            break;
        }
        memset(Buffer->Buffer, (uint8_t)i, 100);
        AllocCount++;
    }
    TEST_TRUE(AllocCount >= 1);
}

//
// Scenario: Allocate segmented send buffers (requires SEND_SEGMENTATION).
// Code path: SendDataAllocBuffer -> CxPlatSendDataAllocSegmentBuffer.
// Assertions: At least one segment allocation succeeds.
//
void
QuicTestDataPathSendDataSegmented(
    )
{
    DatapathScope Datapath;

    if (!HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        return;
    }

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    int AllocCount = 0;
    for (int i = 0; i < 5; i++) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
        if (Buffer == nullptr) {
            break;
        }
        memset(Buffer->Buffer, (uint8_t)i, 100);
        AllocCount++;
    }
    TEST_TRUE(AllocCount >= 1);
}

//
// Scenario: Allocate and free a buffer in segmented mode.
// Code path: SendDataAllocBuffer (segmented) + SendDataFreeBuffer.
// Assertions: Alloc succeeds; free does not crash.
//
void
QuicTestDataPathSendDataFreeBufferSegmented(
    )
{
    DatapathScope Datapath;

    if (!HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        return;
    }

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
    TEST_NOT_EQUAL(nullptr, Buffer);

    CxPlatSendDataFreeBuffer(SendData, Buffer);
}

//
// Scenario: Fill a segmented send data until IsFull returns TRUE.
// Code path: SendDataIsFull + CxPlatSendDataCanAllocSendSegment capacity check.
// Assertions: Initially not full; after filling, at least one allocation succeeded.
//
void
QuicTestDataPathSendDataIsFullSegmented(
    )
{
    DatapathScope Datapath;

    if (!HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        return;
    }

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    TEST_EQUAL(FALSE, (BOOLEAN)CxPlatSendDataIsFull(SendData));

    int AllocCount = 0;
    while (!CxPlatSendDataIsFull(SendData) && AllocCount < 500) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 200);
        if (Buffer == nullptr) {
            break;
        }
        memset(Buffer->Buffer, (uint8_t)AllocCount, 200);
        AllocCount++;
    }
    TEST_TRUE(AllocCount > 0);
}

//
// =========================================================================
// Category 7: Send/Receive Validation
// Coupling: Public API only. Tests end-to-end loopback payload delivery.
// =========================================================================
//

//
// Scenario: Fire-and-forget UDP send through the loopback without recv verification.
// Code path: CxPlatSocketSend -> CxPlatSocketSendInline — WSASendMsg on connected socket.
// Assertions: Send completes without crash; server port is non-zero.
//
void
QuicTestDataPathUdpSendLoopback(
    )
{
    DatapathScope Datapath;

    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope ServerSocket(Datapath, &ServerConfig);

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope ClientSocket(Datapath, &ClientConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    const uint16_t PayloadSize = 64;
    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadSize, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(ClientSocket, &SendConfig);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadSize);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memset(Buffer->Buffer, 0xAB, PayloadSize);

    CxPlatSocketSend(ClientSocket, &Route, SendData.release());
    CxPlatSleep(100);
}

//
// Scenario: End-to-end UDP send/receive loopback with payload verification (parameterized for v4/v6).
// Code path: Full send path (CxPlatSocketSend) + recv completion (CxPlatDataPathUdpRecvComplete) + callback.
// Assertions: Receive event fires within 2s; Received flag is TRUE; received length equals sent length; payload bytes match exactly.
//
void
QuicTestDataPathUdpSendRecvLoopback(
    const FamilyArgs& Params
    )
{
    const char* Addr = (Params.Family == 4) ? "127.0.0.1" : "::1";

    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, Addr);

    const uint8_t TestPayload[] = "DatapathWinUserTest";
    SendAndVerifyPayload(&Ctx, TestPayload, sizeof(TestPayload));

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Calling CxPlatRecvDataReturn with NULL is a safe no-op.
// Code path: RecvDataReturn NULL guard.
// Assertions: No crash.
//
void
QuicTestDataPathRecvDataReturnNull(
    )
{
    CxPlatRecvDataReturn(nullptr);
}

//
// TcpTestScope manages TCP datapath lifecycle with correct cleanup ordering.
// CxPlatDataPathUninitialize is non-blocking — it returns immediately without
// draining pending IO. We must sleep after socket deletion to let async IO
// completions (especially on accepted sockets) finish before destroying
// events that callbacks may reference.
//
// Cleanup order: sockets → sleep(200ms) → datapath uninit → events.
//
struct TcpTestScope {
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Listener = nullptr;
    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_EVENT AcceptEvent = {};
    CXPLAT_EVENT ConnectEvent = {};
    bool HasEvents = false;

    //
    // Initialize TCP datapath with default callbacks. Returns false if TCP
    // is not supported or init fails (caller should return from test).
    //
    bool
    Init(
        _In_ bool WithEvents = true
        )
    {
        HasEvents = WithEvents;
        if (HasEvents) {
            CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
            CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);
        }
        CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
        QUIC_STATUS Status =
            CxPlatDataPathInitialize(
                0, &DefaultUdpCallbacks, &DefaultTcpCallbacks, WorkerPool, &InitConfig, &Datapath);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("CxPlatDataPathInitialize failed, 0x%x", Status);
            return false;
        }
        return HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_TCP);
    }

    //
    // Create a TCP listener on the given loopback address. The listener's
    // context is set to &AcceptEvent if events are enabled, nullptr otherwise.
    //
    void
    CreateListenerOnLoopback(
        _In_ const char* Addr
        )
    {
        uint16_t Port = 0;
        CreateTcpListenerOnLoopback(
            Datapath, Addr, HasEvents ? &AcceptEvent : nullptr, &Listener, &Port);
    }

    //
    // Get the listener's bound port. Returns 0 if no listener.
    //
    uint16_t
    GetListenerPort(
        )
    {
        if (!Listener) return 0;
        QUIC_ADDR BoundAddr = {};
        CxPlatSocketGetLocalAddress(Listener, &BoundAddr);
        return QuicAddrGetPort(&BoundAddr);
    }

    //
    // Connect a TCP client to the listener address. Returns QUIC_STATUS.
    //
    QUIC_STATUS
    ConnectClient(
        _In_ const char* Addr,
        _In_opt_ const QUIC_ADDR* LocalAddr = nullptr
        )
    {
        QUIC_ADDR RemoteAddr = {};
        QuicAddrFromString(Addr, GetListenerPort(), &RemoteAddr);
        return CxPlatSocketCreateTcp(
            Datapath, LocalAddr, &RemoteAddr,
            HasEvents ? &ConnectEvent : nullptr, &ClientSocket);
    }

    //
    // Wait for connect and accept events to fire.
    //
    void
    WaitForConnect(
        _In_ uint32_t TimeoutMs = 2000
        )
    {
        if (HasEvents) {
            CxPlatEventWaitWithTimeout(ConnectEvent, TimeoutMs);
            CxPlatEventWaitWithTimeout(AcceptEvent, TimeoutMs);
        }
    }

    ~TcpTestScope() {
        if (ClientSocket) { CxPlatSocketDelete(ClientSocket); ClientSocket = nullptr; }
        if (Listener) { CxPlatSocketDelete(Listener); Listener = nullptr; }
        CxPlatSleep(500);
        if (Datapath) { CxPlatDataPathUninitialize(Datapath); Datapath = nullptr; }
        if (HasEvents) {
            CxPlatEventUninitialize(ConnectEvent);
            CxPlatEventUninitialize(AcceptEvent);
        }
    }
};

//
// =========================================================================
// Category 8: TCP Socket Operations
// Coupling: Public API. Skips if CXPLAT_DATAPATH_FEATURE_TCP unavailable.
// =========================================================================
//

//
// Scenario: Create a TCP listener socket.
// Code path: SocketCreateTcpListener -> CxPlatSocketCreateTcpInternal with IsServer=TRUE.
// Assertions: Listener pointer is non-null; bound port is non-zero.
//
void
QuicTestDataPathTcpListener(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init(false)) return;

    Tcp.CreateListenerOnLoopback("127.0.0.1");
    TEST_NOT_EQUAL(nullptr, Tcp.Listener);
    TEST_NOT_EQUAL(0, Tcp.GetListenerPort());
}

//
// Scenario: Create a TCP client socket connecting to a listener.
// Code path: SocketCreateTcp -> CxPlatSocketCreateTcpInternal with ConnectEx.
// Assertions: If connection succeeds, client socket is non-null.
//
void
QuicTestDataPathTcpClient(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init(false)) return;

    Tcp.CreateListenerOnLoopback("127.0.0.1");

    QUIC_STATUS Status = Tcp.ConnectClient("127.0.0.1");
    if (QUIC_SUCCEEDED(Status)) {
        TEST_NOT_EQUAL(nullptr, Tcp.ClientSocket);
    }
}

//
// Scenario: Full TCP connect handshake with event-based completion.
// Code path: SocketCreateTcp -> ConnectEx -> CxPlatDataPathSocketProcessConnectCompletion.
// Assertions: Connect succeeds; connect and accept events fire within 2s.
//
void
QuicTestDataPathTcpConnect(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init()) return;

    Tcp.CreateListenerOnLoopback("127.0.0.1");

    QUIC_STATUS Status = Tcp.ConnectClient("127.0.0.1");
    TEST_QUIC_SUCCEEDED(Status);
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.ConnectEvent, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.AcceptEvent, 2000));
    TEST_NOT_EQUAL(nullptr, Tcp.ClientSocket);
}

//
// Scenario: TCP connect over IPv6 loopback.
// Code path: CxPlatSocketCreateTcpInternal — AF_INET6 socket creation + ConnectEx.
// Assertions: Connect succeeds; connect and accept events fire within 2s.
//
void
QuicTestDataPathTcpConnectV6(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init()) return;

    Tcp.CreateListenerOnLoopback("::1");

    TEST_QUIC_SUCCEEDED(Tcp.ConnectClient("::1"));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.ConnectEvent, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.AcceptEvent, 2000));
    TEST_NOT_EQUAL(nullptr, Tcp.ClientSocket);
}

//
// Scenario: Query TCP statistics on a connected socket.
// Code path: CxPlatSocketGetTcpStatistics -> WSAIoctl SIO_TCP_INFO.
// Assertions: If statistics query succeeds, MSS > 0.
//
void
QuicTestDataPathTcpStatistics(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init()) return;

    Tcp.CreateListenerOnLoopback("127.0.0.1");

    TEST_QUIC_SUCCEEDED(Tcp.ConnectClient("127.0.0.1"));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.ConnectEvent, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.AcceptEvent, 2000));

    CXPLAT_TCP_STATISTICS Stats = {};
    QUIC_STATUS StatsStatus =
        CxPlatSocketGetTcpStatistics(Tcp.ClientSocket, &Stats);
    if (QUIC_SUCCEEDED(StatsStatus)) {
        TEST_TRUE(Stats.Mss > 0);
    }
}

//
// Scenario: Send data over a connected TCP socket and verify server receives it.
// Code path: CxPlatSocketSend (TCP branch — WSASend) + TCP recv completion.
// Assertions: Connect/accept events fire; send data allocation succeeds; server receives payload.
//
void
QuicTestDataPathTcpSendRecv(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestTcpRecvContext TcpRecvCtx = {};
    CxPlatEventInitialize(&TcpRecvCtx.RecvEvent, FALSE, FALSE);

    DatapathTestTcpAcceptRecvContext AcceptCtx = {};
    CxPlatEventInitialize(&AcceptCtx.AcceptEvent, FALSE, FALSE);
    AcceptCtx.RecvCtx = &TcpRecvCtx;

    CXPLAT_EVENT ConnectEvent;
    CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallbackWithRecv,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallbackWithContext,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    if (!HasFeature(Datapath, CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        CxPlatEventUninitialize(TcpRecvCtx.RecvEvent);
        CxPlatEventUninitialize(AcceptCtx.AcceptEvent);
        CxPlatEventUninitialize(ConnectEvent);
        return;
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptCtx, &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent, &ClientSocket);

    if (QUIC_SUCCEEDED(Status)) {
        TEST_TRUE(CxPlatEventWaitWithTimeout(ConnectEvent, 2000));
        TEST_TRUE(CxPlatEventWaitWithTimeout(AcceptCtx.AcceptEvent, 2000));

        const uint8_t Payload[] = "TcpSendRecvTest";
        const uint16_t PayloadLen = sizeof(Payload);

        CXPLAT_ROUTE Route = {};
        CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
        Route.RemoteAddress = RemoteAddr;

        CXPLAT_SEND_CONFIG SendConfig = {
            &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
        };
        CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
        TEST_NOT_EQUAL(nullptr, SendData);

        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
        TEST_NOT_EQUAL(nullptr, Buffer);
        memcpy(Buffer->Buffer, Payload, PayloadLen);

        CxPlatSocketSend(ClientSocket, &Route, SendData);

        TEST_TRUE(CxPlatEventWaitWithTimeout(TcpRecvCtx.RecvEvent, 2000));

        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSocketDelete(Listener);
    CxPlatSleep(500);
    CxPlatDataPathUninitialize(Datapath);
    CxPlatEventUninitialize(ConnectEvent);
    CxPlatEventUninitialize(AcceptCtx.AcceptEvent);
    CxPlatEventUninitialize(TcpRecvCtx.RecvEvent);
}

//
// Scenario: Connect then immediately disconnect to exercise cleanup paths.
// Code path: CxPlatSocketCreateTcp -> immediate CxPlatSocketDelete -> CxPlatSocketContextUninitialize.
// Assertions: Connect succeeds; connect/accept events fire within 2s; immediate delete does not crash.
//
void
QuicTestDataPathTcpConnectDisconnect(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init()) return;

    Tcp.CreateListenerOnLoopback("127.0.0.1");

    TEST_QUIC_SUCCEEDED(Tcp.ConnectClient("127.0.0.1"));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.ConnectEvent, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.AcceptEvent, 2000));
    // Destructor handles immediate cleanup — tests that delete doesn't crash.
}

//
// Scenario: Create TCP client with explicit local address binding.
// Code path: CxPlatSocketCreateTcpInternal — local address bind branch.
// Assertions: Connect succeeds; events fire; local port is non-zero.
//
void
QuicTestDataPathTcpCreateWithLocalAddr(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init()) return;

    Tcp.CreateListenerOnLoopback("127.0.0.1");

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    TEST_QUIC_SUCCEEDED(Tcp.ConnectClient("127.0.0.1", &LocalAddr));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.ConnectEvent, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Tcp.AcceptEvent, 2000));

    QUIC_ADDR ClientLocalAddr = {};
    CxPlatSocketGetLocalAddress(Tcp.ClientSocket, &ClientLocalAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&ClientLocalAddr));
}

//
// Scenario: Create a TCP listener on IPv6.
// Code path: CxPlatSocketCreateTcpInternal — AF_INET6 listener path.
// Assertions: Listener non-null; port non-zero; family is INET6.
//
void
QuicTestDataPathTcpListenerV6(
    )
{
    TcpTestScope Tcp;
    if (!Tcp.Init(false)) return;

    Tcp.CreateListenerOnLoopback("::1");
    TEST_NOT_EQUAL(nullptr, Tcp.Listener);
    TEST_NOT_EQUAL(0, Tcp.GetListenerPort());

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Tcp.Listener, &BoundAddr);
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&BoundAddr));
}

//
// =========================================================================
// Category 9: DataPath Lifecycle
// Coupling: Public API only. Tests full init-use-cleanup sequences.
// =========================================================================
//

//
// Scenario: Update polling idle timeout with various values.
// Code path: DataPathUpdatePollingIdleTimeout — no-op on Windows.
// Assertions: No crash with values 0, 1000, UINT32_MAX.
//
void
QuicTestDataPathUpdateIdleTimeout(
    )
{
    DatapathScope Datapath;

    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, 0);
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, 1000);
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, UINT32_MAX);
}

//
// =========================================================================
// Category 10: Extended Integration Tests
// Coupling: Public API. Exercises ECN, DSCP, IPv6, segmentation, and
//           multi-send paths. Some tests skip if features are unavailable.
// =========================================================================
//

//
// Scenario: Send with ECN_ECT_0 marking on IPv4.
// Code path: CxPlatSocketSendInline — IP_ECN cmsg construction.
// Assertions: Payload received matches sent exactly.
//
void
QuicTestDataPathSendWithEcn(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    const uint8_t Payload[] = "EcnTest";
    SendAndVerifyPayload(&Ctx, Payload, sizeof(Payload), CXPLAT_ECN_ECT_0);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send with DSCP_EF marking on IPv4.
// Code path: CxPlatSocketSendInline — IP_TOS cmsg with DSCP<<2.
// Assertions: Payload received matches sent exactly.
//
void
QuicTestDataPathSendWithDscp(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    if (!HasFeature(Ctx.Datapath, CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        TeardownUdpLoopback(&Ctx);
        return;
    }

    const uint8_t Payload[] = "DscpTest";
    SendAndVerifyPayload(
        &Ctx, Payload, sizeof(Payload),
        CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_EF);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Basic send/receive over IPv6 loopback.
// Code path: CxPlatSocketSendInline — IPv6 branch.
// Assertions: Payload matches.
//
void
QuicTestDataPathSendRecvV6(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "::1");

    const uint8_t Payload[] = "IPv6Test";
    SendAndVerifyPayload(&Ctx, Payload, sizeof(Payload));

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send with MAX_THROUGHPUT flag.
// Code path: CxPlatSocketSendInline with CXPLAT_SEND_FLAGS_MAX_THROUGHPUT.
// Assertions: Payload matches.
//
void
QuicTestDataPathSendWithMaxThroughput(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    const uint8_t Payload[] = "MaxThroughputTest";
    SendAndVerifyPayload(
        &Ctx, Payload, sizeof(Payload),
        CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_MAX_THROUGHPUT);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send with DSCP on IPv6.
// Code path: CxPlatSocketSendInline — IPV6_TCLASS cmsg.
// Assertions: Payload matches.
//
void
QuicTestDataPathSendRecvDscpV6(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "::1");

    if (!HasFeature(Ctx.Datapath, CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        TeardownUdpLoopback(&Ctx);
        return;
    }

    const uint8_t Payload[] = "DscpV6Test";
    SendAndVerifyPayload(
        &Ctx, Payload, sizeof(Payload),
        CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_EF);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send with ECN on IPv6.
// Code path: CxPlatSocketSendInline — IPV6_ECN cmsg.
// Assertions: Payload matches.
//
void
QuicTestDataPathSendWithEcnV6(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "::1");

    const uint8_t Payload[] = "EcnV6Test";
    SendAndVerifyPayload(&Ctx, Payload, sizeof(Payload), CXPLAT_ECN_ECT_0);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send 3 UDP packets in sequence over loopback.
// Code path: CxPlatSocketSend called 3 times — exercises repeated send completion.
// Assertions: At least one packet received.
//
void
QuicTestDataPathMultipleSendRecv(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    for (int i = 0; i < 3; i++) {
        const uint8_t Payload[] = "MultiSend";
        const uint16_t PayloadLen = sizeof(Payload);

        CXPLAT_SEND_CONFIG SendConfig = {
            &Ctx.Route, PayloadLen, CXPLAT_ECN_NON_ECT,
            CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
        };
        CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Ctx.ClientSocket, &SendConfig);
        TEST_NOT_EQUAL(nullptr, SendData);

        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
        TEST_NOT_EQUAL(nullptr, Buffer);
        memcpy(Buffer->Buffer, Payload, PayloadLen);

        CxPlatSocketSend(Ctx.ClientSocket, &Ctx.Route, SendData);
        CxPlatSleep(50);
    }

    TEST_TRUE(CxPlatEventWaitWithTimeout(Ctx.RecvCtx.RecvEvent, 2000));
    TEST_EQUAL(TRUE, (BOOLEAN)Ctx.RecvCtx.Received);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: IPv4 client sends to a dual-stack (wildcard) server socket.
// Code path: SocketCreateUdp with no LocalAddress -> dual-stack; recv from v4 client.
// Assertions: Payload matches exactly.
//
void
QuicTestDataPathUdpDualStack(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Server with no local address defaults to dual-stack IPv6.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DualStackTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_EQUAL(TRUE, (BOOLEAN)RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_EQUAL(0, memcmp(RecvCtx.RecvBuf, Payload, PayloadLen));

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

//
// Scenario: Send 512-byte payload (near typical MTU).
// Code path: CxPlatSocketSendInline with large buffer.
// Assertions: Full payload received and matches.
//
void
QuicTestDataPathSendLargePayload(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    uint8_t LargePayload[512];
    memset(LargePayload, 0xCD, sizeof(LargePayload));
    SendAndVerifyPayload(&Ctx, LargePayload, sizeof(LargePayload));

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Create sockets with DSCP recv enabled on both v4 and v6.
// Code path: SocketCreateUdp — IP_RECVTOS/IPV6_RECVTCLASS setsockopt.
// Assertions: Both sockets created successfully; v4 port is non-zero.
//
void
QuicTestDataPathInitDscpRecvDscpSocket(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    InitConfig.EnableDscpOnRecv = TRUE;
    DatapathScope Datapath(0, nullptr, InitConfig);

    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));

    QUIC_ADDR LocalAddrV6 = {};
    QuicAddrFromString("::1", 0, &LocalAddrV6);

    CXPLAT_UDP_CONFIG UdpConfigV6 = {};
    UdpConfigV6.LocalAddress = &LocalAddrV6;
    UdpConfigV6.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope SocketV6(Datapath, &UdpConfigV6);
}

//
// =========================================================================
// Category 11: Server-Send and Advanced Scenarios
// Coupling: Public API. Tests non-fixed-remote sends, combined ECN+DSCP,
//           TCP with local addr, segmented over-wire, and DSCP recv paths.
// =========================================================================
//

//
// Scenario: Server socket (no fixed remote) sends to a specific receiver on IPv4.
// Code path: CxPlatSocketSendInline — !HasFixedRemoteAddress branch -> IN_PKTINFO cmsg.
// Assertions: Payload matches.
//
void
QuicTestDataPathServerSendToRemote(
    )
{
    ServerSendContext Ctx = {};
    SetupServerSend(&Ctx, "127.0.0.1");

    const uint8_t Payload[] = "ServerSendTest";
    ServerSendAndVerify(&Ctx, Payload, sizeof(Payload));

    TeardownServerSend(&Ctx);
}

//
// Scenario: Server socket sends to receiver on IPv6.
// Code path: CxPlatSocketSendInline — IPV6_PKTINFO cmsg.
// Assertions: Payload matches.
//
void
QuicTestDataPathServerSendToRemoteV6(
    )
{
    ServerSendContext Ctx = {};
    SetupServerSend(&Ctx, "::1");

    const uint8_t Payload[] = "ServerSendV6";
    ServerSendAndVerify(&Ctx, Payload, sizeof(Payload));

    TeardownServerSend(&Ctx);
}

//
// Scenario: Send with both ECN and DSCP set on IPv4.
// Code path: CxPlatSocketSendInline — combined IP_TOS = ECN|(DSCP<<2).
// Assertions: Payload matches.
//
void
QuicTestDataPathSendEcnAndDscp(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    if (!HasFeature(Ctx.Datapath, CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        TeardownUdpLoopback(&Ctx);
        return;
    }

    const uint8_t Payload[] = "EcnDscpCombo";
    SendAndVerifyPayload(
        &Ctx, Payload, sizeof(Payload),
        CXPLAT_ECN_ECT_0, CXPLAT_SEND_FLAGS_NONE, 10);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send with both ECN and DSCP on IPv6.
// Code path: CxPlatSocketSendInline — combined IPV6_TCLASS.
// Assertions: Payload matches.
//
void
QuicTestDataPathSendEcnAndDscpV6(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "::1");

    if (!HasFeature(Ctx.Datapath, CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        TeardownUdpLoopback(&Ctx);
        return;
    }

    const uint8_t Payload[] = "EcnDscpV6";
    SendAndVerifyPayload(
        &Ctx, Payload, sizeof(Payload),
        CXPLAT_ECN_ECT_1, CXPLAT_SEND_FLAGS_NONE, 10);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Segmented send over the wire with UDP_SEND_MSG_SIZE.
// Code path: CxPlatSocketSendInline — SegmentSize>0 branch -> UDP_SEND_MSG_SIZE cmsg.
// Assertions: At least one segment received.
//
void
QuicTestDataPathSegmentedSendOverWire(
    )
{
    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1");

    if (!HasFeature(Ctx.Datapath, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        TeardownUdpLoopback(&Ctx);
        return;
    }

    const uint16_t SegmentSize = 100;
    CXPLAT_SEND_CONFIG SendConfig = {
        &Ctx.Route, SegmentSize, CXPLAT_ECN_NON_ECT,
        CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Ctx.ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer1 = CxPlatSendDataAllocBuffer(SendData, SegmentSize);
    TEST_NOT_EQUAL(nullptr, Buffer1);
    memset(Buffer1->Buffer, 0xAA, SegmentSize);

    QUIC_BUFFER* Buffer2 = CxPlatSendDataAllocBuffer(SendData, SegmentSize);
    if (Buffer2 != nullptr) {
        memset(Buffer2->Buffer, 0xBB, SegmentSize);
    }

    CxPlatSocketSend(Ctx.ClientSocket, &Ctx.Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(Ctx.RecvCtx.RecvEvent, 2000));
    TEST_EQUAL(TRUE, (BOOLEAN)Ctx.RecvCtx.Received);

    TeardownUdpLoopback(&Ctx);
}

//
// Scenario: Send/receive with DSCP recv enabled to exercise DSCP extraction on receive.
// Code path: DataPathInitialize with EnableDscpOnRecv + SocketCreateUdp with IP_RECVTOS + CxPlatDataPathUdpRecvComplete DSCP extraction.
// Assertions: Payload matches.
//
void
QuicTestDataPathDscpRecvSendRecv(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG Config = {};
    Config.EnableDscpOnRecv = TRUE;

    UdpLoopbackContext Ctx = {};
    SetupUdpLoopback(&Ctx, "127.0.0.1", &Config);

    const uint8_t Payload[] = "DscpRecvTest";
    SendAndVerifyPayload(&Ctx, Payload, sizeof(Payload));

    TeardownUdpLoopback(&Ctx);
}
