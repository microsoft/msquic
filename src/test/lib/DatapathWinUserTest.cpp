/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests for the Windows user-mode datapath layer (datapath_winuser.c).
    Exercises CxPlat* datapath APIs: initialization, feature queries, address
    resolution, socket creation/deletion, send/receive, and lifecycle management.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "DatapathWinUserTest.cpp.clog.h"
#endif

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

    //
    // UDP-only with default config.
    //
    DatapathScope() {
        CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
        TEST_QUIC_SUCCEEDED(
            CxPlatDataPathInitialize(
                0, &DefaultUdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));
    }

    //
    // UDP + TCP with default config.
    //
    explicit DatapathScope(const CXPLAT_TCP_DATAPATH_CALLBACKS& TcpCallbacks) {
        CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
        TEST_QUIC_SUCCEEDED(
            CxPlatDataPathInitialize(
                0, &DefaultUdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));
    }

    //
    // Custom init config (e.g., EnableDscpOnRecv, ClientRecvContextLength).
    //
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
        if (Datapath) {
            CxPlatDataPathUninitialize(Datapath);
        }
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
        if (Socket) {
            CxPlatSocketDelete(Socket);
        }
    }

    CXPLAT_SOCKET* get() const { return Socket; }
    operator CXPLAT_SOCKET*() const { return Socket; }
};

struct TcpSocketScope {
    CXPLAT_SOCKET* Socket = nullptr;
    bool Owned = true;

    TcpSocketScope() = default;

    ~TcpSocketScope() {
        if (Socket && Owned) {
            CxPlatSocketDelete(Socket);
        }
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
        if (SendData) {
            CxPlatSendDataFree(SendData);
        }
    }

    CXPLAT_SEND_DATA* get() const { return SendData; }
    operator CXPLAT_SEND_DATA*() const { return SendData; }

    //
    // Release ownership (e.g., when consumed by CxPlatSocketSend).
    //
    CXPLAT_SEND_DATA* release() {
        CXPLAT_SEND_DATA* Tmp = SendData;
        SendData = nullptr;
        return Tmp;
    }
};

//
// =========================================================================
// Category 1: Spec-Conformance — Initialization Validation
// Coupling: Public API only. Tests precondition checks per API contract.
// =========================================================================
//

void
QuicTestDataPathInitUdp(
    )
{
    DatapathScope Datapath;
}

void
QuicTestDataPathInitUdpTcp(
    )
{
    DatapathScope Datapath(DefaultTcpCallbacks);
}

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
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            nullptr));
}

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
            0,
            &UdpCallbacks,
            nullptr,
            nullptr,
            &InitConfig,
            &Datapath));
}

void
QuicTestDataPathInitUdpMissingRecv(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {};
    UdpCallbacks.Unreachable = DatapathTestUdpUnreachCallback;
    // Receive is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            &Datapath));
}

void
QuicTestDataPathInitUdpMissingUnreach(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {};
    UdpCallbacks.Receive = DatapathTestUdpRecvCallbackSimple;
    // Unreachable is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            &Datapath));
}

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
    // Accept is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            &TcpCallbacks,
            WorkerPool,
            &InitConfig,
            &Datapath));
}

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
    // Connect is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            &TcpCallbacks,
            WorkerPool,
            &InitConfig,
            &Datapath));
}

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
    // Receive is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            &TcpCallbacks,
            WorkerPool,
            &InitConfig,
            &Datapath));
}

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
    // SendComplete is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            &TcpCallbacks,
            WorkerPool,
            &InitConfig,
            &Datapath));
}

void
QuicTestDataPathInitDscpOnRecv(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    InitConfig.EnableDscpOnRecv = TRUE;
    DatapathScope Datapath(0, nullptr, InitConfig);
}

//
// =========================================================================
// Category 2: Loosely Coupled — Feature Query
// Coupling: Public API only. Exercises feature enumeration interfaces.
// =========================================================================
//

void
QuicTestDataPathFeatureQuery(
    )
{
    DatapathScope Datapath;

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    //
    // Features is a bitmask. On Windows we expect at least something,
    // but the exact set depends on OS version. Just ensure it's valid
    // (no bits outside defined range).
    //
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

void
QuicTestDataPathIsPaddingPreferred(
    )
{
    DatapathScope Datapath;

    //
    // We need a socket + send data to query IsPaddingPreferred.
    // Create a simple client socket for this purpose.
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrSetFamily(&RemoteAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&RemoteAddr, 12345);
    QuicAddrFromString("127.0.0.1", 12345, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;
    Route.Queue = nullptr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    BOOLEAN IsPadded = CxPlatDataPathIsPaddingPreferred(Datapath, SendData);
    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        //
        // With segmentation, padding is preferred (SegmentSize > 0).
        //
        TEST_TRUE(IsPadded);
    } else {
        //
        // Without segmentation, no padding needed (SegmentSize == 0).
        //
        TEST_FALSE(IsPadded);
    }
}

//
// =========================================================================
// Category 3: Loosely Coupled — Address Resolution
// Coupling: Public API only. Exercises hostname/address resolution paths.
// =========================================================================
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
// =========================================================================
// Category 4: Loosely Coupled — Address Enumeration
// Coupling: Public API only. Exercises local/gateway address enumeration.
// =========================================================================
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
    //
    // Some environments may not have gateways configured.
    // Accept success or not-found.
    //
    TEST_TRUE(QUIC_SUCCEEDED(Status) || Status == QUIC_STATUS_NOT_FOUND);

    if (QUIC_SUCCEEDED(Status) && GatewayAddresses != nullptr) {
        CXPLAT_FREE(GatewayAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }
}

//
// =========================================================================
// Category 5: Loosely Coupled — UDP Socket Lifecycle
// Coupling: Public API only. Tests socket creation, binding, and queries.
// =========================================================================
//

void
QuicTestDataPathUdpServerSocket(
    )
{
    DatapathScope Datapath;

    //
    // Create a "server" socket (no remote address).
    //
    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = nullptr;
    UdpConfig.RemoteAddress = nullptr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

void
QuicTestDataPathUdpClientSocket(
    )
{
    DatapathScope Datapath;

    //
    // Create a "client" socket (with remote address).
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 9999, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

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
    //
    // Should have a valid port assigned.
    //
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&LocalAddr));
}

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
    TEST_TRUE(Mtu >= 1280); // Minimum IPv6 MTU
}

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
    UdpConfig.CallbackContext = nullptr;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

//
// =========================================================================
// Category 6: Loosely Coupled — Send Data Management
// Coupling: Public API only. Tests send buffer alloc/free/query lifecycle.
// =========================================================================
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
}

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

    //
    // Initially the send data should not be full.
    //
    TEST_FALSE(CxPlatSendDataIsFull(SendData));

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 1200);
    TEST_NOT_EQUAL(nullptr, Buffer);

    //
    // After allocating a max-sized buffer, fullness depends on segmentation.
    // Without segmentation: MaxSendBatchSize is 1, so one buffer fills it.
    // With segmentation: large backing buffer has space for more segments.
    //
    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        TEST_FALSE(CxPlatSendDataIsFull(SendData));
    } else {
        TEST_TRUE(CxPlatSendDataIsFull(SendData));
    }
}

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

    //
    // Allocate several small buffers. Assert at least one succeeds.
    //
    int AllocCount = 0;
    for (int i = 0; i < 5; i++) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
        if (Buffer == nullptr) {
            break; // send data may be full
        }
        memset(Buffer->Buffer, (uint8_t)i, 100);
        AllocCount++;
    }
    TEST_TRUE(AllocCount >= 1);
}

void
QuicTestDataPathUdpSendLoopback(
    )
{
    DatapathScope Datapath;

    //
    // Create a server socket to receive.
    //
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

    //
    // Create a client socket pointing to the server.
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope ClientSocket(Datapath, &ClientConfig);

    //
    // Send data from the client socket.
    //
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

    //
    // Brief wait for packet transit.
    //
    CxPlatSleep(100);
}

//
// =========================================================================
// Category 7: Loosely Coupled — Send/Receive Validation
// Coupling: Public API only. Tests end-to-end loopback payload delivery.
// =========================================================================
//

void
QuicTestDataPathUdpSendRecvLoopback(
    const FamilyArgs& Params
    )
{
    int Family = Params.Family;
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
    // Create a server socket.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    if (Family == 4) {
        QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);
    } else {
        QuicAddrFromString("::1", 0, &ServerLocalAddr);
    }

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    //
    // Create a client socket.
    //
    QUIC_ADDR RemoteAddr = {};
    if (Family == 4) {
        QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);
    } else {
        QuicAddrFromString("::1", ServerPort, &RemoteAddr);
    }

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send a test payload.
    //
    const uint8_t TestPayload[] = "DatapathWinUserTest";
    const uint16_t PayloadSize = sizeof(TestPayload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadSize, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadSize);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, TestPayload, PayloadSize);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    //
    // Wait for the receive callback.
    //
    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadSize, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, TestPayload, PayloadSize) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathRecvDataReturn(
    )
{
    //
    // RecvDataReturn is implicitly tested by every recv callback that calls
    // CxPlatRecvDataReturn. This test exercises the path through a full
    // send/receive cycle and ensures the callback's CxPlatRecvDataReturn
    // completes without error.
    //
    FamilyArgs Args = { 4 };
    QuicTestDataPathUdpSendRecvLoopback(Args);
}

//
// =========================================================================
// Category 8: Feature-Dependent — TCP Socket Operations
// Coupling: Public API. Skips if CXPLAT_DATAPATH_FEATURE_TCP unavailable.
// =========================================================================
//

void
QuicTestDataPathTcpListener(
    )
{
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return; // TCP not supported on this platform
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath,
            &ListenerAddr,
            nullptr,
            &Listener));
    TEST_NOT_EQUAL(nullptr, Listener);

    CxPlatSocketDelete(Listener);
}

void
QuicTestDataPathTcpClient(
    )
{
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return; // TCP not supported on this platform
    }

    //
    // Create a listener first so we have somewhere to connect to.
    //
    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath,
            &ListenerAddr,
            nullptr,
            &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    //
    // Create a TCP client socket connecting to the listener.
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    TcpSocketScope ClientSocket;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &RemoteAddr,
            nullptr,
            &ClientSocket.Socket);
    //
    // The connection may succeed or be pending. Either is valid.
    //
    if (QUIC_SUCCEEDED(Status)) {
        TEST_NOT_EQUAL(nullptr, ClientSocket.Socket);
    }

    CxPlatSocketDelete(Listener);
}

void
QuicTestDataPathTcpConnect(
    )
{
    EventScope AcceptEvent;
    EventScope ConnectEvent;
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return;
    }

    //
    // Create listener.
    //
    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath,
            &ListenerAddr,
            &AcceptEvent.Event,
            &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    //
    // Create client.
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    TcpSocketScope ClientSocket;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &RemoteAddr,
            &ConnectEvent.Event,
            &ClientSocket.Socket);

    if (QUIC_SUCCEEDED(Status)) {
        //
        // Wait for connect and accept callbacks.
        //
        CxPlatEventWaitWithTimeout(ConnectEvent.Event, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent.Event, 2000);
    }

    CxPlatSocketDelete(Listener);
}

//
// =========================================================================
// Category 9: Loosely Coupled — DataPath Lifecycle
// Coupling: Public API only. Tests full init-use-cleanup sequences.
// =========================================================================
//

void
QuicTestDataPathFullLifecycle(
    )
{
    //
    // Full lifecycle: init → create socket → send → receive → cleanup.
    //
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
    // Create a server socket.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    //
    // Create a client socket.
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send data.
    //
    const uint8_t Payload[] = "LifecycleTest";
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

    //
    // Wait for receive.
    //
    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    //
    // Clean up in reverse order.
    //
    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUpdateIdleTimeout(
    )
{
    DatapathScope Datapath;

    //
    // This is a no-op on Windows but should not crash.
    //
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, 0);
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, 1000);
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, UINT32_MAX);
}

//
// =========================================================================
// Category 10: Feature-Dependent — Extended Integration Tests
// Coupling: Public API. Exercises ECN, DSCP, IPv6, segmentation, and
//           multi-send paths. Some tests skip if features are unavailable.
// =========================================================================
//

void
QuicTestDataPathSendWithEcn(
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

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "EcnTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_ECT_0, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendWithDscp(
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

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        CxPlatEventUninitialize(RecvCtx.RecvEvent);
        CxPlatDataPathUninitialize(Datapath);
        return; // DSCP send not supported
    }

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DscpTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_EF
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendRecvV6(
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

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "IPv6Test";
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
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathServerSocketV6(
    )
{
    DatapathScope Datapath;

    //
    // Create a "server" socket bound to [::] (wildcard IPv6).
    //
    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("::", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.RemoteAddress = nullptr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
}

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

void
QuicTestDataPathSendWithMaxThroughput(
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

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "MaxThroughputTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_MAX_THROUGHPUT, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendRecvDscpV6(
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

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        CxPlatEventUninitialize(RecvCtx.RecvEvent);
        CxPlatDataPathUninitialize(Datapath);
        return; // DSCP send not supported
    }

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DscpV6Test";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_EF
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendWithEcnV6(
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

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "EcnV6Test";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_ECT_0, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpConnectV6(
    )
{
    EventScope AcceptEvent;
    EventScope ConnectEvent;
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return;
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("::1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent.Event, &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("::1", ListenerPort, &RemoteAddr);

    TcpSocketScope ClientSocket;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent.Event, &ClientSocket.Socket);

    if (QUIC_SUCCEEDED(Status)) {
        CxPlatEventWaitWithTimeout(ConnectEvent.Event, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent.Event, 2000);
    }

    CxPlatSocketDelete(Listener);
}

void
QuicTestDataPathTcpStatistics(
    )
{
    EventScope AcceptEvent;
    EventScope ConnectEvent;
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return;
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent.Event, &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    TcpSocketScope ClientSocket;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent.Event, &ClientSocket.Socket);

    if (QUIC_SUCCEEDED(Status)) {
        TEST_TRUE(CxPlatEventWaitWithTimeout(ConnectEvent.Event, 2000));
        CxPlatEventWaitWithTimeout(AcceptEvent.Event, 2000);

        //
        // Query TCP statistics on the connected client socket.
        //
        CXPLAT_TCP_STATISTICS Stats = {};
        QUIC_STATUS StatsStatus =
            CxPlatSocketGetTcpStatistics(ClientSocket, &Stats);
        if (QUIC_SUCCEEDED(StatsStatus)) {
            TEST_TRUE(Stats.Mss > 0);
        }
    }

    CxPlatSocketDelete(Listener);
}

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

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
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

        //
        // Send data over the TCP client socket.
        //
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

        //
        // Wait for the server to receive the data.
        //
        CxPlatEventWaitWithTimeout(TcpRecvCtx.RecvEvent, 2000);

        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSocketDelete(Listener);
    CxPlatEventUninitialize(TcpRecvCtx.RecvEvent);
    CxPlatEventUninitialize(AcceptCtx.AcceptEvent);
    CxPlatEventUninitialize(ConnectEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpBindSpecificPort(
    )
{
    DatapathScope Datapath;

    //
    // Pick a high port and bind to it explicitly.
    //
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
    //
    // Port may be in use - that's okay, just verify no crash.
    //
}

void
QuicTestDataPathMultipleSendRecv(
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

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    //
    // Send 3 packets in sequence.
    //
    for (int i = 0; i < 3; i++) {
        const uint8_t Payload[] = "MultiSend";
        const uint16_t PayloadLen = sizeof(Payload);

        CXPLAT_SEND_CONFIG SendConfig = {
            &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
        };
        CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
        TEST_NOT_EQUAL(nullptr, SendData);

        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
        TEST_NOT_EQUAL(nullptr, Buffer);
        memcpy(Buffer->Buffer, Payload, PayloadLen);

        CxPlatSocketSend(ClientSocket, &Route, SendData);
        CxPlatSleep(50);
    }

    //
    // Verify at least one packet was received.
    //
    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathFeatureQueryWithFlags(
    )
{
    DatapathScope Datapath;

    //
    // Query features with different socket flag combinations.
    //
    CXPLAT_DATAPATH_FEATURES FeaturesNone =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);

    CXPLAT_DATAPATH_FEATURES FeaturesPcp =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_PCP);

    CXPLAT_DATAPATH_FEATURES FeaturesShare =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_SHARE);

    //
    // All queries should return the same features (Windows implementation
    // ignores socket flags for feature queries).
    //
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

void
QuicTestDataPathInitWithClientRecvContextLength(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    DatapathScope Datapath(64, nullptr, InitConfig);

    //
    // Verify basic socket creation still works with the custom context length.
    //
    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);
}

void
QuicTestDataPathSendDataSegmented(
    )
{
    DatapathScope Datapath;

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        return; // Segmentation not supported
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

    //
    // Set MaxPacketSize to a segment size to trigger segmented alloc path.
    //
    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    SendDataScope SendData(Socket, &SendConfig);

    //
    // Allocate 5 segment buffers of 100 bytes each. Assert at least one succeeds.
    //
    int AllocCount = 0;
    for (int i = 0; i < 5; i++) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
        if (Buffer == nullptr) {
            break; // send data may be full
        }
        memset(Buffer->Buffer, (uint8_t)i, 100);
        AllocCount++;
    }
    TEST_TRUE(AllocCount >= 1);
}

void
QuicTestDataPathRecvDataReturnNull(
    )
{
    //
    // Calling CxPlatRecvDataReturn with NULL should be a safe no-op.
    //
    CxPlatRecvDataReturn(nullptr);
}

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
    // Create a server socket with no local address (defaults to dual-stack IPv6).
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = nullptr;
    ServerConfig.RemoteAddress = nullptr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    //
    // Create an IPv4 client to send to the dual-stack server.
    //
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

    //
    // The dual-stack server should receive the IPv4 packet.
    //
    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendDataFreeBufferSegmented(
    )
{
    DatapathScope Datapath;

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        return; // Segmentation not supported
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

void
QuicTestDataPathTcpConnectDisconnect(
    )
{
    EventScope AcceptEvent;
    EventScope ConnectEvent;
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return;
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent.Event, &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    TcpSocketScope ClientSocket;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent.Event, &ClientSocket.Socket);

    if (QUIC_SUCCEEDED(Status)) {
        CxPlatEventWaitWithTimeout(ConnectEvent.Event, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent.Event, 2000);

        //
        // Delete client immediately to exercise disconnect/cleanup paths.
        //
    }

    CxPlatSleep(100);
    CxPlatSocketDelete(Listener);
}

void
QuicTestDataPathSendLargePayload(
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

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send a payload close to typical QUIC MTU size.
    //
    const uint16_t PayloadLen = 512; // Fits in RecvBuf[512]

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
    memset(Buffer->Buffer, 0xCD, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathInitDscpRecvDscpSocket(
    )
{
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    InitConfig.EnableDscpOnRecv = TRUE;
    DatapathScope Datapath(0, nullptr, InitConfig);

    //
    // Create a UDP socket - this exercises the RECV_DSCP socket option path.
    //
    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_UDP_CONFIG UdpConfig = {};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope Socket(Datapath, &UdpConfig);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));

    //
    // Also create an IPv6 socket with DSCP recv enabled.
    //
    QUIC_ADDR LocalAddrV6 = {};
    QuicAddrFromString("::1", 0, &LocalAddrV6);

    CXPLAT_UDP_CONFIG UdpConfigV6 = {};
    UdpConfigV6.LocalAddress = &LocalAddrV6;
    UdpConfigV6.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpSocketScope SocketV6(Datapath, &UdpConfigV6);
}

//
// =========================================================================
// Category 11: Feature-Dependent — Server-Send and Advanced Scenarios
// Coupling: Public API. Tests non-fixed-remote sends, combined ECN+DSCP,
//           TCP with local addr, segmented over-wire, and DSCP recv paths.
// =========================================================================
//

void
QuicTestDataPathServerSendToRemote(
    )
{
    //
    // Scenario: Send from a "server" socket (no fixed remote) to a specific
    // remote address. This exercises the !HasFixedRemoteAddress branch in
    // CxPlatSocketSendInline where WSAMhdr.name is set to the mapped remote
    // address and IP_PKTINFO/IPV6_PKTINFO control messages are constructed.
    //
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
    // Create a "receiver" client socket with a known remote.
    //
    CXPLAT_SOCKET* RecvSocket = nullptr;
    QUIC_ADDR RecvLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &RecvLocalAddr);

    CXPLAT_UDP_CONFIG RecvConfig = {};
    RecvConfig.LocalAddress = &RecvLocalAddr;
    RecvConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    RecvConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &RecvConfig, &RecvSocket));

    QUIC_ADDR BoundRecvAddr = {};
    CxPlatSocketGetLocalAddress(RecvSocket, &BoundRecvAddr);
    uint16_t RecvPort = QuicAddrGetPort(&BoundRecvAddr);
    TEST_NOT_EQUAL(0, RecvPort);

    //
    // Create a "server" socket (no remote address) to send from.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.RemoteAddress = nullptr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    //
    // Send from server socket to the receiver's address.
    //
    QUIC_ADDR TargetAddr = {};
    QuicAddrFromString("127.0.0.1", RecvPort, &TargetAddr);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &Route.LocalAddress);
    Route.RemoteAddress = TargetAddr;
    Route.Queue = nullptr; // let it default

    const uint8_t Payload[] = "ServerSendTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ServerSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ServerSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);
    TEST_TRUE(memcmp(RecvCtx.RecvBuf, Payload, PayloadLen) == 0);

    CxPlatSocketDelete(ServerSocket);
    CxPlatSocketDelete(RecvSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathServerSendToRemoteV6(
    )
{
    //
    // Scenario: Send from a "server" (no fixed remote) to a remote over IPv6.
    // This exercises the IPv6 branch in CxPlatSocketSendInline where
    // IPV6_PKTINFO control message is constructed for non-fixed-remote sockets.
    //
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

    CXPLAT_SOCKET* RecvSocket = nullptr;
    QUIC_ADDR RecvLocalAddr = {};
    QuicAddrFromString("::1", 0, &RecvLocalAddr);

    CXPLAT_UDP_CONFIG RecvConfig = {};
    RecvConfig.LocalAddress = &RecvLocalAddr;
    RecvConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    RecvConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &RecvConfig, &RecvSocket));

    QUIC_ADDR BoundRecvAddr = {};
    CxPlatSocketGetLocalAddress(RecvSocket, &BoundRecvAddr);
    uint16_t RecvPort = QuicAddrGetPort(&BoundRecvAddr);

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.RemoteAddress = nullptr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR TargetAddr = {};
    QuicAddrFromString("::1", RecvPort, &TargetAddr);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &Route.LocalAddress);
    Route.RemoteAddress = TargetAddr;
    Route.Queue = nullptr;

    const uint8_t Payload[] = "ServerSendV6";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ServerSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ServerSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);

    CxPlatSocketDelete(ServerSocket);
    CxPlatSocketDelete(RecvSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendEcnAndDscp(
    )
{
    //
    // Scenario: Send a packet with both ECN and DSCP set simultaneously.
    // This exercises the combined IP_TOS control message path (line 3841):
    // *(PINT)WSA_CMSG_DATA(CMsg) = SendData->ECN | (SendData->DSCP << 2);
    //
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

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        CxPlatEventUninitialize(RecvCtx.RecvEvent);
        CxPlatDataPathUninitialize(Datapath);
        return;
    }

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "EcnDscpCombo";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    //
    // ECN_ECT_0 (2) + DSCP_AF11 (10) to exercise combined TOS byte.
    //
    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_ECT_0, CXPLAT_SEND_FLAGS_NONE, 10 // DSCP AF11
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendEcnAndDscpV6(
    )
{
    //
    // Scenario: Send with both ECN + DSCP over IPv6. Exercises the IPv6
    // IPV6_TCLASS control message path with combined TOS byte (line 3876).
    //
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

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_DSCP)) {
        CxPlatEventUninitialize(RecvCtx.RecvEvent);
        CxPlatDataPathUninitialize(Datapath);
        return;
    }

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "EcnDscpV6";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadLen, CXPLAT_ECN_ECT_1, CXPLAT_SEND_FLAGS_NONE, 10
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadLen);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memcpy(Buffer->Buffer, Payload, PayloadLen);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpCreateWithLocalAddr(
    )
{
    //
    // Scenario: Create a TCP client socket with an explicit local address.
    // This exercises the local address binding path in CxPlatSocketCreateTcpInternal.
    //
    EventScope AcceptEvent;
    EventScope ConnectEvent;
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return;
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent.Event, &Listener));

    QUIC_ADDR BoundListenerAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    //
    // Connect with an explicit local address.
    //
    QUIC_ADDR LocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    TcpSocketScope ClientSocket;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, &LocalAddr, &RemoteAddr, &ConnectEvent.Event, &ClientSocket.Socket);

    if (QUIC_SUCCEEDED(Status)) {
        CxPlatEventWaitWithTimeout(ConnectEvent.Event, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent.Event, 2000);

        //
        // Verify local address is bound correctly.
        //
        QUIC_ADDR ClientLocalAddr = {};
        CxPlatSocketGetLocalAddress(ClientSocket, &ClientLocalAddr);
        TEST_NOT_EQUAL(0, QuicAddrGetPort(&ClientLocalAddr));
    }

    CxPlatSocketDelete(Listener);
}

void
QuicTestDataPathSegmentedSendOverWire(
    )
{
    //
    // Scenario: Actually send segmented data over the wire to exercise the
    // UDP_SEND_MSG_SIZE control message construction (lines 3891-3899) and
    // the WSASendMsg path with segmented buffers.
    //
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

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        CxPlatEventUninitialize(RecvCtx.RecvEvent);
        CxPlatDataPathUninitialize(Datapath);
        return;
    }

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    CXPLAT_ROUTE Route = {};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    //
    // Create segmented send data and allocate multiple segments.
    //
    const uint16_t SegmentSize = 100;
    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, SegmentSize, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer1 = CxPlatSendDataAllocBuffer(SendData, SegmentSize);
    TEST_NOT_EQUAL(nullptr, Buffer1);
    memset(Buffer1->Buffer, 0xAA, SegmentSize);

    QUIC_BUFFER* Buffer2 = CxPlatSendDataAllocBuffer(SendData, SegmentSize);
    if (Buffer2 != nullptr) {
        memset(Buffer2->Buffer, 0xBB, SegmentSize);
    }

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    //
    // Wait for at least one segment to arrive.
    //
    TEST_TRUE(CxPlatEventWaitWithTimeout(RecvCtx.RecvEvent, 2000));
    TEST_TRUE(RecvCtx.Received);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathResolveUnspecFamily(
    )
{
    //
    // Scenario: Resolve "localhost" with UNSPEC family to exercise the
    // UNSPEC code path in CxPlatDataPathPopulateTargetAddress.
    //
    DatapathScope Datapath;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "localhost", &Address));
    //
    // With UNSPEC, the system may return either v4 or v6.
    //
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Address);
    TEST_TRUE(
        Family == QUIC_ADDRESS_FAMILY_INET ||
        Family == QUIC_ADDRESS_FAMILY_INET6);
}

void
QuicTestDataPathSendDataIsFullSegmented(
    )
{
    //
    // Scenario: Allocate segmented send data and fill it until IsFull returns
    // TRUE. This exercises the CxPlatSendDataCanAllocSend and
    // CxPlatSendDataCanAllocSendSegment capacity check paths.
    //
    DatapathScope Datapath;

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
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

    //
    // Initially should not be full.
    //
    TEST_FALSE(CxPlatSendDataIsFull(SendData));

    //
    // Allocate segments until either full or we run out of space.
    //
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

void
QuicTestDataPathTcpListenerV6(
    )
{
    //
    // Scenario: Create a TCP listener on IPv6 to exercise the IPv6 TCP
    // listener creation path in CxPlatSocketCreateTcpInternal.
    //
    DatapathScope Datapath(DefaultTcpCallbacks);

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        return;
    }

    QUIC_ADDR ListenerAddr = {};
    QuicAddrFromString("::1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, nullptr, &Listener));
    TEST_NOT_EQUAL(nullptr, Listener);

    QUIC_ADDR BoundAddr = {};
    CxPlatSocketGetLocalAddress(Listener, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&BoundAddr));

    CxPlatSocketDelete(Listener);
}

void
QuicTestDataPathUdpSocketWithLocalAndRemote(
    )
{
    //
    // Scenario: Create a UDP client socket with both a local address and a
    // remote address specified. This exercises both the local address bind
    // path and the connect path together in SocketCreateUdp.
    //
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

void
QuicTestDataPathDscpRecvSendRecv(
    )
{
    //
    // Scenario: Initialize with EnableDscpOnRecv, create sockets, and
    // send/receive to exercise the DSCP recv socket option path
    // (IPV6_RECVTCLASS/IP_RECVTOS) and the DSCP extraction from
    // received control messages.
    //
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {};
    InitConfig.EnableDscpOnRecv = TRUE;

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DscpRecvTest";
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
    TEST_TRUE(RecvCtx.Received);
    TEST_EQUAL(PayloadLen, RecvCtx.RecvBufLen);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatEventUninitialize(RecvCtx.RecvEvent);
    CxPlatDataPathUninitialize(Datapath);
}
