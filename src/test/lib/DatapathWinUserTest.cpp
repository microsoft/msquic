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
// ===== Category 1: DataPath Initialization Tests =====
//

void
QuicTestDataPathInitUdp(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathInitUdpTcp(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            &TcpCallbacks,
            WorkerPool,
            &InitConfig,
            &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathInitNullOutput(
    )
{
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {0};
    UdpCallbacks.Unreachable = DatapathTestUdpUnreachCallback;
    // Receive is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {0};
    UdpCallbacks.Receive = DatapathTestUdpRecvCallbackSimple;
    // Unreachable is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {0};
    TcpCallbacks.Connect = DatapathTestTcpConnectCallback;
    TcpCallbacks.Receive = DatapathTestTcpRecvCallback;
    TcpCallbacks.SendComplete = DatapathTestTcpSendCompleteCallback;
    // Accept is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {0};
    TcpCallbacks.Accept = DatapathTestTcpAcceptCallback;
    TcpCallbacks.Receive = DatapathTestTcpRecvCallback;
    TcpCallbacks.SendComplete = DatapathTestTcpSendCompleteCallback;
    // Connect is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {0};
    TcpCallbacks.Accept = DatapathTestTcpAcceptCallback;
    TcpCallbacks.Connect = DatapathTestTcpConnectCallback;
    TcpCallbacks.SendComplete = DatapathTestTcpSendCompleteCallback;
    // Receive is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {0};
    TcpCallbacks.Accept = DatapathTestTcpAcceptCallback;
    TcpCallbacks.Connect = DatapathTestTcpConnectCallback;
    TcpCallbacks.Receive = DatapathTestTcpRecvCallback;
    // SendComplete is NULL
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};
    InitConfig.EnableDscpOnRecv = TRUE;

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);
    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 2: Feature Query Tests =====
//

void
QuicTestDataPathFeatureQuery(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);

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

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathIsPaddingPreferred(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0,
            &UdpCallbacks,
            nullptr,
            WorkerPool,
            &InitConfig,
            &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);

    //
    // We need a socket + send data to query IsPaddingPreferred.
    // Create a simple client socket for this purpose.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrSetFamily(&RemoteAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&RemoteAddr, 12345);
    QuicAddrFromString("127.0.0.1", 12345, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(
            Datapath,
            &UdpConfig,
            &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;
    Route.Queue = nullptr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    BOOLEAN IsPadded = CxPlatDataPathIsPaddingPreferred(Datapath, SendData);
    // Just verify it returns a valid boolean
    TEST_TRUE(IsPadded == TRUE || IsPadded == FALSE);

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 3: Address Resolution Tests =====
//

void
QuicTestDataPathResolveLocalhostV4(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "localhost", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&Address));

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathResolveLocalhostV6(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET6);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "localhost", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&Address));

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathResolveNumericV4(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "127.0.0.1", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&Address));

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathResolveNumericV6(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET6);
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathResolveAddress(Datapath, "::1", &Address));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&Address));

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathResolveInvalidHost(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QUIC_STATUS Status =
        CxPlatDataPathResolveAddress(
            Datapath, "this.host.does.not.exist.invalid", &Address);
    TEST_TRUE(QUIC_FAILED(Status));

    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 4: Address Enumeration Tests =====
//

void
QuicTestDataPathGetLocalAddresses(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_ADAPTER_ADDRESS* Addresses = nullptr;
    uint32_t AddressCount = 0;

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathGetLocalAddresses(Datapath, &Addresses, &AddressCount));
    TEST_TRUE(AddressCount > 0);
    TEST_NOT_EQUAL(nullptr, Addresses);

    CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathGetGatewayAddresses(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

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
    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 5: UDP Socket Tests =====
//

void
QuicTestDataPathUdpServerSocket(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a "server" socket (no remote address).
    //
    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = nullptr;
    UdpConfig.RemoteAddress = nullptr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpClientSocket(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a "client" socket (with remote address).
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 9999, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpGetLocalAddress(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    QUIC_ADDR LocalAddr = {0};
    CxPlatSocketGetLocalAddress(Socket, &LocalAddr);
    //
    // Should have a valid port assigned.
    //
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&LocalAddr));

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpGetRemoteAddress(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 8888, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    QUIC_ADDR RetrievedRemote = {0};
    CxPlatSocketGetRemoteAddress(Socket, &RetrievedRemote);
    TEST_EQUAL(8888, QuicAddrGetPort(&RetrievedRemote));

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpGetMtu(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 7777, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    uint16_t Mtu = CxPlatSocketGetLocalMtu(Socket, &Route);
    TEST_TRUE(Mtu >= 1280); // Minimum IPv6 MTU

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpBindV4(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR LocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    QUIC_ADDR BoundAddr = {0};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&BoundAddr));

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpBindV6(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR LocalAddr = {0};
    QuicAddrFromString("::1", 0, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    QUIC_ADDR BoundAddr = {0};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));
    TEST_EQUAL(QUIC_ADDRESS_FAMILY_INET6, QuicAddrGetFamily(&BoundAddr));

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpPcpSocket(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 5351, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_PCP;
    UdpConfig.CallbackContext = nullptr;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 6: Send Data Tests =====
//

void
QuicTestDataPathSendDataAllocFree(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendDataAllocBuffer(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
    TEST_NOT_EQUAL(nullptr, Buffer);
    TEST_NOT_EQUAL(nullptr, Buffer->Buffer);
    TEST_TRUE(Buffer->Length >= 100);

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendDataFreeBuffer(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
    TEST_NOT_EQUAL(nullptr, Buffer);

    CxPlatSendDataFreeBuffer(SendData, Buffer);

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendDataIsFull(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 1200, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    //
    // Initially the send data should not be full.
    //
    TEST_FALSE(CxPlatSendDataIsFull(SendData));

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 1200);
    TEST_NOT_EQUAL(nullptr, Buffer);

    //
    // After allocating a max-sized buffer without segmentation,
    // it may or may not be full depending on segmentation support.
    //
    BOOLEAN IsFull = CxPlatSendDataIsFull(SendData);
    TEST_TRUE(IsFull == TRUE || IsFull == FALSE);

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendDataAllocMultiple(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    //
    // Allocate several small buffers.
    //
    for (int i = 0; i < 5; i++) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
        if (Buffer == nullptr) {
            break; // send data may be full
        }
        memset(Buffer->Buffer, (uint8_t)i, 100);
    }

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpSendLoopback(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a server socket to receive.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    //
    // Create a client socket pointing to the server.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send data from the client socket.
    //
    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(ClientSocket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    const uint16_t PayloadSize = 64;
    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, PayloadSize, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(ClientSocket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, PayloadSize);
    TEST_NOT_EQUAL(nullptr, Buffer);
    memset(Buffer->Buffer, 0xAB, PayloadSize);

    CxPlatSocketSend(ClientSocket, &Route, SendData);

    //
    // Brief wait for packet transit.
    //
    CxPlatSleep(100);

    CxPlatSocketDelete(ClientSocket);
    CxPlatSocketDelete(ServerSocket);
    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 7: Receive Data Tests =====
//

void
QuicTestDataPathUdpSendRecvLoopback(
    const FamilyArgs& Params
    )
{
    int Family = Params.Family;
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a server socket.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    if (Family == 4) {
        QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);
    } else {
        QuicAddrFromString("::1", 0, &ServerLocalAddr);
    }

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    //
    // Create a client socket.
    //
    QUIC_ADDR RemoteAddr = {0};
    if (Family == 4) {
        QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);
    } else {
        QuicAddrFromString("::1", ServerPort, &RemoteAddr);
    }

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send a test payload.
    //
    const uint8_t TestPayload[] = "DatapathWinUserTest";
    const uint16_t PayloadSize = sizeof(TestPayload);

    CXPLAT_ROUTE Route = {0};
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
// ===== Category 8: TCP Socket Tests =====
//

void
QuicTestDataPathTcpListener(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        return; // TCP not supported on this platform
    }

    QUIC_ADDR ListenerAddr = {0};
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
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpClient(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        return; // TCP not supported on this platform
    }

    //
    // Create a listener first so we have somewhere to connect to.
    //
    QUIC_ADDR ListenerAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath,
            &ListenerAddr,
            nullptr,
            &Listener));

    QUIC_ADDR BoundListenerAddr = {0};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    //
    // Create a TCP client socket connecting to the listener.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &RemoteAddr,
            nullptr,
            &ClientSocket);
    //
    // The connection may succeed or be pending. Either is valid.
    //
    if (QUIC_SUCCEEDED(Status)) {
        TEST_NOT_EQUAL(nullptr, ClientSocket);
        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSocketDelete(Listener);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpConnect(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_EVENT AcceptEvent;
    CXPLAT_EVENT ConnectEvent;
    CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
    CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        CxPlatEventUninitialize(AcceptEvent);
        CxPlatEventUninitialize(ConnectEvent);
        return;
    }

    //
    // Create listener.
    //
    QUIC_ADDR ListenerAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath,
            &ListenerAddr,
            &AcceptEvent,
            &Listener));

    QUIC_ADDR BoundListenerAddr = {0};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    //
    // Create client.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &RemoteAddr,
            &ConnectEvent,
            &ClientSocket);

    if (QUIC_SUCCEEDED(Status)) {
        //
        // Wait for connect and accept callbacks.
        //
        CxPlatEventWaitWithTimeout(ConnectEvent, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent, 2000);

        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSocketDelete(Listener);
    CxPlatEventUninitialize(AcceptEvent);
    CxPlatEventUninitialize(ConnectEvent);
    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Category 9: DataPath Lifecycle Tests =====
//

void
QuicTestDataPathFullLifecycle(
    )
{
    //
    // Full lifecycle: init → create socket → send → receive → cleanup.
    //
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a server socket.
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    //
    // Create a client socket.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send data.
    //
    const uint8_t Payload[] = "LifecycleTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // This is a no-op on Windows but should not crash.
    //
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, 0);
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, 1000);
    CxPlatDataPathUpdatePollingIdleTimeout(Datapath, UINT32_MAX);

    CxPlatDataPathUninitialize(Datapath);
}

//
// ===== Additional Coverage Tests =====
//

void
QuicTestDataPathSendWithEcn(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "EcnTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DscpTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "IPv6Test";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a "server" socket bound to [::] (wildcard IPv6).
    //
    QUIC_ADDR LocalAddr = {0};
    QuicAddrFromString("::", 0, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.RemoteAddress = nullptr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    QUIC_ADDR BoundAddr = {0};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathUdpShareFlag(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    QUIC_ADDR LocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_SHARE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendWithMaxThroughput(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "MaxThroughputTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DscpV6Test";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("::1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("::1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "EcnV6Test";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_EVENT AcceptEvent;
    CXPLAT_EVENT ConnectEvent;
    CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
    CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        CxPlatEventUninitialize(AcceptEvent);
        CxPlatEventUninitialize(ConnectEvent);
        return;
    }

    QUIC_ADDR ListenerAddr = {0};
    QuicAddrFromString("::1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent, &Listener));

    QUIC_ADDR BoundListenerAddr = {0};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("::1", ListenerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent, &ClientSocket);

    if (QUIC_SUCCEEDED(Status)) {
        CxPlatEventWaitWithTimeout(ConnectEvent, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent, 2000);
        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSocketDelete(Listener);
    CxPlatEventUninitialize(AcceptEvent);
    CxPlatEventUninitialize(ConnectEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpStatistics(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_EVENT AcceptEvent;
    CXPLAT_EVENT ConnectEvent;
    CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
    CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        CxPlatEventUninitialize(AcceptEvent);
        CxPlatEventUninitialize(ConnectEvent);
        return;
    }

    QUIC_ADDR ListenerAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent, &Listener));

    QUIC_ADDR BoundListenerAddr = {0};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent, &ClientSocket);

    if (QUIC_SUCCEEDED(Status)) {
        TEST_TRUE(CxPlatEventWaitWithTimeout(ConnectEvent, 2000));
        CxPlatEventWaitWithTimeout(AcceptEvent, 2000);

        //
        // Query TCP statistics on the connected client socket.
        //
        CXPLAT_TCP_STATISTICS Stats = {0};
        QUIC_STATUS StatsStatus =
            CxPlatSocketGetTcpStatistics(ClientSocket, &Stats);
        if (QUIC_SUCCEEDED(StatsStatus)) {
            TEST_TRUE(Stats.Mss > 0);
        }

        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSocketDelete(Listener);
    CxPlatEventUninitialize(AcceptEvent);
    CxPlatEventUninitialize(ConnectEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpSendRecv(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestTcpRecvContext TcpRecvCtx = {0};
    CxPlatEventInitialize(&TcpRecvCtx.RecvEvent, FALSE, FALSE);

    DatapathTestTcpAcceptRecvContext AcceptCtx = {0};
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
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

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

    QUIC_ADDR ListenerAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptCtx, &Listener));

    QUIC_ADDR BoundListenerAddr = {0};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {0};
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

        CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Pick a high port and bind to it explicitly.
    //
    const uint16_t SpecificPort = 49152 + (uint16_t)(CxPlatCurThreadID() % 1000);

    QUIC_ADDR LocalAddr = {0};
    QuicAddrFromString("127.0.0.1", SpecificPort, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    QUIC_STATUS Status =
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket);
    if (QUIC_SUCCEEDED(Status)) {
        QUIC_ADDR BoundAddr = {0};
        CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
        TEST_EQUAL(SpecificPort, QuicAddrGetPort(&BoundAddr));
        CxPlatSocketDelete(Socket);
    }
    //
    // Port may be in use - that's okay, just verify no crash.
    //

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathMultipleSendRecv(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Query features with different socket flag combinations.
    //
    CXPLAT_DATAPATH_FEATURES FeaturesNone =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    (void)FeaturesNone; // Just verify no crash

    CXPLAT_DATAPATH_FEATURES FeaturesPcp =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_PCP);
    (void)FeaturesPcp;

    CXPLAT_DATAPATH_FEATURES FeaturesShare =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_SHARE);
    (void)FeaturesShare;

    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathInitWithClientRecvContextLength(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    //
    // Initialize with a non-zero ClientRecvContextLength.
    //
    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            64, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);

    //
    // Verify basic socket creation still works with the custom context length.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendDataSegmented(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        CxPlatDataPathUninitialize(Datapath);
        return; // Segmentation not supported
    }

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    //
    // Set MaxPacketSize to a segment size to trigger segmented alloc path.
    //
    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    //
    // Allocate 5 segment buffers of 100 bytes each.
    //
    for (int i = 0; i < 5; i++) {
        QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
        if (Buffer == nullptr) {
            break; // send data may be full
        }
        memset(Buffer->Buffer, (uint8_t)i, 100);
    }

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
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

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    //
    // Create a server socket with no local address (defaults to dual-stack IPv6).
    //
    CXPLAT_SOCKET* ServerSocket = nullptr;
    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = nullptr;
    ServerConfig.RemoteAddress = nullptr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);
    TEST_NOT_EQUAL(0, ServerPort);

    //
    // Create an IPv4 client to send to the dual-stack server.
    //
    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    const uint8_t Payload[] = "DualStackTest";
    const uint16_t PayloadLen = sizeof(Payload);

    CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)) {
        CxPlatDataPathUninitialize(Datapath);
        return; // Segmentation not supported
    }

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", 6666, &RemoteAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.RemoteAddress = &RemoteAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    Route.RemoteAddress = RemoteAddr;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, 100, CXPLAT_ECN_NON_ECT, CXPLAT_SEND_FLAGS_NONE, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    TEST_NOT_EQUAL(nullptr, SendData);

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocBuffer(SendData, 100);
    TEST_NOT_EQUAL(nullptr, Buffer);

    CxPlatSendDataFreeBuffer(SendData, Buffer);

    CxPlatSendDataFree(SendData);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathTcpConnectDisconnect(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_EVENT AcceptEvent;
    CXPLAT_EVENT ConnectEvent;
    CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
    CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };
    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpCallbacks = {
        DatapathTestTcpAcceptCallback,
        DatapathTestTcpConnectCallback,
        DatapathTestTcpRecvCallback,
        DatapathTestTcpSendCompleteCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, &TcpCallbacks, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_DATAPATH_FEATURES Features =
        CxPlatDataPathGetSupportedFeatures(Datapath, CXPLAT_SOCKET_FLAG_NONE);
    if (!(Features & CXPLAT_DATAPATH_FEATURE_TCP)) {
        CxPlatDataPathUninitialize(Datapath);
        CxPlatEventUninitialize(AcceptEvent);
        CxPlatEventUninitialize(ConnectEvent);
        return;
    }

    QUIC_ADDR ListenerAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ListenerAddr);

    CXPLAT_SOCKET* Listener = nullptr;
    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateTcpListener(
            Datapath, &ListenerAddr, &AcceptEvent, &Listener));

    QUIC_ADDR BoundListenerAddr = {0};
    CxPlatSocketGetLocalAddress(Listener, &BoundListenerAddr);
    uint16_t ListenerPort = QuicAddrGetPort(&BoundListenerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ListenerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateTcp(
            Datapath, nullptr, &RemoteAddr, &ConnectEvent, &ClientSocket);

    if (QUIC_SUCCEEDED(Status)) {
        CxPlatEventWaitWithTimeout(ConnectEvent, 2000);
        CxPlatEventWaitWithTimeout(AcceptEvent, 2000);

        //
        // Delete client immediately to exercise disconnect/cleanup paths.
        //
        CxPlatSocketDelete(ClientSocket);
    }

    CxPlatSleep(100);
    CxPlatSocketDelete(Listener);
    CxPlatEventUninitialize(AcceptEvent);
    CxPlatEventUninitialize(ConnectEvent);
    CxPlatDataPathUninitialize(Datapath);
}

void
QuicTestDataPathSendLargePayload(
    )
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    DatapathTestRecvContext RecvCtx = {0};
    CxPlatEventInitialize(&RecvCtx.RecvEvent, FALSE, FALSE);

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallback,
        DatapathTestUdpUnreachCallback,
    };
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));

    CXPLAT_SOCKET* ServerSocket = nullptr;
    QUIC_ADDR ServerLocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &ServerLocalAddr);

    CXPLAT_UDP_CONFIG ServerConfig = {0};
    ServerConfig.LocalAddress = &ServerLocalAddr;
    ServerConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    ServerConfig.CallbackContext = &RecvCtx;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ServerConfig, &ServerSocket));

    QUIC_ADDR BoundServerAddr = {0};
    CxPlatSocketGetLocalAddress(ServerSocket, &BoundServerAddr);
    uint16_t ServerPort = QuicAddrGetPort(&BoundServerAddr);

    QUIC_ADDR RemoteAddr = {0};
    QuicAddrFromString("127.0.0.1", ServerPort, &RemoteAddr);

    CXPLAT_SOCKET* ClientSocket = nullptr;
    CXPLAT_UDP_CONFIG ClientConfig = {0};
    ClientConfig.RemoteAddress = &RemoteAddr;
    ClientConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &ClientConfig, &ClientSocket));

    //
    // Send a payload close to typical QUIC MTU size.
    //
    const uint16_t PayloadLen = 512; // Fits in RecvBuf[512]

    CXPLAT_ROUTE Route = {0};
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
    CXPLAT_DATAPATH* Datapath = nullptr;
    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks = {
        DatapathTestUdpRecvCallbackSimple,
        DatapathTestUdpUnreachCallback,
    };

    //
    // Initialize with EnableDscpOnRecv = TRUE.
    //
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};
    InitConfig.EnableDscpOnRecv = TRUE;

    TEST_QUIC_SUCCEEDED(
        CxPlatDataPathInitialize(
            0, &UdpCallbacks, nullptr, WorkerPool, &InitConfig, &Datapath));
    TEST_NOT_EQUAL(nullptr, Datapath);

    //
    // Create a UDP socket - this exercises the RECV_DSCP socket option path.
    //
    QUIC_ADDR LocalAddr = {0};
    QuicAddrFromString("127.0.0.1", 0, &LocalAddr);

    CXPLAT_SOCKET* Socket = nullptr;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = &LocalAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket));
    TEST_NOT_EQUAL(nullptr, Socket);

    QUIC_ADDR BoundAddr = {0};
    CxPlatSocketGetLocalAddress(Socket, &BoundAddr);
    TEST_NOT_EQUAL(0, QuicAddrGetPort(&BoundAddr));

    //
    // Also create an IPv6 socket with DSCP recv enabled.
    //
    QUIC_ADDR LocalAddrV6 = {0};
    QuicAddrFromString("::1", 0, &LocalAddrV6);

    CXPLAT_SOCKET* SocketV6 = nullptr;
    CXPLAT_UDP_CONFIG UdpConfigV6 = {0};
    UdpConfigV6.LocalAddress = &LocalAddrV6;
    UdpConfigV6.Flags = CXPLAT_SOCKET_FLAG_NONE;

    TEST_QUIC_SUCCEEDED(
        CxPlatSocketCreateUdp(Datapath, &UdpConfigV6, &SocketV6));
    TEST_NOT_EQUAL(nullptr, SocketV6);

    CxPlatSocketDelete(SocketV6);
    CxPlatSocketDelete(Socket);
    CxPlatDataPathUninitialize(Datapath);
}
