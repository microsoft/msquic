/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Unit test

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "main.h"
#include "quic_datapath.h"

#include "msquic.h"
#ifdef QUIC_CLOG
#include "DataPathTest.cpp.clog.h"
#endif

extern bool UseDuoNic;
extern CXPLAT_WORKER_POOL WorkerPool;

//
// Connect to the duonic address (if using duonic) or localhost (if not).
//
#define QUIC_TEST_LOOPBACK_FOR_AF(Af) (UseDuoNic ? ((Af == QUIC_ADDRESS_FAMILY_INET) ? "192.168.1.11" : "fc00::1:11") : QUIC_LOCALHOST_FOR_AF(Af))

const uint32_t ExpectedDataSize = 1 * 1024;
char* ExpectedData;

//
// Helper class for managing the memory of a IP address.
//
struct QuicAddr
{
    QUIC_ADDR SockAddr;

    uint16_t Port() {
        if (QuicAddrGetFamily(&SockAddr) == QUIC_ADDRESS_FAMILY_INET) {
            return SockAddr.Ipv4.sin_port;
        } else {
            return SockAddr.Ipv6.sin6_port;
        }
    }

    #undef SetPort
    void SetPort(uint16_t port) {
        if (QuicAddrGetFamily(&SockAddr) == QUIC_ADDRESS_FAMILY_INET) {
            SockAddr.Ipv4.sin_port = port;
        } else {
            SockAddr.Ipv6.sin6_port = port;
        }
    }

    QuicAddr() {
        CxPlatZeroMemory(this, sizeof(*this));
    }

    void Resolve(QUIC_ADDRESS_FAMILY af, const char* hostname) {
        CXPLAT_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            CxPlatDataPathInitialize(
                0,
                NULL,
                NULL,
                &WorkerPool,
                NULL,
                &Datapath))) {
            GTEST_FATAL_FAILURE_(" QuicDataPathInitialize failed.");
        }
        QuicAddrSetFamily(&SockAddr, af);
        if (QUIC_FAILED(
            CxPlatDataPathResolveAddress(
                Datapath,
                hostname,
                &SockAddr))) {
            GTEST_FATAL_FAILURE_("Failed to resolve IP address.");
        }
        CxPlatDataPathUninitialize(Datapath);
    }
};

struct UdpRecvContext {
    QUIC_ADDR DestinationAddress;
    CXPLAT_EVENT ClientCompletion;
    CXPLAT_ECN_TYPE EcnType {CXPLAT_ECN_NON_ECT};
    UdpRecvContext() {
        CxPlatEventInitialize(&ClientCompletion, FALSE, FALSE);
    }
    ~UdpRecvContext() {
        CxPlatEventUninitialize(ClientCompletion);
    }
};

struct TcpClientContext {
    bool Connected : 1;
    bool Disconnected : 1;
    bool Received : 1;
    CXPLAT_EVENT ConnectEvent;
    CXPLAT_EVENT DisconnectEvent;
    CXPLAT_EVENT ReceiveEvent;
    TcpClientContext() : Connected(false), Disconnected(false), Received(false) {
        CxPlatEventInitialize(&ConnectEvent, FALSE, FALSE);
        CxPlatEventInitialize(&DisconnectEvent, FALSE, FALSE);
        CxPlatEventInitialize(&ReceiveEvent, FALSE, FALSE);
    }
    ~TcpClientContext() {
        CxPlatEventUninitialize(ConnectEvent);
        CxPlatEventUninitialize(DisconnectEvent);
        CxPlatEventUninitialize(ReceiveEvent);
    }
};

struct TcpListenerContext {
    CXPLAT_SOCKET* Server;
    TcpClientContext ServerContext;
    bool Accepted : 1;
    bool Reject : 1;
    bool Rejected : 1;
    CXPLAT_EVENT AcceptEvent;
    TcpListenerContext() : Server(nullptr), Accepted(false), Reject{false}, Rejected{false} {
        CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
    }
    ~TcpListenerContext() {
        DeleteSocket();
        CxPlatEventUninitialize(AcceptEvent);
    }
    void DeleteSocket() {
        if (Server) {
            CxPlatSocketDelete(Server);
            Server = nullptr;
        }
    }
};

struct DataPathTest : public ::testing::TestWithParam<int32_t>
{
protected:
    static volatile uint16_t NextPort;
    static QuicAddr LocalIPv4;
    static QuicAddr LocalIPv6;
    static QuicAddr UnspecIPv4;
    static QuicAddr UnspecIPv6;

    //
    // Helper to get a new port to bind to.
    //
    uint16_t
    GetNextPort()
    {
        return QuicNetByteSwapShort((uint16_t)InterlockedIncrement16((volatile short*)&NextPort));
    }

    //
    // Helper to return a new local IPv4 address and port to use.
    //
    QuicAddr
    GetNewLocalIPv4(bool randomPort = true)
    {
        QuicAddr ipv4Copy = LocalIPv4;
        if (randomPort) { ipv4Copy.SockAddr.Ipv4.sin_port = GetNextPort(); }
        else { ipv4Copy.SockAddr.Ipv4.sin_port = 0; }
        return ipv4Copy;
    }

    //
    // Helper to return a new local IPv4 address and port to use.
    //
    QuicAddr
    GetNewLocalIPv6(bool randomPort = true)
    {
        QuicAddr ipv6Copy = LocalIPv6;
        if (randomPort) { ipv6Copy.SockAddr.Ipv6.sin6_port = GetNextPort(); }
        else { ipv6Copy.SockAddr.Ipv6.sin6_port = 0; }
        return ipv6Copy;
    }

    //
    // Helper to return a new local IPv4 or IPv6 address based on the test data.
    //
    QuicAddr
    GetNewLocalAddr(bool randomPort = true)
    {
        int addressFamily = GetParam();

        if (addressFamily == 4) {
            return GetNewLocalIPv4(randomPort);
        } else if (addressFamily == 6) {
            return GetNewLocalIPv6(randomPort);
        } else {
            GTEST_NONFATAL_FAILURE_("Malconfigured test data; This should never happen!!");
            return QuicAddr();
        }
    }

    //
    // Helper to return a new unspecified IPv4 address and port to use.
    //
    QuicAddr
    GetNewUnspecIPv4(bool randomPort = true)
    {
        QuicAddr ipv4Copy = UnspecIPv4;
        if (randomPort) { ipv4Copy.SockAddr.Ipv4.sin_port = GetNextPort(); }
        else { ipv4Copy.SockAddr.Ipv4.sin_port = 0; }
        return ipv4Copy;
    }

    //
    // Helper to return a new unspecified IPv4 address and port to use.
    //
    QuicAddr
    GetNewUnspecIPv6(bool randomPort = true)
    {
        QuicAddr ipv6Copy = UnspecIPv6;
        if (randomPort) { ipv6Copy.SockAddr.Ipv6.sin6_port = GetNextPort(); }
        else { ipv6Copy.SockAddr.Ipv6.sin6_port = 0; }
        return ipv6Copy;
    }

    //
    // Helper to return a new unspecified IPv4 or IPv6 address based on the test data.
    //
    QuicAddr
    GetNewUnspecAddr(bool randomPort = true)
    {
        int addressFamily = GetParam();

        if (addressFamily == 4) {
            return GetNewUnspecIPv4(randomPort);
        } else if (addressFamily == 6) {
            return GetNewUnspecIPv6(randomPort);
        } else {
            GTEST_NONFATAL_FAILURE_("Malconfigured test data; This should never happen!!");
            return QuicAddr();
        }
    }

    static void SetUpTestSuite()
    {
        //
        // Initialize a semi-random base port number.
        //
        NextPort = 50000 + (CxPlatCurThreadID() % 10000) + (rand() % 5000);

        LocalIPv4.Resolve(QUIC_ADDRESS_FAMILY_INET, QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET));
        LocalIPv6.Resolve(QUIC_ADDRESS_FAMILY_INET6, QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET6));

        UnspecIPv4.Resolve(QUIC_ADDRESS_FAMILY_INET, "0.0.0.0");
        UnspecIPv6.Resolve(QUIC_ADDRESS_FAMILY_INET6, "::");

        ExpectedData = (char*)CXPLAT_ALLOC_NONPAGED(ExpectedDataSize, QUIC_POOL_TEST);
        ASSERT_NE(ExpectedData, nullptr);
    }

    static void TearDownTestSuite()
    {
        CXPLAT_FREE(ExpectedData, QUIC_POOL_TEST);
    }

    static void
    EmptyReceiveCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* /* RecvContext */,
        _In_ CXPLAT_RECV_DATA* /* RecvDataChain */
        )
    {
    }

    static void
    EmptyUnreachableCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ const QUIC_ADDR* /* RemoteAddress */
        )
    {
    }

    static void
    UdpDataRecvCallback(
        _In_ CXPLAT_SOCKET* Socket,
        _In_ void* Context,
        _In_ CXPLAT_RECV_DATA* RecvDataChain
        )
    {
        UdpRecvContext* RecvContext = (UdpRecvContext*)Context;
        ASSERT_NE(nullptr, RecvContext);

        CXPLAT_RECV_DATA* RecvData = RecvDataChain;

        while (RecvData != NULL) {
            ASSERT_EQ(RecvData->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(RecvData->Buffer, ExpectedData, ExpectedDataSize));

            if (RecvData->Route->LocalAddress.Ipv4.sin_port == RecvContext->DestinationAddress.Ipv4.sin_port) {

                ASSERT_EQ((CXPLAT_ECN_TYPE)RecvData->TypeOfService, RecvContext->EcnType);

                CXPLAT_SEND_CONFIG SendConfig = { RecvData->Route, 0, (uint8_t)RecvContext->EcnType, 0 };
                auto ServerSendData = CxPlatSendDataAlloc(Socket, &SendConfig);
                ASSERT_NE(nullptr, ServerSendData);
                auto ServerBuffer = CxPlatSendDataAllocBuffer(ServerSendData, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerBuffer);
                memcpy(ServerBuffer->Buffer, RecvData->Buffer, RecvData->BufferLength);

                CxPlatSocketSend(Socket, RecvData->Route, ServerSendData);

            } else if (RecvData->Route->RemoteAddress.Ipv4.sin_port == RecvContext->DestinationAddress.Ipv4.sin_port) {
                CxPlatEventSet(RecvContext->ClientCompletion);

            } else {
                GTEST_NONFATAL_FAILURE_("Received on unexpected address!");
            }

            RecvData = RecvData->Next;
        }

        CxPlatRecvDataReturn(RecvDataChain);
    }

    static QUIC_STATUS
    EmptyAcceptCallback(
        _In_ CXPLAT_SOCKET* /* ListenerSocket */,
        _In_ void* /* ListenerContext */,
        _In_ CXPLAT_SOCKET* /* ClientSocket */,
        _Out_ void** /* ClientContext */
        )
    {
        // If we somehow get a connection here, reject it
        return QUIC_STATUS_CONNECTION_REFUSED;
    }

    static void
    EmptyConnectCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ BOOLEAN /* Connected */
        )
    {
    }

    static QUIC_STATUS
    TcpAcceptCallback(
        _In_ CXPLAT_SOCKET* /* ListenerSocket */,
        _In_ void* Context,
        _In_ CXPLAT_SOCKET* ClientSocket,
        _Out_ void** ClientContext
        )
    {
        TcpListenerContext* ListenerContext = (TcpListenerContext*)Context;
        if (ListenerContext->Reject) {
            ListenerContext->Rejected = true;
            CxPlatEventSet(ListenerContext->AcceptEvent);
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        ListenerContext->Server = ClientSocket;
        *ClientContext = &ListenerContext->ServerContext;
        ListenerContext->Accepted = true;
        CxPlatEventSet(ListenerContext->AcceptEvent);
        return QUIC_STATUS_SUCCESS;
    }

    static void
    TcpConnectCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* Context,
        _In_ BOOLEAN Connected
        )
    {
        TcpClientContext* ClientContext = (TcpClientContext*)Context;
        if (Connected) {
            ClientContext->Connected = true;
            CxPlatEventSet(ClientContext->ConnectEvent);
        } else {
            ClientContext->Disconnected = true;
            CxPlatEventSet(ClientContext->DisconnectEvent);
        }
    }

    static void
    TcpDataRecvCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* Context,
        _In_ CXPLAT_RECV_DATA* RecvDataChain
        )
    {
        if (Context) {
            TcpClientContext* ClientContext = (TcpClientContext*)Context;
            ClientContext->Received = true;
            CxPlatEventSet(ClientContext->ReceiveEvent);
        }
        CxPlatRecvDataReturn(RecvDataChain);
    }

    static void
    TcpEmptySendCompleteCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ QUIC_STATUS /* Status */,
        _In_ uint32_t /* ByteCount */
        )
    {
    }

    const CXPLAT_UDP_DATAPATH_CALLBACKS EmptyUdpCallbacks = {
        EmptyReceiveCallback,
        EmptyUnreachableCallback,
    };

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpRecvCallbacks = {
        UdpDataRecvCallback,
        EmptyUnreachableCallback,
    };

    const CXPLAT_TCP_DATAPATH_CALLBACKS EmptyTcpCallbacks = {
        EmptyAcceptCallback,
        EmptyConnectCallback,
        EmptyReceiveCallback,
        TcpEmptySendCompleteCallback
    };

    const CXPLAT_TCP_DATAPATH_CALLBACKS TcpRecvCallbacks = {
        TcpAcceptCallback,
        TcpConnectCallback,
        TcpDataRecvCallback,
        TcpEmptySendCompleteCallback
    };
};

volatile uint16_t DataPathTest::NextPort;
QuicAddr DataPathTest::LocalIPv4;
QuicAddr DataPathTest::LocalIPv6;
QuicAddr DataPathTest::UnspecIPv4;
QuicAddr DataPathTest::UnspecIPv6;

struct CxPlatDataPath {
    QUIC_EXECUTION_CONFIG DefaultExecutionConfig { QUIC_EXECUTION_CONFIG_FLAG_NONE, 0, 0, {0} };
    CXPLAT_DATAPATH* Datapath {nullptr};
    QUIC_STATUS InitStatus;
    CxPlatDataPath(
        _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
        _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks = nullptr,
        _In_ uint32_t ClientRecvContextLength = 0,
        _In_opt_ QUIC_EXECUTION_CONFIG* Config = nullptr
        ) noexcept
    {
        if (UseDuoNic && Config == nullptr) {
            DefaultExecutionConfig.Flags = QUIC_EXECUTION_CONFIG_FLAG_XDP;
        }
        InitStatus =
            CxPlatDataPathInitialize(
                ClientRecvContextLength,
                UdpCallbacks,
                TcpCallbacks,
                &WorkerPool,
                Config ? Config : &DefaultExecutionConfig,
                &Datapath);
    }
    ~CxPlatDataPath() noexcept {
        if (Datapath) {
            CxPlatDataPathUninitialize(Datapath);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    CxPlatDataPath(CxPlatDataPath& other) = delete;
    CxPlatDataPath operator=(CxPlatDataPath& Other) = delete;
    operator CXPLAT_DATAPATH* () const noexcept { return Datapath; }
    uint32_t GetSupportedFeatures() const noexcept { return CxPlatDataPathGetSupportedFeatures(Datapath); }
    bool IsSupported(uint32_t feature) const noexcept { return static_cast<bool>(GetSupportedFeatures() & feature); }
};

static
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_ROUTE_RESOLUTION_CALLBACK)
void
ResolveRouteComplete(
    _Inout_ void* Context,
    _When_(Succeeded == FALSE, _Reserved_)
    _When_(Succeeded == TRUE, _In_reads_bytes_(6))
        const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    )
{
    UNREFERENCED_PARAMETER(PathId);
    if (Succeeded) {
        CxPlatResolveRouteComplete(nullptr, (CXPLAT_ROUTE*)Context, PhysicalAddress, 0);
    }
}

struct CxPlatSocket {
    CXPLAT_SOCKET* Socket {nullptr};
    QUIC_STATUS InitStatus {QUIC_STATUS_INVALID_STATE};
    CXPLAT_ROUTE Route {0};
    CxPlatSocket() { }
    CxPlatSocket(
        _In_ CxPlatDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_opt_ const QUIC_ADDR* RemoteAddress = nullptr,
        _In_opt_ void* CallbackContext = nullptr,
        _In_ uint32_t InternalFlags = 0
        ) noexcept // UDP
    {
        CreateUdp(
            Datapath,
            LocalAddress,
            RemoteAddress,
            CallbackContext,
            InternalFlags);
    }
    ~CxPlatSocket() noexcept {
        if (Socket) {
            CxPlatSocketDelete(Socket);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    CxPlatSocket(CxPlatSocket& other) = delete;
    CxPlatSocket operator=(CxPlatSocket& Other) = delete;
    operator CXPLAT_SOCKET* () const noexcept { return Socket; }
    void CreateUdp(
        _In_ CxPlatDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_opt_ const QUIC_ADDR* RemoteAddress = nullptr,
        _In_opt_ void* CallbackContext = nullptr,
        _In_ uint32_t InternalFlags = 0
        ) noexcept
    {
        CXPLAT_UDP_CONFIG UdpConfig = {0};
        UdpConfig.LocalAddress = LocalAddress;
        UdpConfig.RemoteAddress = RemoteAddress;
        UdpConfig.Flags = InternalFlags;
        UdpConfig.InterfaceIndex = 0;
        UdpConfig.CallbackContext = CallbackContext;
        InitStatus =
            CxPlatSocketCreateUdp(
                Datapath,
                &UdpConfig,
                &Socket);
#ifdef _WIN32
        if (InitStatus == HRESULT_FROM_WIN32(WSAEACCES)) {
            InitStatus = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(LocalAddress->Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
        if (QUIC_SUCCEEDED(InitStatus)) {
            CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
            CxPlatSocketGetRemoteAddress(Socket, &Route.RemoteAddress);
            if (Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_RAW) &&
                !QuicAddrIsWildCard(&Route.RemoteAddress)) {
                //
                // This is a connected socket and its route must be resolved
                // to be able to send traffic.
                //
                InitStatus = CxPlatResolveRoute(Socket, &Route, 0, &Route, ResolveRouteComplete);
                //
                // Duonic sets up static neighbor entries, so CxPlatResolveRoute should
                // complete synchronously. If this changes, we will need to add code to
                // wait for an event set by ResolveRouteComplete.
                //
                EXPECT_EQ(InitStatus, QUIC_STATUS_SUCCESS);
                EXPECT_TRUE(CxPlatSocketRawSocketAvailable(Socket));
            }
        }
    }
    void CreateTcp(
        _In_ CxPlatDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress,
        _In_ const QUIC_ADDR* RemoteAddress,
        _In_opt_ void* CallbackContext = nullptr
        ) noexcept
    {
        InitStatus =
            CxPlatSocketCreateTcp(
                Datapath,
                LocalAddress,
                RemoteAddress,
                CallbackContext,
                &Socket);
        if (QUIC_SUCCEEDED(InitStatus)) {
            CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
            CxPlatSocketGetRemoteAddress(Socket, &Route.RemoteAddress);
        }
    }
    void CreateTcpListener(
        _In_ CxPlatDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_opt_ void* CallbackContext = nullptr
        ) noexcept
    {
        InitStatus =
            CxPlatSocketCreateTcpListener(
                Datapath,
                LocalAddress,
                CallbackContext,
                &Socket);
#ifdef _WIN32
        if (InitStatus == HRESULT_FROM_WIN32(WSAEACCES)) {
            InitStatus = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(LocalAddress->Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
        if (QUIC_SUCCEEDED(InitStatus)) {
            CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
            CxPlatSocketGetRemoteAddress(Socket, &Route.RemoteAddress);
        }
    }
    QUIC_ADDR GetLocalAddress() const noexcept {
        return Route.LocalAddress;
    }
    QUIC_ADDR GetRemoteAddress() const noexcept {
        return Route.RemoteAddress;
    }
    void
    Send(
        _In_ const CXPLAT_ROUTE& _Route,
        _In_ CXPLAT_SEND_DATA* SendData
        ) const noexcept
    {
        CxPlatSocketSend(Socket, &_Route, SendData);
    }
    void
    Send(
        _In_ const QUIC_ADDR& RemoteAddress,
        _In_ CXPLAT_SEND_DATA* SendData
        ) const noexcept
    {
        CXPLAT_ROUTE _Route = Route;
        _Route.RemoteAddress = RemoteAddress;
        Send(_Route, SendData);
    }
    void
    Send(
        _In_ CXPLAT_SEND_DATA* SendData
        ) const noexcept
    {
        Send(Route, SendData);
    }
};

TEST_F(DataPathTest, Initialize)
{
    {
        CxPlatDataPath Datapath(nullptr);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }
    {
        CxPlatDataPath Datapath(&EmptyUdpCallbacks);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }
    {
        CxPlatDataPath Datapath(nullptr, &EmptyTcpCallbacks);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }
    {
        QUIC_EXECUTION_CONFIG Config = { QUIC_EXECUTION_CONFIG_FLAG_NONE, UINT32_MAX, 0 };
        CxPlatDataPath Datapath(&EmptyUdpCallbacks, nullptr, 0, &Config);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }
    {
        QUIC_EXECUTION_CONFIG Config = { QUIC_EXECUTION_CONFIG_FLAG_NONE, 0, 0 };
        CxPlatDataPath Datapath(&EmptyUdpCallbacks, nullptr, 0, &Config);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }
    {
        QUIC_EXECUTION_CONFIG Config = { QUIC_EXECUTION_CONFIG_FLAG_NONE, UINT32_MAX, 1, {0} };
        CxPlatDataPath Datapath(&EmptyUdpCallbacks, nullptr, 0, &Config);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }
    if (UseDuoNic) {
        QUIC_EXECUTION_CONFIG Config = { QUIC_EXECUTION_CONFIG_FLAG_XDP, 0, 1, {0} };
        CxPlatDataPath Datapath(&EmptyUdpCallbacks, nullptr, 0, &Config);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
        ASSERT_TRUE(Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_RAW));
    }
}

TEST_F(DataPathTest, InitializeInvalid)
{
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, CxPlatDataPathInitialize(0, nullptr, nullptr, nullptr, nullptr, nullptr));
    {
        const CXPLAT_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks = { nullptr, EmptyUnreachableCallback };
        CxPlatDataPath Datapath(&InvalidUdpCallbacks);
        ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, Datapath.GetInitStatus());
        ASSERT_EQ(nullptr, Datapath.Datapath);
    }
    {
        const CXPLAT_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks = { EmptyReceiveCallback, nullptr };
        CxPlatDataPath Datapath(&InvalidUdpCallbacks);
        ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, Datapath.GetInitStatus());
        ASSERT_EQ(nullptr, Datapath.Datapath);
    }
}

TEST_F(DataPathTest, UdpBind)
{
    CxPlatDataPath Datapath(&EmptyUdpCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    CxPlatSocket Socket(Datapath);
    VERIFY_QUIC_SUCCESS(Socket.GetInitStatus());
    ASSERT_NE(nullptr, Socket.Socket);
    ASSERT_NE(Socket.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);
}

TEST_F(DataPathTest, UdpRebind)
{
    CxPlatDataPath Datapath(&EmptyUdpCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    CxPlatSocket Socket1(Datapath);
    VERIFY_QUIC_SUCCESS(Socket1.GetInitStatus());
    ASSERT_NE(nullptr, Socket1.Socket);
    ASSERT_NE(Socket1.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    CxPlatSocket Socket2(Datapath);
    VERIFY_QUIC_SUCCESS(Socket2.GetInitStatus());
    ASSERT_NE(nullptr, Socket2.Socket);
    ASSERT_NE(Socket2.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);
}

TEST_F(DataPathTest, UdpQeo)
{
    CxPlatDataPath Datapath(&EmptyUdpCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    CxPlatSocket Socket(Datapath);
    VERIFY_QUIC_SUCCESS(Socket.GetInitStatus());
    ASSERT_NE(nullptr, Socket.Socket);

    CXPLAT_QEO_CONNECTION Offloads[] = {
        {
            CXPLAT_QEO_OPERATION_ADD,
            CXPLAT_QEO_DIRECTION_TRANSMIT,
            CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
            0,
            0,
            CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
            8,
            {0}
        },
        {
            CXPLAT_QEO_OPERATION_ADD,
            CXPLAT_QEO_DIRECTION_RECEIVE,
            CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
            0,
            0,
            CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
            0,
            {0}
        }
    };
    ASSERT_TRUE(QuicAddrFromString("192.168.0.1:443", 443, &Offloads[0].Address));
    ASSERT_TRUE(QuicAddrFromString("192.168.0.1:5555", 5555, &Offloads[1].Address));
    ASSERT_EQ(
        QUIC_STATUS_NOT_SUPPORTED,
        CxPlatSocketUpdateQeo(Socket.Socket, Offloads, 2));
}

TEST_P(DataPathTest, UdpData)
{
    UdpRecvContext RecvContext;
    CxPlatDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto unspecAddress = GetNewUnspecAddr();
    CxPlatSocket Server(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        unspecAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);

    auto serverAddress = GetNewLocalAddr();
    RecvContext.DestinationAddress = serverAddress.SockAddr;
    RecvContext.DestinationAddress.Ipv4.sin_port = Server.GetLocalAddress().Ipv4.sin_port;
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    CxPlatSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);

    CXPLAT_SEND_CONFIG SendConfig = { &Client.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    auto ClientSendData = CxPlatSendDataAlloc(Client, &SendConfig);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    Client.Send(ClientSendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
}

TEST_P(DataPathTest, UdpDataPolling)
{
    QUIC_EXECUTION_CONFIG Config = { QUIC_EXECUTION_CONFIG_FLAG_NONE, UINT32_MAX, 0 };
    UdpRecvContext RecvContext;
    CxPlatDataPath Datapath(&UdpRecvCallbacks, nullptr, 0, &Config);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto unspecAddress = GetNewUnspecAddr();
    CxPlatSocket Server(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        unspecAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);

    auto serverAddress = GetNewLocalAddr();
    RecvContext.DestinationAddress = serverAddress.SockAddr;
    RecvContext.DestinationAddress.Ipv4.sin_port = Server.GetLocalAddress().Ipv4.sin_port;
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    CxPlatSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);

    CXPLAT_SEND_CONFIG SendConfig = { &Client.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    auto ClientSendData = CxPlatSendDataAlloc(Client, &SendConfig);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    Client.Send(ClientSendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
}

TEST_P(DataPathTest, UdpDataRebind)
{
    UdpRecvContext RecvContext;
    CxPlatDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto unspecAddress = GetNewUnspecAddr();
    CxPlatSocket Server(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        unspecAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);

    auto serverAddress = GetNewLocalAddr();
    RecvContext.DestinationAddress = serverAddress.SockAddr;
    RecvContext.DestinationAddress.Ipv4.sin_port = Server.GetLocalAddress().Ipv4.sin_port;
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    {
        CxPlatSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
        VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
        ASSERT_NE(nullptr, Client.Socket);

        CXPLAT_SEND_CONFIG SendConfig = { &Client.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
        auto ClientSendData = CxPlatSendDataAlloc(Client, &SendConfig);
        ASSERT_NE(nullptr, ClientSendData);
        auto ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
        ASSERT_NE(nullptr, ClientBuffer);
        memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

        Client.Send(ClientSendData);
        ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
        CxPlatEventReset(RecvContext.ClientCompletion);
    }

    {
        CxPlatSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
        VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
        ASSERT_NE(nullptr, Client.Socket);

        CXPLAT_SEND_CONFIG SendConfig = { &Client.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
        auto ClientSendData = CxPlatSendDataAlloc(Client, &SendConfig);
        ASSERT_NE(nullptr, ClientSendData);
        auto ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
        ASSERT_NE(nullptr, ClientBuffer);
        memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

        Client.Send(ClientSendData);
        ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    }
}

TEST_P(DataPathTest, UdpDataECT0)
{
    UdpRecvContext RecvContext;
    RecvContext.EcnType = CXPLAT_ECN_ECT_0;
    CxPlatDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto unspecAddress = GetNewUnspecAddr();
    CxPlatSocket Server(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        unspecAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &unspecAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);

    auto serverAddress = GetNewLocalAddr();
    RecvContext.DestinationAddress = serverAddress.SockAddr;
    RecvContext.DestinationAddress.Ipv4.sin_port = Server.GetLocalAddress().Ipv4.sin_port;
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    CxPlatSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);

    CXPLAT_SEND_CONFIG SendConfig = { &Client.Route, 0, CXPLAT_ECN_ECT_0, 0 };
    auto ClientSendData = CxPlatSendDataAlloc(Client, &SendConfig);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    Client.Send(ClientSendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
}

TEST_P(DataPathTest, UdpShareClientSocket)
{
    UdpRecvContext RecvContext;
    CxPlatDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);
    // TODO: Linux XDP (duonic) to support port sharing
    if (!(Datapath.GetSupportedFeatures() & CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING) || UseDuoNic) {
        std::cout << "SKIP: Sharing Feature Unsupported" << std::endl;
        return;
    }

    auto serverAddress = GetNewLocalAddr();
    CxPlatSocket Server1(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server1.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server1.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server1.GetInitStatus());

    serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
    CxPlatSocket Server2(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server2.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server2.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server2.GetInitStatus());

    serverAddress.SockAddr = Server1.GetLocalAddress();
    CxPlatSocket Client1(Datapath, nullptr, &serverAddress.SockAddr, &RecvContext, CXPLAT_SOCKET_FLAG_SHARE);
    VERIFY_QUIC_SUCCESS(Client1.GetInitStatus());

    auto clientAddress = Client1.GetLocalAddress();
    serverAddress.SockAddr = Server2.GetLocalAddress();
    CxPlatSocket Client2(Datapath, &clientAddress, &serverAddress.SockAddr, &RecvContext, CXPLAT_SOCKET_FLAG_SHARE);
    VERIFY_QUIC_SUCCESS(Client2.GetInitStatus());

    CXPLAT_SEND_CONFIG SendConfig = { &Client1.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    auto ClientSendData = CxPlatSendDataAlloc(Client1, &SendConfig);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    RecvContext.DestinationAddress = Server1.GetLocalAddress();
    Client1.Send(ClientSendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    CxPlatEventReset(RecvContext.ClientCompletion);

    CXPLAT_SEND_CONFIG SendConfig2 = { &Client2.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    ClientSendData = CxPlatSendDataAlloc(Client2, &SendConfig2);
    ASSERT_NE(nullptr, ClientSendData);
    ClientBuffer = CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    RecvContext.DestinationAddress = Server2.GetLocalAddress();
    Client2.Send(ClientSendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    CxPlatEventReset(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, MultiBindListener) {
    UdpRecvContext RecvContext;
    CxPlatDataPath Datapath(&UdpRecvCallbacks);
    if (!(Datapath.GetSupportedFeatures() & CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS)) {
        std::cout << "SKIP: Port Reservations Feature Unsupported" << std::endl;
        return;
    }

    auto ServerAddress = GetNewLocalAddr();
    CxPlatSocket Server1(Datapath, &ServerAddress.SockAddr, nullptr, &RecvContext);
    while (Server1.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        ServerAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server1.CreateUdp(Datapath, &ServerAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server1.GetInitStatus());

    CxPlatSocket Server2(Datapath, &ServerAddress.SockAddr, nullptr, &RecvContext);
    ASSERT_EQ(QUIC_STATUS_ADDRESS_IN_USE, Server2.GetInitStatus());
}

TEST_P(DataPathTest, MultiBindListenerSingleProcessor) {
    UdpRecvContext RecvContext;
    QUIC_EXECUTION_CONFIG Config = { QUIC_EXECUTION_CONFIG_FLAG_NO_IDEAL_PROC, UINT32_MAX, 1, 0 };
    CxPlatDataPath Datapath(&UdpRecvCallbacks, nullptr, 0, &Config);

    auto ServerAddress = GetNewLocalAddr();
    CxPlatSocket Server1(Datapath, &ServerAddress.SockAddr, nullptr, &RecvContext);
    while (Server1.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        ServerAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server1.CreateUdp(Datapath, &ServerAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server1.GetInitStatus());

    CxPlatSocket Server2(Datapath, &ServerAddress.SockAddr, nullptr, &RecvContext);
    ASSERT_EQ(QUIC_STATUS_ADDRESS_IN_USE, Server2.GetInitStatus());
}

TEST_F(DataPathTest, TcpListener)
{
    CxPlatDataPath Datapath(nullptr, &EmptyTcpCallbacks);
    if (!Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        GTEST_SKIP_("TCP is not supported");
    }
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    CxPlatSocket Listener; Listener.CreateTcpListener(Datapath, nullptr, &ListenerContext);
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    ASSERT_NE(Listener.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);
}

TEST_P(DataPathTest, TcpConnect)
{
    CxPlatDataPath Datapath(nullptr, &TcpRecvCallbacks);
    if (!Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        GTEST_SKIP_("TCP is not supported");
    }
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    CxPlatSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    TcpClientContext ClientContext;
    CxPlatSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 500));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 500));
    ASSERT_NE(nullptr, ListenerContext.Server);
    QUIC_ADDR ServerRemote = {};
    CxPlatSocketGetRemoteAddress(ListenerContext.Server, &ServerRemote);
    QUIC_ADDR ServerLocal = {};
    CxPlatSocketGetLocalAddress(ListenerContext.Server, &ServerLocal);
    ASSERT_NE(ServerRemote.Ipv4.sin_port, (uint16_t)0);
    ASSERT_NE(ServerLocal.Ipv4.sin_port, (uint16_t)0);
    ASSERT_EQ(ServerRemote.Ipv4.sin_port, Client.GetLocalAddress().Ipv4.sin_port);

    ListenerContext.DeleteSocket();

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.DisconnectEvent, 500));
}

TEST_P(DataPathTest, TcpRejectConnect)
{
    CxPlatDataPath Datapath(nullptr, &TcpRecvCallbacks);
    if (!Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        GTEST_SKIP_("TCP is not supported");
    }
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    CxPlatSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    ListenerContext.Reject = true;

    TcpClientContext ClientContext;
    CxPlatSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 500));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 500));
    ASSERT_EQ(true, ListenerContext.Rejected);
    ASSERT_EQ(nullptr, ListenerContext.Server);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.DisconnectEvent, 500));
}

TEST_P(DataPathTest, TcpDisconnect)
{
    CxPlatDataPath Datapath(nullptr, &TcpRecvCallbacks);
    if (!Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        GTEST_SKIP_("TCP is not supported");
    }
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    CxPlatSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    {
        TcpClientContext ClientContext;
        CxPlatSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
        VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
        ASSERT_NE(nullptr, Client.Socket);
        ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

        ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 500));
        ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 500));
        ASSERT_NE(nullptr, ListenerContext.Server);
    }

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.ServerContext.DisconnectEvent, 500));
}

TEST_P(DataPathTest, TcpDataClient)
{
    CxPlatDataPath Datapath(nullptr, &TcpRecvCallbacks);
    if (!Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        GTEST_SKIP_("TCP is not supported");
    }
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    CxPlatSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    TcpClientContext ClientContext;
    CxPlatSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 500));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 500));
    ASSERT_NE(nullptr, ListenerContext.Server);

    CXPLAT_SEND_CONFIG SendConfig = { &Client.Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    auto SendData = CxPlatSendDataAlloc(Client, &SendConfig);
    ASSERT_NE(nullptr, SendData);
    auto SendBuffer = CxPlatSendDataAllocBuffer(SendData, ExpectedDataSize);
    ASSERT_NE(nullptr, SendBuffer);
    memcpy(SendBuffer->Buffer, ExpectedData, ExpectedDataSize);

    Client.Send(SendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.ServerContext.ReceiveEvent, 500));
}

TEST_P(DataPathTest, TcpDataServer)
{
    CxPlatDataPath Datapath(nullptr, &TcpRecvCallbacks);
    if (!Datapath.IsSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        GTEST_SKIP_("TCP is not supported");
    }
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    CxPlatSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    TcpClientContext ClientContext;
    CxPlatSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 500));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 500));
    ASSERT_NE(nullptr, ListenerContext.Server);

    CXPLAT_ROUTE Route = Listener.Route;
    Route.RemoteAddress = Client.GetLocalAddress();

    CXPLAT_SEND_CONFIG SendConfig = { &Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    auto SendData = CxPlatSendDataAlloc(ListenerContext.Server, &SendConfig);
    ASSERT_NE(nullptr, SendData);
    auto SendBuffer = CxPlatSendDataAllocBuffer(SendData, ExpectedDataSize);
    ASSERT_NE(nullptr, SendBuffer);
    memcpy(SendBuffer->Buffer, ExpectedData, ExpectedDataSize);

    CxPlatSocketSend(ListenerContext.Server, &Route, SendData);
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ReceiveEvent, 500));
}

INSTANTIATE_TEST_SUITE_P(DataPathTest, DataPathTest, ::testing::Values(4, 6), testing::PrintToStringParamName());
