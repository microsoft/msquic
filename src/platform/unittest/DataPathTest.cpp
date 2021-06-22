/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Unit test

--*/

#include "main.h"
#include "quic_datapath.h"

#include "msquic.h"
#ifdef QUIC_CLOG
#include "DataPathTest.cpp.clog.h"
#endif

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
        UNREFERENCED_PARAMETER(af);
        CXPLAT_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            CxPlatDataPathInitialize(
                0,
                NULL,
                NULL,
                &Datapath))) {
            GTEST_FATAL_FAILURE_(" QuicDataPathInitialize failed.");
        }
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
    QUIC_ADDR ServerAddress;
    CXPLAT_EVENT ClientCompletion;
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
    CXPLAT_EVENT AcceptEvent;
    TcpListenerContext() : Server(nullptr), Accepted(false) {
        CxPlatEventInitialize(&AcceptEvent, FALSE, FALSE);
    }
    ~TcpListenerContext() {
        CxPlatEventUninitialize(AcceptEvent);
    }
};

struct DataPathTest : public ::testing::TestWithParam<int32_t>
{
protected:
    static volatile uint16_t NextPort;
    static QuicAddr LocalIPv4;
    static QuicAddr LocalIPv6;

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

    static void SetUpTestSuite()
    {
        //
        // Initialize a semi-random base port number.
        //
        NextPort = 50000 + (CxPlatCurThreadID() % 10000) + (rand() % 5000);

        LocalIPv4.Resolve(QUIC_ADDRESS_FAMILY_INET, "localhost");
        LocalIPv6.Resolve(QUIC_ADDRESS_FAMILY_INET6, "localhost");

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

            if (RecvData->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                auto ServerSendData =
                    CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, 0);
                ASSERT_NE(nullptr, ServerSendData);

                auto ServerBuffer =
                    CxPlatSendDataAllocBuffer(ServerSendData, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerBuffer);

                memcpy(ServerBuffer->Buffer, RecvData->Buffer, RecvData->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    CxPlatSocketSend(
                        Socket,
                        &RecvData->Tuple->LocalAddress,
                        &RecvData->Tuple->RemoteAddress,
                        ServerSendData, 0
                    ));

            } else {
                CxPlatEventSet(RecvContext->ClientCompletion);
            }

            RecvData = RecvData->Next;
        }

        CxPlatRecvDataReturn(RecvDataChain);
    }

    static void
    UdpDataRecvCallbackECT0(
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

            if (RecvData->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                CXPLAT_ECN_TYPE ecn = (CXPLAT_ECN_TYPE)RecvData->TypeOfService;

                auto ServerSendData =
                    CxPlatSendDataAlloc(Socket, CXPLAT_ECN_ECT_0, 0);
                ASSERT_NE(nullptr, ServerSendData);

                auto ServerBuffer =
                    CxPlatSendDataAllocBuffer(ServerSendData, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerBuffer);
                ASSERT_EQ(ecn, CXPLAT_ECN_ECT_0);

                memcpy(ServerBuffer->Buffer, RecvData->Buffer, RecvData->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    CxPlatSocketSend(
                        Socket,
                        &RecvData->Tuple->LocalAddress,
                        &RecvData->Tuple->RemoteAddress,
                        ServerSendData, 0
                    ));

            } else {
                CxPlatEventSet(RecvContext->ClientCompletion);
            }

            RecvData = RecvData->Next;
        }

        CxPlatRecvDataReturn(RecvDataChain);
    }

    static void
    EmptyAcceptCallback(
        _In_ CXPLAT_SOCKET* /* ListenerSocket */,
        _In_ void* /* ListenerContext */,
        _In_ CXPLAT_SOCKET* /* ClientSocket */,
        _Out_ void** /* ClientContext */
        )
    {
    }

    static void
    EmptyConnectCallback(
        _In_ CXPLAT_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ BOOLEAN /* Connected */
        )
    {
    }

    static void
    TcpAcceptCallback(
        _In_ CXPLAT_SOCKET* /* ListenerSocket */,
        _In_ void* Context,
        _In_ CXPLAT_SOCKET* ClientSocket,
        _Out_ void** ClientContext
        )
    {
        TcpListenerContext* ListenerContext = (TcpListenerContext*)Context;
        ListenerContext->Server = ClientSocket;
        *ClientContext = &ListenerContext->ServerContext;
        ListenerContext->Accepted = true;
        CxPlatEventSet(ListenerContext->AcceptEvent);
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

    const CXPLAT_UDP_DATAPATH_CALLBACKS UdpRecvECT0Callbacks = {
        UdpDataRecvCallbackECT0,
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

TEST_F(DataPathTest, Initialize)
{
    CXPLAT_DATAPATH* Datapath = nullptr;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            nullptr,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    CxPlatDataPathUninitialize(
        Datapath);

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            &EmptyUdpCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    CxPlatDataPathUninitialize(
        Datapath);

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            &EmptyTcpCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_F(DataPathTest, InitializeInvalid)
{
    const CXPLAT_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks1 = {
        nullptr,
        EmptyUnreachableCallback,
    };
    const CXPLAT_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks2 = {
        EmptyReceiveCallback,
        nullptr,
    };

    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            nullptr,
            nullptr,
            nullptr));

    CXPLAT_DATAPATH* Datapath = nullptr;
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &InvalidUdpCallbacks1,
            nullptr,
            &Datapath));
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            &InvalidUdpCallbacks2,
            nullptr,
            &Datapath));
}

TEST_F(DataPathTest, UdpBind)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Socket = nullptr;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            &EmptyUdpCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            nullptr,
            nullptr,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &Socket));
    ASSERT_NE(nullptr, Socket);

    QUIC_ADDR Address;
    CxPlatSocketGetLocalAddress(Socket, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);

    CxPlatSocketDelete(Socket);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_F(DataPathTest, UdpRebind)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* binding1 = nullptr;
    CXPLAT_SOCKET* binding2 = nullptr;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            &EmptyUdpCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            nullptr,
            nullptr,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &binding1));
    ASSERT_NE(nullptr, binding1);

    QUIC_ADDR Address1;
    CxPlatSocketGetLocalAddress(binding1, &Address1);
    ASSERT_NE(Address1.Ipv4.sin_port, (uint16_t)0);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            nullptr,
            nullptr,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &binding2));
    ASSERT_NE(nullptr, binding2);

    QUIC_ADDR Address2;
    CxPlatSocketGetLocalAddress(binding2, &Address2);
    ASSERT_NE(Address2.Ipv4.sin_port, (uint16_t)0);

    CxPlatSocketDelete(binding1);
    CxPlatSocketDelete(binding2);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, UdpData)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* server = nullptr;
    CXPLAT_SOCKET* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    UdpRecvContext RecvContext = {};

    CxPlatEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            &UdpRecvCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateUdp(
                Datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
                0,
                (uint16_t)CxPlatProcCurrentNumber(),
                &server);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, server);
    CxPlatSocketGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendData =
        CxPlatSendDataAlloc(client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendData);

    auto ClientBuffer =
        CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);

    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    CxPlatSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendData, 0));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatSocketDelete(client);
    CxPlatSocketDelete(server);

    CxPlatDataPathUninitialize(
        Datapath);

    CxPlatEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, UdpDataRebind)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* server = nullptr;
    CXPLAT_SOCKET* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    UdpRecvContext RecvContext = {};

    CxPlatEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            &UdpRecvCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateUdp(
                Datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
                0,
                (uint16_t)CxPlatProcCurrentNumber(),
                &server);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, server);
    CxPlatSocketGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendData =
        CxPlatSendDataAlloc(client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendData);

    auto ClientBuffer =
        CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);

    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    CxPlatSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendData, 0));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatSocketDelete(client);
    client = nullptr;
    CxPlatEventReset(RecvContext.ClientCompletion);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &client));
    ASSERT_NE(nullptr, client);

    ClientSendData =
        CxPlatSendDataAlloc(client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendData);

    ClientBuffer =
        CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);

    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    CxPlatSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendData, 0));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatSocketDelete(client);
    CxPlatSocketDelete(server);

    CxPlatDataPathUninitialize(
        Datapath);

    CxPlatEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, UdpDataECT0)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* server = nullptr;
    CXPLAT_SOCKET* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    UdpRecvContext RecvContext = {};

    CxPlatEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            &UdpRecvECT0Callbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateUdp(
                Datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
                0,
                (uint16_t)CxPlatProcCurrentNumber(),
                &server);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, server);
    CxPlatSocketGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            0,
            (uint16_t)CxPlatProcCurrentNumber(),
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendData =
        CxPlatSendDataAlloc(client, CXPLAT_ECN_ECT_0, 0);
    ASSERT_NE(nullptr, ClientSendData);

    auto ClientBuffer =
        CxPlatSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);

    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    CxPlatSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendData, 0));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatSocketDelete(client);
    CxPlatSocketDelete(server);

    CxPlatDataPathUninitialize(
        Datapath);

    CxPlatEventUninitialize(RecvContext.ClientCompletion);
}

#if WIN32
TEST_F(DataPathTest, TcpListener)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Socket = nullptr;

    TcpListenerContext ListenerContext;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            &EmptyTcpCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateTcpListener(
            Datapath,
            nullptr,
            &ListenerContext,
            &Socket));
    ASSERT_NE(nullptr, Socket);

    QUIC_ADDR Address;
    CxPlatSocketGetLocalAddress(Socket, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);

    CxPlatSocketDelete(Socket);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, TcpConnect)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Listener = nullptr;
    CXPLAT_SOCKET* Client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    TcpListenerContext ListenerContext;
    TcpClientContext ClientContext;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            &TcpRecvCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateTcpListener(
                Datapath,
                &serverAddress.SockAddr,
                &ListenerContext,
                &Listener);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, Listener);

    QUIC_ADDR Address;
    CxPlatSocketGetLocalAddress(Listener, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(Address.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &ClientContext,
            &Client));
    ASSERT_NE(nullptr, Client);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    CxPlatSocketDelete(ListenerContext.Server);
    ListenerContext.Server = nullptr;

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.DisconnectEvent, 100));

    CxPlatSocketDelete(Client);
    CxPlatSocketDelete(Listener);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, TcpDisconnect)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Listener = nullptr;
    CXPLAT_SOCKET* Client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    TcpListenerContext ListenerContext;
    TcpClientContext ClientContext;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            &TcpRecvCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateTcpListener(
                Datapath,
                &serverAddress.SockAddr,
                &ListenerContext,
                &Listener);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, Listener);

    QUIC_ADDR Address;
    CxPlatSocketGetLocalAddress(Listener, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(Address.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &ClientContext,
            &Client));
    ASSERT_NE(nullptr, Client);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    CxPlatSocketDelete(Client);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.ServerContext.DisconnectEvent, 100));

    CxPlatSocketDelete(ListenerContext.Server);
    CxPlatSocketDelete(Listener);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, TcpDataClient)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Listener = nullptr;
    CXPLAT_SOCKET* Client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    TcpListenerContext ListenerContext;
    TcpClientContext ClientContext;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            &TcpRecvCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateTcpListener(
                Datapath,
                &serverAddress.SockAddr,
                &ListenerContext,
                &Listener);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, Listener);

    QUIC_ADDR ServerAddress;
    CxPlatSocketGetLocalAddress(Listener, &ServerAddress);
    ASSERT_NE(ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &ClientContext,
            &Client));
    ASSERT_NE(nullptr, Client);

    QUIC_ADDR ClientAddress;
    CxPlatSocketGetLocalAddress(Client, &ClientAddress);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    auto SendData =
        CxPlatSendDataAlloc(Client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, SendData);

    auto SendBuffer =
        CxPlatSendDataAllocBuffer(SendData, ExpectedDataSize);
    ASSERT_NE(nullptr, SendBuffer);

    memcpy(SendBuffer->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketSend(
            Client,
            &ServerAddress,
            &ClientAddress,
            SendData, 0));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.ServerContext.ReceiveEvent, 100));

    CxPlatSocketDelete(Client);
    CxPlatSocketDelete(ListenerContext.Server);
    CxPlatSocketDelete(Listener);

    CxPlatDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, TcpDataServer)
{
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_SOCKET* Listener = nullptr;
    CXPLAT_SOCKET* Client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    TcpListenerContext ListenerContext;
    TcpClientContext ClientContext;

    VERIFY_QUIC_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            nullptr,
            &TcpRecvCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatSocketCreateTcpListener(
                Datapath,
                &serverAddress.SockAddr,
                &ListenerContext,
                &Listener);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_QUIC_SUCCESS(Status);
    ASSERT_NE(nullptr, Listener);

    QUIC_ADDR ServerAddress;
    CxPlatSocketGetLocalAddress(Listener, &ServerAddress);
    ASSERT_NE(ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketCreateTcp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &ClientContext,
            &Client));
    ASSERT_NE(nullptr, Client);

    QUIC_ADDR ClientAddress;
    CxPlatSocketGetLocalAddress(Client, &ClientAddress);

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    auto SendData =
        CxPlatSendDataAlloc(ListenerContext.Server, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, SendData);

    auto SendBuffer =
        CxPlatSendDataAllocBuffer(SendData, ExpectedDataSize);
    ASSERT_NE(nullptr, SendBuffer);

    memcpy(SendBuffer->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(
        CxPlatSocketSend(
            ListenerContext.Server,
            &ServerAddress,
            &ClientAddress,
            SendData, 0));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(ClientContext.ReceiveEvent, 100));

    CxPlatSocketDelete(Client);
    CxPlatSocketDelete(ListenerContext.Server);
    CxPlatSocketDelete(Listener);

    CxPlatDataPathUninitialize(
        Datapath);
}
#endif // WIN32

INSTANTIATE_TEST_SUITE_P(DataPathTest, DataPathTest, ::testing::Values(4, 6), testing::PrintToStringParamName());
