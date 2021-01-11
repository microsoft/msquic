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
        QuicZeroMemory(this, sizeof(*this));
    }

    void Resolve(QUIC_ADDRESS_FAMILY af, const char* hostname) {
        UNREFERENCED_PARAMETER(af);
        QUIC_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            QuicDataPathInitialize(
                0,
                NULL,
                NULL,
                &Datapath))) {
            GTEST_FATAL_FAILURE_(" QuicDataPathInitialize failed.");
        }
        if (QUIC_FAILED(
            QuicDataPathResolveAddress(
                Datapath,
                hostname,
                &SockAddr))) {
            GTEST_FATAL_FAILURE_("Failed to resolve IP address.");
        }
        QuicDataPathUninitialize(Datapath);
    }
};

struct DataRecvContext {
    QUIC_ADDR ServerAddress;
    QUIC_EVENT ClientCompletion;
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
        NextPort = 50000 + (QuicCurThreadID() % 10000) + (rand() % 5000);

        LocalIPv4.Resolve(QUIC_ADDRESS_FAMILY_INET, "localhost");
        LocalIPv6.Resolve(QUIC_ADDRESS_FAMILY_INET6, "localhost");

        ExpectedData = (char*)QUIC_ALLOC_NONPAGED(ExpectedDataSize, QUIC_POOL_TEST);
        ASSERT_NE(ExpectedData, nullptr);
    }

    static void TearDownTestSuite()
    {
        QUIC_FREE(ExpectedData, QUIC_POOL_TEST);
    }

    static void
    EmptyReceiveCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* RecvContext */,
        _In_ QUIC_RECV_DATA* /* RecvDataChain */
        )
    {
    }

    static void
    EmptyUnreachableCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ const QUIC_ADDR* /* RemoteAddress */
        )
    {
    }

    static void
    UdpDataRecvCallback(
        _In_ QUIC_SOCKET* Socket,
        _In_ void* Context,
        _In_ QUIC_RECV_DATA* RecvDataChain
        )
    {
        DataRecvContext* RecvContext = (DataRecvContext*)Context;
        ASSERT_NE(nullptr, RecvContext);

        QUIC_RECV_DATA* RecvData = RecvDataChain;

        while (RecvData != NULL) {
            ASSERT_EQ(RecvData->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(RecvData->Buffer, ExpectedData, ExpectedDataSize));

            if (RecvData->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                auto ServerSendContext =
                    QuicSendDataAlloc(Socket, QUIC_ECN_NON_ECT, 0);
                ASSERT_NE(nullptr, ServerSendContext);

                auto ServerDatagram =
                    QuicSendDataAllocBuffer(ServerSendContext, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerDatagram);

                memcpy(ServerDatagram->Buffer, RecvData->Buffer, RecvData->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    QuicSocketSend(
                        Socket,
                        &RecvData->Tuple->LocalAddress,
                        &RecvData->Tuple->RemoteAddress,
                        ServerSendContext
                    ));

            } else {
                QuicEventSet(RecvContext->ClientCompletion);
            }

            RecvData = RecvData->Next;
        }

        QuicRecvDataReturn(RecvDataChain);
    }

    static void
    UdpDataRecvCallbackECT0(
        _In_ QUIC_SOCKET* Socket,
        _In_ void* Context,
        _In_ QUIC_RECV_DATA* RecvDataChain
        )
    {
        DataRecvContext* RecvContext = (DataRecvContext*)Context;
        ASSERT_NE(nullptr, RecvContext);

        QUIC_RECV_DATA* RecvData = RecvDataChain;

        while (RecvData != NULL) {
            ASSERT_EQ(RecvData->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(RecvData->Buffer, ExpectedData, ExpectedDataSize));

            if (RecvData->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                QUIC_ECN_TYPE ecn = (QUIC_ECN_TYPE)RecvData->TypeOfService;

                auto ServerSendContext =
                    QuicSendDataAlloc(Socket, QUIC_ECN_ECT_0, 0);
                ASSERT_NE(nullptr, ServerSendContext);

                auto ServerDatagram =
                    QuicSendDataAllocBuffer(ServerSendContext, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerDatagram);
                ASSERT_EQ(ecn, QUIC_ECN_ECT_0);

                memcpy(ServerDatagram->Buffer, RecvData->Buffer, RecvData->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    QuicSocketSend(
                        Socket,
                        &RecvData->Tuple->LocalAddress,
                        &RecvData->Tuple->RemoteAddress,
                        ServerSendContext
                    ));

            } else {
                QuicEventSet(RecvContext->ClientCompletion);
            }

            RecvData = RecvData->Next;
        }

        QuicRecvDataReturn(RecvDataChain);
    }

    static void
    EmptyAcceptCallback(
        _In_ QUIC_SOCKET* /* ListenerSocket */,
        _In_ void* /* ListenerContext */,
        _In_ QUIC_SOCKET* /* ClientSocket */,
        _Out_ void** /* ClientContext */
        )
    {
    }

    static void
    EmptyConnectCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ BOOLEAN /* Connected */
        )
    {
    }

    static void
    TcpAcceptCallback(
        _In_ QUIC_SOCKET* /* ListenerSocket */,
        _In_ void* ListenerContext,
        _In_ QUIC_SOCKET* ClientSocket,
        _Out_ void** /* ClientContext */
        )
    {
        QUIC_SOCKET** ServerSocket = (QUIC_SOCKET**)ListenerContext;
        *ServerSocket = ClientSocket;
    }

    static void
    TcpConnectCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ BOOLEAN /* Connected */
        )
    {
    }

    static void
    TcpDataRecvCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ QUIC_RECV_DATA* RecvDataChain
        )
    {
        QuicRecvDataReturn(RecvDataChain);
    }

    const QUIC_UDP_DATAPATH_CALLBACKS EmptyUdpCallbacks = {
        EmptyReceiveCallback,
        EmptyUnreachableCallback,
    };

    const QUIC_UDP_DATAPATH_CALLBACKS UdpRecvCallbacks = {
        UdpDataRecvCallback,
        EmptyUnreachableCallback,
    };

    const QUIC_UDP_DATAPATH_CALLBACKS UdpRecvECT0Callbacks = {
        UdpDataRecvCallbackECT0,
        EmptyUnreachableCallback,
    };

    const QUIC_TCP_DATAPATH_CALLBACKS EmptyTcpCallbacks = {
        EmptyAcceptCallback,
        EmptyConnectCallback,
        EmptyReceiveCallback,
    };

    const QUIC_TCP_DATAPATH_CALLBACKS TcpRecvCallbacks = {
        TcpAcceptCallback,
        TcpConnectCallback,
        TcpDataRecvCallback,
    };
};

volatile uint16_t DataPathTest::NextPort;
QuicAddr DataPathTest::LocalIPv4;
QuicAddr DataPathTest::LocalIPv6;

TEST_F(DataPathTest, Initialize)
{
    QUIC_DATAPATH* Datapath = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            nullptr,
            nullptr,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QuicDataPathUninitialize(
        Datapath);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            &EmptyUdpCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QuicDataPathUninitialize(
        Datapath);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            nullptr,
            &EmptyTcpCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QuicDataPathUninitialize(
        Datapath);
}

TEST_F(DataPathTest, InitializeInvalid)
{
    const QUIC_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks1 = {
        nullptr,
        EmptyUnreachableCallback,
    };
    const QUIC_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks2 = {
        EmptyReceiveCallback,
        nullptr,
    };

    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        QuicDataPathInitialize(
            0,
            nullptr,
            nullptr,
            nullptr));

    QUIC_DATAPATH* Datapath = nullptr;
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        QuicDataPathInitialize(
            0,
            &InvalidUdpCallbacks1,
            nullptr,
            &Datapath));
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        QuicDataPathInitialize(
            0,
            &InvalidUdpCallbacks2,
            nullptr,
            &Datapath));
}

TEST_F(DataPathTest, UdpBind)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* Socket = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            &EmptyUdpCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            nullptr,
            nullptr,
            &Socket));
    ASSERT_NE(nullptr, Socket);

    QUIC_ADDR Address;
    QuicSocketGetLocalAddress(Socket, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);

    QuicSocketDelete(Socket);

    QuicDataPathUninitialize(
        Datapath);
}

TEST_F(DataPathTest, UdpRebind)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* binding1 = nullptr;
    QUIC_SOCKET* binding2 = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            &EmptyUdpCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding1));
    ASSERT_NE(nullptr, binding1);

    QUIC_ADDR Address1;
    QuicSocketGetLocalAddress(binding1, &Address1);
    ASSERT_NE(Address1.Ipv4.sin_port, (uint16_t)0);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding2));
    ASSERT_NE(nullptr, binding2);

    QUIC_ADDR Address2;
    QuicSocketGetLocalAddress(binding2, &Address2);
    ASSERT_NE(Address2.Ipv4.sin_port, (uint16_t)0);

    QuicSocketDelete(binding1);
    QuicSocketDelete(binding2);

    QuicDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, UdpData)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* server = nullptr;
    QUIC_SOCKET* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            &UdpRecvCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicSocketCreateUdp(
                Datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
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
    QuicSocketGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        QuicSendDataAlloc(client, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        QuicSendDataAllocBuffer(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    QuicSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        QuicSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicSocketDelete(client);
    QuicSocketDelete(server);

    QuicDataPathUninitialize(
        Datapath);

    QuicEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, UdpDataRebind)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* server = nullptr;
    QUIC_SOCKET* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            &UdpRecvCallbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicSocketCreateUdp(
                Datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
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
    QuicSocketGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        QuicSendDataAlloc(client, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        QuicSendDataAllocBuffer(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    QuicSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        QuicSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicSocketDelete(client);
    client = nullptr;
    QuicEventReset(RecvContext.ClientCompletion);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    ClientSendContext =
        QuicSendDataAlloc(client, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    ClientDatagram =
        QuicSendDataAllocBuffer(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    QuicSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        QuicSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicSocketDelete(client);
    QuicSocketDelete(server);

    QuicDataPathUninitialize(
        Datapath);

    QuicEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, UdpDataECT0)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* server = nullptr;
    QUIC_SOCKET* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            &UdpRecvECT0Callbacks,
            nullptr,
            &Datapath));
    ASSERT_NE(nullptr, Datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicSocketCreateUdp(
                Datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
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
    QuicSocketGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateUdp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        QuicSendDataAlloc(client, QUIC_ECN_ECT_0, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        QuicSendDataAllocBuffer(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    QuicSocketGetLocalAddress(client, &ClientAddress);

    VERIFY_QUIC_SUCCESS(
        QuicSocketSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicSocketDelete(client);
    QuicSocketDelete(server);

    QuicDataPathUninitialize(
        Datapath);

    QuicEventUninitialize(RecvContext.ClientCompletion);
}

TEST_F(DataPathTest, TcpListener)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* Socket = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            nullptr,
            &EmptyTcpCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateTcpListener(
            Datapath,
            nullptr,
            nullptr,
            &Socket));
    ASSERT_NE(nullptr, Socket);

    QUIC_ADDR Address;
    QuicSocketGetLocalAddress(Socket, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);

    QuicSocketDelete(Socket);

    QuicDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, TcpConnect)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* Listener = nullptr;
    QUIC_SOCKET* Server = nullptr;
    QUIC_SOCKET* Client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            nullptr,
            &TcpRecvCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicSocketCreateTcpListener(
                Datapath,
                &serverAddress.SockAddr,
                &Server,
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
    QuicSocketGetLocalAddress(Listener, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(Address.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateTcp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            nullptr,
            &Client));
    ASSERT_NE(nullptr, Client);

    //ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    QuicSleep(100);

    ASSERT_NE(nullptr, Server);

    QuicSocketDelete(Client);
    QuicSocketDelete(Server);
    QuicSocketDelete(Listener);

    QuicDataPathUninitialize(
        Datapath);
}

TEST_P(DataPathTest, TcpData)
{
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_SOCKET* Listener = nullptr;
    QUIC_SOCKET* Server = nullptr;
    QUIC_SOCKET* Client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            nullptr,
            &TcpRecvCallbacks,
            &Datapath));
    ASSERT_NE(Datapath, nullptr);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicSocketCreateTcpListener(
                Datapath,
                &serverAddress.SockAddr,
                &Server,
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
    QuicSocketGetLocalAddress(Listener, &ServerAddress);
    ASSERT_NE(ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicSocketCreateTcp(
            Datapath,
            nullptr,
            &serverAddress.SockAddr,
            nullptr,
            &Client));
    ASSERT_NE(nullptr, Client);

    auto ClientSendContext =
        QuicSendDataAlloc(Client, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        QuicSendDataAllocBuffer(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ClientAddress;
    QuicSocketGetLocalAddress(Client, &ClientAddress);

    QuicSleep(100); // Wait for connected

    VERIFY_QUIC_SUCCESS(
        QuicSocketSend(
            Client,
            &ClientAddress,
            &ServerAddress,
            ClientSendContext));

    //ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    QuicSleep(100);

    ASSERT_NE(nullptr, Server);

    QuicSocketDelete(Client);
    QuicSocketDelete(Server);
    QuicSocketDelete(Listener);

    QuicDataPathUninitialize(
        Datapath);
}

INSTANTIATE_TEST_SUITE_P(DataPathTest, DataPathTest, ::testing::Values(4, 6), testing::PrintToStringParamName());
