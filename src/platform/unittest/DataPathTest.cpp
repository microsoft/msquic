/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath User Mode Unit test

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
        if (QuicAddrGetFamily(&SockAddr) == AF_INET) {
            return SockAddr.Ipv4.sin_port;
        } else {
            return SockAddr.Ipv6.sin6_port;
        }
    }

    #undef SetPort
    void SetPort(uint16_t port) {
        if (QuicAddrGetFamily(&SockAddr) == AF_INET) {
            SockAddr.Ipv4.sin_port = port;
        } else {
            SockAddr.Ipv6.sin6_port = port;
        }
    }

    QuicAddr() {
        QuicZeroMemory(this, sizeof(*this));
    }

    void Resolve(QUIC_ADDRESS_FAMILY af, const char* hostname) {
        QUIC_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            QuicDataPathInitialize(
                0,
                (QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER)(1),
                (QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER)(1),
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

        LocalIPv4.Resolve(AF_INET, "localhost");
        LocalIPv6.Resolve(AF_INET6, "localhost");

        ExpectedData = (char*)QUIC_ALLOC_NONPAGED(ExpectedDataSize);
        ASSERT_NE(ExpectedData, nullptr);
    }

    static void TearDownTestSuite()
    {
        QUIC_FREE(ExpectedData);
    }

    static void
    EmptyReceiveCallback(
        _In_ QUIC_DATAPATH_BINDING* /* Binding */,
        _In_ void * /* RecvContext */,
        _In_ QUIC_RECV_DATAGRAM* /* RecvPacketChain */
        )
    {
    }

    static void
    EmptyUnreachableCallback(
        _In_ QUIC_DATAPATH_BINDING* /* Binding */,
        _In_ void * /* Context */,
        _In_ const QUIC_ADDR* /* RemoteAddress */
        )
    {
    }

    static void
    DataRecvCallback(
        _In_ QUIC_DATAPATH_BINDING* binding,
        _In_ void * recvContext,
        _In_ QUIC_RECV_DATAGRAM* recvBufferChain
        )
    {
        DataRecvContext* RecvContext = (DataRecvContext*)recvContext;
        ASSERT_NE(nullptr, RecvContext);

        QUIC_RECV_DATAGRAM* recvBuffer = recvBufferChain;

        while (recvBuffer != NULL) {
            ASSERT_EQ(recvBuffer->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(recvBuffer->Buffer, ExpectedData, ExpectedDataSize));

            if (recvBuffer->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                auto ServerSendContext =
                    QuicDataPathBindingAllocSendContext(binding, 0);
                ASSERT_NE(nullptr, ServerSendContext);

                auto ServerDatagram =
                    QuicDataPathBindingAllocSendDatagram(ServerSendContext, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerDatagram);

                memcpy(ServerDatagram->Buffer, recvBuffer->Buffer, recvBuffer->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    QuicDataPathBindingSendFromTo(
                        binding,
                        &recvBuffer->Tuple->LocalAddress,
                        &recvBuffer->Tuple->RemoteAddress,
                        ServerSendContext
                    ));

            } else {
                QuicEventSet(RecvContext->ClientCompletion);
            }

            recvBuffer = recvBuffer->Next;
        }

        QuicDataPathBindingReturnRecvDatagrams(recvBufferChain);
    }
};

volatile uint16_t DataPathTest::NextPort;
QuicAddr DataPathTest::LocalIPv4;
QuicAddr DataPathTest::LocalIPv6;

TEST_F(DataPathTest, Initialize)
{
    QUIC_DATAPATH* datapath = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(datapath, nullptr);

    QuicDataPathUninitialize(
        datapath);
}

TEST_F(DataPathTest, InitializeInvalid)
{
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        QuicDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            nullptr));

    QUIC_DATAPATH* datapath = nullptr;
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        QuicDataPathInitialize(
            0,
            nullptr,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER,
        QuicDataPathInitialize(
            0,
            EmptyReceiveCallback,
            nullptr,
            &datapath));
}

TEST_F(DataPathTest, Bind)
{
    QUIC_DATAPATH* datapath = nullptr;
    QUIC_DATAPATH_BINDING* binding = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(datapath, nullptr);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingCreate(
            datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding));
    ASSERT_NE(nullptr, binding);

    QUIC_ADDR Address;
    QuicDataPathBindingGetLocalAddress(binding, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);

    QuicDataPathBindingDelete(binding);

    QuicDataPathUninitialize(
        datapath);
}

TEST_F(DataPathTest, Rebind)
{
    QUIC_DATAPATH* datapath = nullptr;
    QUIC_DATAPATH_BINDING* binding1 = nullptr;
    QUIC_DATAPATH_BINDING* binding2 = nullptr;

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingCreate(
            datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding1));
    ASSERT_NE(nullptr, binding1);

    QUIC_ADDR Address1;
    QuicDataPathBindingGetLocalAddress(binding1, &Address1);
    ASSERT_NE(Address1.Ipv4.sin_port, (uint16_t)0);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingCreate(
            datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding2));
    ASSERT_NE(nullptr, binding2);

    QUIC_ADDR Address2;
    QuicDataPathBindingGetLocalAddress(binding2, &Address2);
    ASSERT_NE(Address2.Ipv4.sin_port, (uint16_t)0);

    QuicDataPathBindingDelete(binding1);
    QuicDataPathBindingDelete(binding2);

    QuicDataPathUninitialize(
        datapath);
}

TEST_P(DataPathTest, Data)
{
    QUIC_DATAPATH* datapath = nullptr;
    QUIC_DATAPATH_BINDING* server = nullptr;
    QUIC_DATAPATH_BINDING* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            DataRecvCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicDataPathBindingCreate(
                datapath,
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
    QuicDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        QuicDataPathBindingAllocSendContext(client, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        QuicDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingSendTo(
            client,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicDataPathBindingDelete(client);
    QuicDataPathBindingDelete(server);

    QuicDataPathUninitialize(
        datapath);

    QuicEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, DataRebind)
{
    QUIC_DATAPATH* datapath = nullptr;
    QUIC_DATAPATH_BINDING* server = nullptr;
    QUIC_DATAPATH_BINDING* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathInitialize(
            0,
            DataRecvCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            QuicDataPathBindingCreate(
                datapath,
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
    QuicDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        QuicDataPathBindingAllocSendContext(client, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        QuicDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingSendTo(
            client,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicDataPathBindingDelete(client);
    client = nullptr;
    QuicEventReset(RecvContext.ClientCompletion);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    ClientSendContext =
        QuicDataPathBindingAllocSendContext(client, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    ClientDatagram =
        QuicDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(
        QuicDataPathBindingSendTo(
            client,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    QuicDataPathBindingDelete(client);
    QuicDataPathBindingDelete(server);

    QuicDataPathUninitialize(
        datapath);

    QuicEventUninitialize(RecvContext.ClientCompletion);
}

INSTANTIATE_TEST_SUITE_P(DataPathTest, DataPathTest, ::testing::Values(4, 6), testing::PrintToStringParamName());
