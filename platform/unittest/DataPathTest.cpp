/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath User Mode Unit test

--*/

#include "quic_platform.h"
#include "quic_datapath.h"
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>

#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

#include "msquic.h"
#include "quic_trace.h"

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
#include "datapathtest.tmh"
#endif

using namespace WEX::Logging;

#define VERIFY_QUIC_SUCCESS(result, ...) VERIFY_ARE_EQUAL(QUIC_STATUS_SUCCESS, result, __VA_ARGS__)

const uint32_t ExpectedDataSize = 1 * 1024;
char* ExpectedData;

//
// Helper class for managing the memory of a IP address.
//
struct QuicAddr
{
    SOCKADDR_INET SockAddr;

    UINT16 Port() {
        if (SockAddr.si_family == AF_INET) {
            return SockAddr.Ipv4.sin_port;
        } else {
            return SockAddr.Ipv6.sin6_port;
        }
    }

    #undef SetPort
    void SetPort(UINT16 port) {
        if (SockAddr.si_family == AF_INET) {
            SockAddr.Ipv4.sin_port = port;
        } else {
            SockAddr.Ipv6.sin6_port = port;
        }
    }

    QuicAddr() {
        ZeroMemory(this, sizeof(*this));
    }

    void Resolve(QUIC_ADDRESS_FAMILY af, PSTR hostname) {
        WSADATA wsaData;
        ADDRINFOA hints = { 0 };
        ADDRINFOA *ai;

        //
        // Prepopulate hint with input family.
        //
        hints.ai_family = af;
        hints.ai_flags = AI_CANONNAME;

        VERIFY_ARE_EQUAL(
            WSAStartup(MAKEWORD(2, 2), &wsaData),
            (int)0);

        VERIFY_ARE_EQUAL(
            GetAddrInfoA(hostname, nullptr, &hints, &ai),
            (int)0);

        memcpy(&SockAddr, ai->ai_addr, ai->ai_addrlen);

        FreeAddrInfoA(ai);
        WSACleanup();
    }
};

struct DataPathTest : public WEX::TestClass<DataPathTest>
{
    volatile uint16_t NextPort;
    QuicAddr LocalIPv4;
    QuicAddr LocalIPv6;

    //
    // Helper to get a new port to bind to.
    //
    UINT16
    GetNextPort()
    {
        return htons((UINT16)InterlockedIncrement16((PSHORT)&NextPort));
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
        int addressFamily;
        VERIFY_SUCCEEDED(WEX::TestExecution::TestData::TryGetValue(L"Family", addressFamily));

        if (addressFamily == 4) {
            return GetNewLocalIPv4(randomPort);
        } else if (addressFamily == 6) {
            return GetNewLocalIPv6(randomPort);
        } else {
            VERIFY_FAIL(L"Malconfigured test data; This should never happen!!");
            return QuicAddr();
        }
    }

    BEGIN_TEST_CLASS(DataPathTest)
        TEST_CLASS_PROPERTY(L"Data:Family", L"{4,6}")
    END_TEST_CLASS()

    TEST_CLASS_SETUP(Setup)
    {
        //
        // Initialize a semi-random base port number.
        //
        NextPort = 50000 + (GetCurrentProcessId() % 10000) + (rand() % 5000);

        LocalIPv4.Resolve(AF_INET, "localhost");
        LocalIPv6.Resolve(AF_INET6, "localhost");

        ExpectedData = (char*)LocalAlloc(NONZEROLPTR, ExpectedDataSize);
        return ExpectedData != nullptr;
    }

    TEST_CLASS_CLEANUP(Cleanup)
    {
        LocalFree(ExpectedData);
        return true;
    }

    static void
    EmptyReceiveCallback(
        _In_ QUIC_DATAPATH_BINDING* /* Binding */,
        _In_ PVOID /* RecvContext */,
        _In_ QUIC_RECV_DATAGRAM* /* RecvPacketChain */
        )
    {
    }

    static void
    EmptyUnreachableCallback(
        _In_ QUIC_DATAPATH_BINDING* /* Binding */,
        _In_ PVOID /* Context */,
        _In_ const SOCKADDR_INET* /* RemoteAddress */
        )
    {
    }

    TEST_METHOD(Initialize)
    {
        QUIC_DATAPATH* datapath = nullptr;

        VERIFY_QUIC_SUCCESS(
            QuicDataPathInitialize(
                0,
                EmptyReceiveCallback,
                EmptyUnreachableCallback,
                &datapath));
        VERIFY_IS_NOT_NULL(datapath);

        QuicDataPathUninitialize(
            datapath);
    }

    TEST_METHOD(InitializeInvalid)
    {
        VERIFY_ARE_EQUAL(QUIC_STATUS_INVALID_PARAMETER,
            QuicDataPathInitialize(
                0,
                EmptyReceiveCallback,
                EmptyUnreachableCallback,
                nullptr));

        QUIC_DATAPATH* datapath = nullptr;
        VERIFY_ARE_EQUAL(QUIC_STATUS_INVALID_PARAMETER,
            QuicDataPathInitialize(
                0,
                nullptr,
                EmptyUnreachableCallback,
                &datapath));
        VERIFY_ARE_EQUAL(QUIC_STATUS_INVALID_PARAMETER,
            QuicDataPathInitialize(
                0,
                EmptyReceiveCallback,
                nullptr,
                &datapath));
    }

    TEST_METHOD(Bind)
    {
        QUIC_DATAPATH* datapath = nullptr;
        QUIC_DATAPATH_BINDING* binding = nullptr;

        VERIFY_QUIC_SUCCESS(
            QuicDataPathInitialize(
                0,
                EmptyReceiveCallback,
                EmptyUnreachableCallback,
                &datapath));
        VERIFY_IS_NOT_NULL(datapath);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingCreate(
                datapath,
                nullptr,
                nullptr,
                nullptr,
                &binding));
        VERIFY_IS_NOT_NULL(binding);

        SOCKADDR_INET Address;
        QuicDataPathBindingGetLocalAddress(binding, &Address);
        VERIFY_ARE_NOT_EQUAL(Address.Ipv4.sin_port, (UINT16)0);

        QuicDataPathBindingDelete(binding);

        QuicDataPathUninitialize(
            datapath);
    }

    TEST_METHOD(Rebind)
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
        VERIFY_IS_NOT_NULL(datapath);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingCreate(
                datapath,
                nullptr,
                nullptr,
                nullptr,
                &binding1));
        VERIFY_IS_NOT_NULL(binding1);

        SOCKADDR_INET Address1;
        QuicDataPathBindingGetLocalAddress(binding1, &Address1);
        VERIFY_ARE_NOT_EQUAL(Address1.Ipv4.sin_port, (UINT16)0);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingCreate(
                datapath,
                nullptr,
                nullptr,
                nullptr,
                &binding2));
        VERIFY_IS_NOT_NULL(binding2);

        SOCKADDR_INET Address2;
        QuicDataPathBindingGetLocalAddress(binding2, &Address2);
        VERIFY_ARE_NOT_EQUAL(Address2.Ipv4.sin_port, (UINT16)0);

        QuicDataPathBindingDelete(binding1);
        QuicDataPathBindingDelete(binding2);

        QuicDataPathUninitialize(
            datapath);
    }

    struct DataRecvContext {
        SOCKADDR_INET ServerAddress;
        HANDLE ClientCompletion;
    };

    static void
    DataRecvCallback(
        _In_ QUIC_DATAPATH_BINDING* binding,
        _In_ PVOID recvContext,
        _In_ QUIC_RECV_DATAGRAM* recvBufferChain
        )
    {
        DataRecvContext* RecvContext = (DataRecvContext*)recvContext;
        VERIFY_IS_NOT_NULL(RecvContext);

        QUIC_RECV_DATAGRAM* recvBuffer = recvBufferChain;

        while (recvBuffer != NULL) {
            VERIFY_ARE_EQUAL(recvBuffer->BufferLength, ExpectedDataSize);
            VERIFY_ARE_EQUAL(0, memcmp(recvBuffer->Buffer, ExpectedData, ExpectedDataSize));

            if (recvBuffer->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                auto ServerSendContext =
                    QuicDataPathBindingAllocSendContext(binding, 0);
                VERIFY_IS_NOT_NULL(ServerSendContext);

                auto ServerDatagram =
                    QuicDataPathBindingAllocSendDatagram(ServerSendContext, ExpectedDataSize);
                VERIFY_IS_NOT_NULL(ServerDatagram);

                memcpy(ServerDatagram->Buffer, recvBuffer->Buffer, recvBuffer->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    QuicDataPathBindingSendFromTo(
                        binding,
                        &recvBuffer->Tuple->LocalAddress,
                        &recvBuffer->Tuple->RemoteAddress,
                        ServerSendContext
                    ));

            } else {

                VERIFY_ARE_EQUAL(TRUE, SetEvent(RecvContext->ClientCompletion));
            }

            recvBuffer = recvBuffer->Next;
        }

        QuicDataPathBindingReturnRecvDatagrams(recvBufferChain);
    }

    TEST_METHOD(Data)
    {
        QUIC_DATAPATH* datapath = nullptr;
        QUIC_DATAPATH_BINDING* server = nullptr;
        QUIC_DATAPATH_BINDING* client = nullptr;
        auto serverAddress = GetNewLocalAddr();

        DataRecvContext RecvContext =
        {
            { 0 },
            CreateEvent(nullptr, FALSE, FALSE, nullptr)
        };

        VERIFY_QUIC_SUCCESS(
            QuicDataPathInitialize(
                0,
                DataRecvCallback,
                EmptyUnreachableCallback,
                &datapath));
        VERIFY_IS_NOT_NULL(datapath);

        QUIC_STATUS Status = WSAEADDRINUSE;
        while (Status == WSAEADDRINUSE) {
            serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
            Status =
                QuicDataPathBindingCreate(
                    datapath,
                    &serverAddress.SockAddr,
                    nullptr,
                    &RecvContext,
                    &server);
        }
        VERIFY_QUIC_SUCCESS(Status);
        VERIFY_IS_NOT_NULL(server);
        QuicDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
        VERIFY_ARE_NOT_EQUAL(RecvContext.ServerAddress.Ipv4.sin_port, (UINT16)0);
        serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingCreate(
                datapath,
                nullptr,
                &serverAddress.SockAddr,
                &RecvContext,
                &client));
        VERIFY_IS_NOT_NULL(client);

        auto ClientSendContext =
            QuicDataPathBindingAllocSendContext(client, 0);
        VERIFY_IS_NOT_NULL(ClientSendContext);

        auto ClientDatagram =
            QuicDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
        VERIFY_IS_NOT_NULL(ClientDatagram);

        memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingSendTo(
                client,
                &serverAddress.SockAddr,
                ClientSendContext));

        VERIFY_ARE_EQUAL((DWORD)WAIT_OBJECT_0, WaitForSingleObject(RecvContext.ClientCompletion, 2000));

        QuicDataPathBindingDelete(client);
        QuicDataPathBindingDelete(server);

        QuicDataPathUninitialize(
            datapath);

        CloseHandle(RecvContext.ClientCompletion);
    }

    TEST_METHOD(DataRebind)
    {
        QUIC_DATAPATH* datapath = nullptr;
        QUIC_DATAPATH_BINDING* server = nullptr;
        QUIC_DATAPATH_BINDING* client = nullptr;
        auto serverAddress = GetNewLocalAddr();

        DataRecvContext RecvContext =
        {
            { 0 },
            CreateEvent(nullptr, FALSE, FALSE, nullptr)
        };

        VERIFY_QUIC_SUCCESS(
            QuicDataPathInitialize(
                0,
                DataRecvCallback,
                EmptyUnreachableCallback,
                &datapath));
        VERIFY_IS_NOT_NULL(datapath);

        QUIC_STATUS Status = WSAEADDRINUSE;
        while (Status == WSAEADDRINUSE) {
            serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
            Status =
                QuicDataPathBindingCreate(
                    datapath,
                    &serverAddress.SockAddr,
                    nullptr,
                    &RecvContext,
                    &server);
        }
        VERIFY_QUIC_SUCCESS(Status);
        VERIFY_IS_NOT_NULL(server);
        QuicDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
        VERIFY_ARE_NOT_EQUAL(RecvContext.ServerAddress.Ipv4.sin_port, (UINT16)0);
        serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingCreate(
                datapath,
                nullptr,
                &serverAddress.SockAddr,
                &RecvContext,
                &client));
        VERIFY_IS_NOT_NULL(client);

        auto ClientSendContext =
            QuicDataPathBindingAllocSendContext(client, 0);
        VERIFY_IS_NOT_NULL(ClientSendContext);

        auto ClientDatagram =
            QuicDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
        VERIFY_IS_NOT_NULL(ClientDatagram);

        memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingSendTo(
                client,
                &serverAddress.SockAddr,
                ClientSendContext));

        VERIFY_ARE_EQUAL((DWORD)WAIT_OBJECT_0, WaitForSingleObject(RecvContext.ClientCompletion, 2000));

        QuicDataPathBindingDelete(client);
        client = nullptr;
        ResetEvent(RecvContext.ClientCompletion);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingCreate(
                datapath,
                nullptr,
                &serverAddress.SockAddr,
                &RecvContext,
                &client));
        VERIFY_IS_NOT_NULL(client);

        ClientSendContext =
            QuicDataPathBindingAllocSendContext(client, 0);
        VERIFY_IS_NOT_NULL(ClientSendContext);

        ClientDatagram =
            QuicDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
        VERIFY_IS_NOT_NULL(ClientDatagram);

        memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

        VERIFY_QUIC_SUCCESS(
            QuicDataPathBindingSendTo(
                client,
                &serverAddress.SockAddr,
                ClientSendContext));

        VERIFY_ARE_EQUAL((DWORD)WAIT_OBJECT_0, WaitForSingleObject(RecvContext.ClientCompletion, 2000));

        QuicDataPathBindingDelete(client);
        QuicDataPathBindingDelete(server);

        QuicDataPathUninitialize(
            datapath);

        CloseHandle(RecvContext.ClientCompletion);
    }
};
