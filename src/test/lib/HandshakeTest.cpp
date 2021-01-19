/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests handshake related features and functionality.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "HandshakeTest.cpp.clog.h"
#endif

QUIC_TEST_DATAPATH_HOOKS DatapathHooks::FuncTable = {
    DatapathHooks::ReceiveCallback,
    DatapathHooks::SendCallback
};
DatapathHooks* DatapathHooks::Instance;

void QuicTestInitialize()
{
    DatapathHooks::Instance = new(std::nothrow) DatapathHooks;
}

void QuicTestUninitialize()
{
    delete DatapathHooks::Instance;
    DatapathHooks::Instance = nullptr;
}

void
QuicTestPrimeResumption(
    _In_ MsQuicRegistration& Registration,
    _In_ MsQuicConfiguration& ServerConfiguration,
    _In_ MsQuicConfiguration& ClientConfiguration,
    _Out_ QUIC_BUFFER** ResumptionTicket
    )
{
    TestScopeLogger logScope("PrimeResumption");
    *ResumptionTicket = nullptr;

    struct PrimeResumption {
        _Function_class_(NEW_CONNECTION_CALLBACK) static bool
        ListenerAccept(_In_ TestListener* /* Listener */, _In_ HQUIC ConnectionHandle) {
            auto NewConnection = new(std::nothrow) TestConnection(ConnectionHandle);
            if (NewConnection == nullptr || !NewConnection->IsValid()) {
                TEST_FAILURE("Failed to accept new TestConnection.");
                delete NewConnection;
                return false;
            }
            NewConnection->SetAutoDelete();
            return true;
        }
    };

    TestListener Listener(Registration, PrimeResumption::ListenerAccept, ServerConfiguration);
    TEST_TRUE(Listener.IsValid());

    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    {
        TestConnection Client(Registration);
        TEST_TRUE(Client.IsValid());
        TEST_QUIC_SUCCEEDED(
            Client.Start(
                ClientConfiguration,
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                QUIC_LOCALHOST_FOR_AF(QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                ServerLocalAddr.GetPort()));
        if (Client.WaitForConnectionComplete()) {
            TEST_TRUE(Client.GetIsConnected());
            *ResumptionTicket = Client.WaitForResumptionTicket();
            if (*ResumptionTicket == nullptr) {
                TEST_FAILURE("Failed to prime resumption ticket.");
            }
        }

        Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    }
}

struct ServerAcceptContext {
    CXPLAT_EVENT NewConnectionReady;
    TestConnection** NewConnection;
    ServerAcceptContext(TestConnection** _NewConnection) :
        NewConnection(_NewConnection) {
        CxPlatEventInitialize(&NewConnectionReady, TRUE, FALSE);
    }
    ~ServerAcceptContext() {
        CxPlatEventUninitialize(NewConnectionReady);
    }
};

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerAcceptConnection(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    ServerAcceptContext* AcceptContext = (ServerAcceptContext*)Listener->Context;
    *AcceptContext->NewConnection = new(std::nothrow) TestConnection(ConnectionHandle);
    if (*AcceptContext->NewConnection == nullptr || !(*AcceptContext->NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *AcceptContext->NewConnection;
        *AcceptContext->NewConnection = nullptr;
        return false;
    }
    (*AcceptContext->NewConnection)->SetHasRandomLoss(Listener->GetHasRandomLoss());
    CxPlatEventSet(AcceptContext->NewConnectionReady);
    return true;
}

void
QuicTestConnect(
    _In_ int Family,
    _In_ bool ServerStatelessRetry,
    _In_ bool ClientUsesOldVersion,
    _In_ bool MultipleALPNs,
    _In_ bool AsyncConfiguration,
    _In_ bool MultiPacketClientInitial,
    _In_ bool SessionResumption,
    _In_ uint8_t RandomLossPercentage
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn1("MsQuicTest");
    MsQuicAlpn Alpn2("MsQuicTest2", "MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(4);
    if (RandomLossPercentage != 0) {
        Settings.SetIdleTimeoutMs(30000);
        Settings.SetDisconnectTimeoutMs(30000);
    } else {
        Settings.SetIdleTimeoutMs(10000);
    }
    if (SessionResumption) {
        Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY);
    }

    MsQuicConfiguration ServerConfiguration(Registration, Alpn2, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn1, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_BUFFER* ResumptionTicket = nullptr;
    if (SessionResumption) {
        QuicTestPrimeResumption(
            Registration,
            ServerConfiguration,
            ClientConfiguration,
            &ResumptionTicket);
        if (!ResumptionTicket) {
            return;
        }
    }

    StatelessRetryHelper RetryHelper(ServerStatelessRetry);
    PrivateTransportHelper TpHelper(MultiPacketClientInitial);
    RandomLossHelper LossHelper(RandomLossPercentage);

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    {
        TestListener Listener(
            Registration,
            ListenerAcceptConnection,
            (AsyncConfiguration ? (HQUIC)nullptr : (HQUIC)ServerConfiguration));
        TEST_TRUE(Listener.IsValid());
        Listener.SetHasRandomLoss(RandomLossPercentage != 0);

        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(MultipleALPNs ? Alpn2 : Alpn1, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());
                Client.SetHasRandomLoss(RandomLossPercentage != 0);

                if (ClientUsesOldVersion) {
                    TEST_QUIC_SUCCEEDED(
                        Client.SetQuicVersion(OLD_SUPPORTED_VERSION));
                }

                if (MultiPacketClientInitial) {
                    TEST_QUIC_SUCCEEDED(
                        Client.SetTestTransportParameter(&TpHelper));
                }

                if (SessionResumption) {
                    Client.SetResumptionTicket(ResumptionTicket);
                    CXPLAT_FREE(ResumptionTicket, QUIC_POOL_TEST);
                    Client.SetExpectedResumed(true);
                }

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (AsyncConfiguration) {
                    if (!CxPlatEventWaitWithTimeout(ServerAcceptCtx.NewConnectionReady, TestWaitTimeout)) {
                        TEST_FAILURE("Timed out waiting for server accept.");
                    } else if (Server == nullptr) {
                        TEST_FAILURE("Failed to accept server connection.");
                    } else {
                        TEST_QUIC_SUCCEEDED(
                            Server->SetConfiguration(ServerConfiguration));
                    }
                }

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                if (ClientUsesOldVersion) {
                    TEST_EQUAL(Server->GetQuicVersion(), OLD_SUPPORTED_VERSION);
                } else {
                    TEST_EQUAL(Server->GetQuicVersion(), LATEST_SUPPORTED_VERSION);
                }

                if (ServerStatelessRetry) {
                    TEST_TRUE(Client.GetStatistics().StatelessRetry);
                }

                if (SessionResumption) {
                    TEST_TRUE(Client.GetResumed());
                    TEST_TRUE(Server->GetResumed());
                }

                TEST_EQUAL(
                    Server->GetPeerBidiStreamCount(),
                    Client.GetLocalBidiStreamCount());

                if (RandomLossPercentage == 0) {
                    //
                    // Don't worry about graceful shutdown if we have random
                    // loss. It will likely just result in the maximum wait
                    // timeout, causing the test to run longer.
                    //
                    Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                    if (!Client.WaitForShutdownComplete()) {
                        return;
                    }

                    TEST_FALSE(Client.GetPeerClosed());
                    TEST_FALSE(Client.GetTransportClosed());
                }
            }

            if (RandomLossPercentage == 0) {
                TEST_TRUE(Server->GetPeerClosed());
                TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
            } else {
                Server->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
            }
        }
    }
}

void
QuicTestNatPortRebind(
    _In_ int Family
    )
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                QuicAddr OrigLocalAddr;
                TEST_QUIC_SUCCEEDED(Client.GetLocalAddr(OrigLocalAddr));
                QuicAddr NewLocalAddr(OrigLocalAddr, 1);
                CxPlatSleep(100);

                ReplaceAddressHelper AddrHelper(OrigLocalAddr.SockAddr, NewLocalAddr.SockAddr);
                TEST_FALSE(Client.GetIsShutdown());
                Client.SetKeepAlive(25);

                bool ServerAddressUpdated = false;
                uint32_t Try = 0;
                do {
                    if (Try != 0) {
                        CxPlatSleep(200);
                    }
                    QuicAddr ServerRemoteAddr;
                    TEST_QUIC_SUCCEEDED(Server->GetRemoteAddr(ServerRemoteAddr));
                    if (Server->GetPeerAddrChanged() &&
                        QuicAddrCompare(&NewLocalAddr.SockAddr, &ServerRemoteAddr.SockAddr)) {
                        ServerAddressUpdated = true;
                        break;
                    }
                } while (++Try <= 3);
                TEST_TRUE(ServerAddressUpdated);

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }

            TEST_TRUE(Server->GetPeerClosed());
            TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
        }
    }
}

void
QuicTestNatAddrRebind(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(10000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                QuicAddr OrigLocalAddr;
                TEST_QUIC_SUCCEEDED(Client.GetLocalAddr(OrigLocalAddr));
                QuicAddr NewLocalAddr(OrigLocalAddr, 1);
                NewLocalAddr.IncrementAddr();
                CxPlatSleep(100);

                ReplaceAddressHelper AddrHelper(OrigLocalAddr.SockAddr, NewLocalAddr.SockAddr);
                TEST_FALSE(Client.GetIsShutdown());
                Client.SetKeepAlive(25);

                bool ServerAddressUpdated = false;
                uint32_t Try = 0;
                do {
                    if (Try != 0) {
                        CxPlatSleep(200);
                    }
                    QuicAddr ServerRemoteAddr;
                    TEST_QUIC_SUCCEEDED(Server->GetRemoteAddr(ServerRemoteAddr));
                    if (Server->GetPeerAddrChanged() &&
                        QuicAddrCompare(&NewLocalAddr.SockAddr, &ServerRemoteAddr.SockAddr)) {
                        ServerAddressUpdated = true;
                        break;
                    }
                } while (++Try <= 3);
                TEST_TRUE(ServerAddressUpdated);

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }

            TEST_TRUE(Server->GetPeerClosed());
            TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
        }
    }
}

void
QuicTestPathValidationTimeout(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(10000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                Server->SetExpectedTransportCloseStatus(QUIC_STATUS_CONNECTION_TIMEOUT);
                TEST_QUIC_SUCCEEDED(Server->SetDisconnectTimeout(1000)); // ms

                QuicAddr OrigLocalAddr;
                TEST_QUIC_SUCCEEDED(Client.GetLocalAddr(OrigLocalAddr));
                QuicAddr NewLocalAddr(OrigLocalAddr, 1);
                CxPlatSleep(100);

                ReplaceAddressThenDropHelper AddrHelper(OrigLocalAddr.SockAddr, NewLocalAddr.SockAddr, 1);
                TEST_FALSE(Client.GetIsShutdown());
                Client.SetKeepAlive(25);

                CxPlatSleep(200);
                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, QUIC_TEST_NO_ERROR);
            }

            if (!Server->WaitForShutdownComplete()) {
                return;
            }
        }
    }
}

void
QuicTestChangeMaxStreamID(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(10000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));


        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                TEST_EQUAL(
                    Server->GetPeerBidiStreamCount(),
                    Client.GetLocalBidiStreamCount());

                TEST_QUIC_SUCCEEDED(Client.SetPeerBidiStreamCount(101));
                TEST_EQUAL(101, Client.GetPeerBidiStreamCount());
                CxPlatSleep(100);
                TEST_EQUAL(101, Server->GetLocalBidiStreamCount());

                TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount(100));
                TEST_EQUAL(100, Server->GetPeerBidiStreamCount());
                CxPlatSleep(100);
                TEST_EQUAL(100, Client.GetLocalBidiStreamCount());

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }

            TEST_TRUE(Server->GetPeerClosed());
            TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
        }
    }
}

void
QuicTestConnectAndIdle(
    _In_ bool EnableKeepAlive
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                if (!EnableKeepAlive) {
                    Client.SetExpectedTransportCloseStatus(QUIC_STATUS_CONNECTION_IDLE);
                }

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QUIC_ADDRESS_FAMILY_UNSPEC,
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!EnableKeepAlive) {
                    Server->SetExpectedTransportCloseStatus(QUIC_STATUS_CONNECTION_IDLE);
                }
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                if (EnableKeepAlive) {
                    TEST_QUIC_SUCCEEDED(Client.SetKeepAlive(1000));
                }

                CxPlatSleep(4000); // Wait for the first idle period to expire.

                if (EnableKeepAlive) {
                    TEST_FALSE(Client.GetIsShutdown());
                    TEST_FALSE(Server->GetIsShutdown());

                    Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                    if (!Client.WaitForShutdownComplete()) {
                        return;
                    }

                    TEST_FALSE(Client.GetPeerClosed());
                    TEST_FALSE(Client.GetTransportClosed());

#if !QUIC_SEND_FAKE_LOSS
                    TEST_TRUE(Server->GetPeerClosed());
                    TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
#endif
                } else {
                    TEST_TRUE(Client.GetIsShutdown());
                    TEST_TRUE(Server->GetIsShutdown());
                    TEST_TRUE(Client.GetTransportClosed());
                    TEST_TRUE(Server->GetTransportClosed());
                }
            }
        }
    }
}

void
QuicTestConnectUnreachable(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

        TestConnection Client(Registration);
        TEST_TRUE(Client.IsValid());

        Client.SetExpectedTransportCloseStatus(QUIC_STATUS_UNREACHABLE);
        TEST_QUIC_SUCCEEDED(
            Client.Start(
                ClientConfiguration,
                QuicAddrFamily,
                QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                TestUdpPortBase - 1));
        if (!Client.WaitForConnectionComplete()) {
            return;
        }

        TEST_FALSE(Client.GetIsConnected());
        TEST_TRUE(Client.GetTransportClosed());
    }
}

void
QuicTestVersionNegotiation(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.SetQuicVersion(168430090ul)); // Random reserved version to force VN.

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));
                if (!Client.WaitForConnectionComplete()) {
                    return;
                }

                TEST_TRUE(Client.GetIsConnected());
                TEST_TRUE(Client.GetStatistics().VersionNegotiation);
                TEST_EQUAL(Client.GetQuicVersion(), LATEST_SUPPORTED_VERSION);
            }
        }
    }
}

void
QuicTestConnectBadAlpn(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "BanALPN", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                Client.SetExpectedTransportCloseStatus(QUIC_STATUS_ALPN_NEG_FAILURE);
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));
                if (!Client.WaitForConnectionComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetIsConnected());
                TEST_TRUE(Client.GetTransportClosed());

                TEST_EQUAL(nullptr, Server);
            }
        }
    }
}

void
QuicTestConnectBadSni(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                QuicAddr RemoteAddr(Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));

                Client.SetExpectedTransportCloseStatus(QUIC_STATUS_CONNECTION_REFUSED);
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6,
                        "badlocalhost",
                        ServerLocalAddr.GetPort()));
                if (!Client.WaitForConnectionComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetIsConnected());
                TEST_TRUE(Client.GetTransportClosed());

                TEST_EQUAL(nullptr, Server);
            }
        }
    }
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerRejectConnection(
    _In_ TestListener* /*  Listener */,
    _In_ HQUIC ConnectionHandle
    )
{
    auto Connection = new(std::nothrow) TestConnection(ConnectionHandle);
    if (Connection == nullptr || !Connection->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete Connection;
        return false;
    }
    Connection->SetAutoDelete();
    Connection->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_SPECIAL_ERROR);
    return true;
}

void
QuicTestConnectServerRejected(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);
    Settings.SetSendBufferingEnabled(true);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerRejectConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            TestConnection Client(Registration);
            TEST_TRUE(Client.IsValid());

            Client.SetExpectedTransportCloseStatus(QUIC_STATUS_USER_CANCELED);
            TEST_QUIC_SUCCEEDED(
                Client.Start(
                    ClientConfiguration,
                    QuicAddrFamily,
                    QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                    ServerLocalAddr.GetPort()));
            if (!Client.WaitForShutdownComplete()) {
                return;
            }
        }
    }
}

void
QuicTestKeyUpdate(
    _In_ int Family,
    _In_ uint16_t Iterations,
    _In_ uint16_t KeyUpdateBytes,
    _In_ bool UseKeyUpdateBytes,
    _In_ bool ClientKeyUpdate,
    _In_ bool ServerKeyUpdate
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    if (UseKeyUpdateBytes) {
        Settings.SetMaxBytesPerKey(KeyUpdateBytes);
    }

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                for (uint16_t i = 0; i < Iterations; ++i) {

                    CxPlatSleep(100);

                    if (ClientKeyUpdate) {
                        TEST_QUIC_SUCCEEDED(Client.ForceKeyUpdate());
                    }

                    if (ServerKeyUpdate) {
                        TEST_QUIC_SUCCEEDED(Server->ForceKeyUpdate());
                    }

                    //
                    // Send some data to perform the key update.
                    // TODO: Update this to send stream data, like QuicConnectAndPing does.
                    //
                    TEST_QUIC_SUCCEEDED(Client.SetPeerBidiStreamCount((uint16_t)(101+i)));
                    TEST_EQUAL((uint16_t)(101+i), Client.GetPeerBidiStreamCount());
                    CxPlatSleep(100);
                    TEST_EQUAL((uint16_t)(101+i), Server->GetLocalBidiStreamCount());

                    TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount((uint16_t)(100+i)));
                    TEST_EQUAL((uint16_t)(100+i), Server->GetPeerBidiStreamCount());
                    CxPlatSleep(100);
                    TEST_EQUAL((uint16_t)(100+i), Client.GetLocalBidiStreamCount());
                }

                CxPlatSleep(100);

                QUIC_STATISTICS Stats = Client.GetStatistics();
                if (Stats.Recv.DecryptionFailures) {
                    TEST_FAILURE("%llu server packets failed to decrypt!", Stats.Recv.DecryptionFailures);
                    return;
                }

                uint16_t ExpectedUpdates = Iterations - (UseKeyUpdateBytes ? 1u : 0u);

                if (Stats.Misc.KeyUpdateCount < ExpectedUpdates) {
                    TEST_FAILURE("%u Key updates occured. Expected %d", Stats.Misc.KeyUpdateCount, ExpectedUpdates);
                    return;
                }

                Stats = Server->GetStatistics();
                if (Stats.Recv.DecryptionFailures) {
                    TEST_FAILURE("%llu client packets failed to decrypt!", Stats.Recv.DecryptionFailures);
                    return;
                }

                if (Stats.Misc.KeyUpdateCount < ExpectedUpdates) {
                    TEST_FAILURE("%u Key updates occured. Expected %d", Stats.Misc.KeyUpdateCount, ExpectedUpdates);
                    return;
                }

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }

#if !QUIC_SEND_FAKE_LOSS
            TEST_TRUE(Server->GetPeerClosed());
            TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
#endif
        }
    }
}

void
QuicTestCidUpdate(
    _In_ int Family,
    _In_ uint16_t Iterations
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                for (uint16_t i = 0; i < Iterations; ++i) {

                    CxPlatSleep(100);

                    TEST_QUIC_SUCCEEDED(Client.ForceCidUpdate());

                    TEST_QUIC_SUCCEEDED(Client.SetPeerBidiStreamCount((uint16_t)(101+i)));
                    TEST_EQUAL((uint16_t)(101+i), Client.GetPeerBidiStreamCount());
                    CxPlatSleep(100);
                    TEST_EQUAL((uint16_t)(101+i), Server->GetLocalBidiStreamCount());

                    TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount((uint16_t)(100+i)));
                    TEST_EQUAL((uint16_t)(100+i), Server->GetPeerBidiStreamCount());
                    CxPlatSleep(100);
                    TEST_EQUAL((uint16_t)(100+i), Client.GetLocalBidiStreamCount());
                }

                CxPlatSleep(100);

                QUIC_STATISTICS Stats = Client.GetStatistics();
                if (Stats.Recv.DecryptionFailures) {
                    TEST_FAILURE("%llu server packets failed to decrypt!", Stats.Recv.DecryptionFailures);
                    return;
                }

                Stats = Server->GetStatistics();
                if (Stats.Recv.DecryptionFailures) {
                    TEST_FAILURE("%llu client packets failed to decrypt!", Stats.Recv.DecryptionFailures);
                    return;
                }

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }

#if !QUIC_SEND_FAKE_LOSS
            TEST_TRUE(Server->GetPeerClosed());
            TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
#endif
        }
    }
}
