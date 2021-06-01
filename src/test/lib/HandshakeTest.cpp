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
    if (AcceptContext->ExpectedTransportCloseStatus != QUIC_STATUS_SUCCESS) {
        (*AcceptContext->NewConnection)->SetExpectedTransportCloseStatus(
            AcceptContext->ExpectedTransportCloseStatus);
    }
    if (AcceptContext->ExpectedClientCertValidationResult != QUIC_STATUS_SUCCESS) {
        (*AcceptContext->NewConnection)->SetExpectedClientCertValidationResult(
            AcceptContext->ExpectedClientCertValidationResult);
    }
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
    _In_ QUIC_TEST_RESUMPTION_MODE SessionResumption,
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
        Settings.SetInitialRttMs(50);
    } else {
        Settings.SetIdleTimeoutMs(10000);
    }
    if (SessionResumption != QUIC_TEST_RESUMPTION_DISABLED) {
        Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY);
    }

    MsQuicConfiguration ServerConfiguration(Registration, Alpn2, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn1, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_TICKET_KEY_CONFIG GoodKey;
    CxPlatZeroMemory(&GoodKey, sizeof(GoodKey));
    GoodKey.MaterialLength = 64;

    QUIC_TICKET_KEY_CONFIG BadKey;
    CxPlatZeroMemory(&BadKey, sizeof(BadKey));
    BadKey.MaterialLength = 64;
    BadKey.Material[0] = 0xFF;

    if (SessionResumption == QUIC_TEST_RESUMPTION_REJECTED) {
        TEST_QUIC_SUCCEEDED(ServerConfiguration.SetTicketKey(&GoodKey));
    }

    QUIC_BUFFER* ResumptionTicket = nullptr;
    if (SessionResumption != QUIC_TEST_RESUMPTION_DISABLED) {
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
        if (SessionResumption == QUIC_TEST_RESUMPTION_REJECTED) {
            TEST_QUIC_SUCCEEDED(ServerConfiguration.SetTicketKey(&BadKey));
        }
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

                if (SessionResumption != QUIC_TEST_RESUMPTION_DISABLED) {
                    Client.SetResumptionTicket(ResumptionTicket);
                    CXPLAT_FREE(ResumptionTicket, QUIC_POOL_TEST);
                    if (SessionResumption == QUIC_TEST_RESUMPTION_ENABLED) {
                        Client.SetExpectedResumed(true);
                    }
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

                if (SessionResumption == QUIC_TEST_RESUMPTION_ENABLED) {
                    TEST_TRUE(Client.GetResumed());
                    TEST_TRUE(Server->GetResumed());
                } else if (SessionResumption == QUIC_TEST_RESUMPTION_REJECTED) {
                    TEST_FALSE(Client.GetResumed());
                    TEST_FALSE(Server->GetResumed());
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSelfSignedCredConfig);
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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

            if (Server) {
                Server->WaitForShutdownComplete();
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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
QuicTestCustomCertificateValidation(
    _In_ bool AcceptCert,
    _In_ bool AsyncValidation
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION | QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED);
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
            if (!AcceptCert) {
                ServerAcceptCtx.ExpectedTransportCloseStatus = QUIC_STATUS_BAD_CERTIFICATE;
            }
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                Client.SetExpectedCustomValidationResult(AcceptCert);
                Client.SetAsyncCustomValidationResult(AsyncValidation);
                if (!AcceptCert) {
                    Client.SetExpectedTransportCloseStatus(QUIC_STATUS_BAD_CERTIFICATE);
                }

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QUIC_ADDRESS_FAMILY_UNSPEC,
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                if (AsyncValidation) {
                    CxPlatSleep(1000);
                    TEST_QUIC_SUCCEEDED(Client.SetCustomValidationResult(AcceptCert));
                }

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(AcceptCert, Client.GetIsConnected());

                if (AcceptCert) { // Server will be deleted on reject case, so can't validate.
                    TEST_NOT_EQUAL(nullptr, Server);
                    if (!Server->WaitForConnectionComplete()) {
                        return;
                    }
                    TEST_TRUE(Server->GetIsConnected());
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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
    const uint32_t ClientVersions[] = { 168430090ul, QUIC_VERSION_1_H }; // Random reserved version to force VN.
    const uint32_t ClientVersionsLength = ARRAYSIZE(ClientVersions);
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicSettings ClientSettings;
    ClientSettings.SetIdleTimeoutMs(3000);
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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

struct ClearForcedRetryScope {
    ~ClearForcedRetryScope() {
        uint16_t value = 65;

        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_LEVEL_GLOBAL,
                QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                sizeof(value),
                &value));
    }
};

void
QuicTestVersionNegotiationRetry(
    _In_ int Family
    )
{
    const uint32_t ClientVersions[] = { 168430090ul, QUIC_VERSION_1_H }; // Random reserved version to force VN.
    const uint32_t ClientVersionsLength = ARRAYSIZE(ClientVersions);
    const uint16_t RetryMemoryLimit = 0;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
            sizeof(RetryMemoryLimit),
            &RetryMemoryLimit));

    ClearForcedRetryScope ClearForcedRetry;

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicSettings ClientSettings;
    ClientSettings.SetIdleTimeoutMs(3000);
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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
                TEST_TRUE(Client.GetStatistics().StatelessRetry);
                TEST_EQUAL(Client.GetQuicVersion(), LATEST_SUPPORTED_VERSION);
            }
        }
    }
}

void
QuicTestCompatibleVersionNegotiation(
    _In_ int Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    )
{
    const uint32_t ClientVersions[] = { QUIC_VERSION_1_MS_H, QUIC_VERSION_1_H };
    const uint32_t ServerVersions[] = { QUIC_VERSION_1_H, QUIC_VERSION_1_MS_H };
    const uint32_t ClientVersionsLength = ARRAYSIZE(ClientVersions);
    const uint32_t ServerVersionsLength = ARRAYSIZE(ServerVersions);
    const uint32_t ExpectedSuccessVersion = QUIC_VERSION_1_H;
    const uint32_t ExpectedFailureVersion = QUIC_VERSION_1_MS_H;

    ClearGlobalVersionListScope ClearVersionsScope;

    MsQuicSettings ClientSettings;
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);
    ClientSettings.SetVersionNegotiationExtEnabled(!DisableVNEClient);
    ClientSettings.SetIdleTimeoutMs(3000);

    MsQuicSettings ServerSettings;
    ServerSettings.SetDesiredVersionsList(ServerVersions, ServerVersionsLength);
    ServerSettings.SetVersionNegotiationExtEnabled(!DisableVNEServer);
    ServerSettings.SetIdleTimeoutMs(3000);

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_SETTINGS,
            sizeof(ServerSettings),
            &ServerSettings));

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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

                if (DisableVNEClient || DisableVNEServer) {
                    TEST_EQUAL(Client.GetQuicVersion(), ExpectedFailureVersion);
                    TEST_EQUAL(Server->GetQuicVersion(), ExpectedFailureVersion);
                } else {
                    TEST_EQUAL(Client.GetQuicVersion(), ExpectedSuccessVersion);
                    TEST_EQUAL(Server->GetQuicVersion(), ExpectedSuccessVersion);
                }
                TEST_FALSE(Client.GetStatistics().VersionNegotiation);
            }
        }
    }
}

void
QuicTestCompatibleVersionNegotiationRetry(
    _In_ int Family
    )
{
    const uint32_t ClientVersions[] = { QUIC_VERSION_1_MS_H, QUIC_VERSION_1_H };
    const uint32_t ServerVersions[] = { QUIC_VERSION_1_H, QUIC_VERSION_1_MS_H };
    const uint32_t ClientVersionsLength = ARRAYSIZE(ClientVersions);
    const uint32_t ServerVersionsLength = ARRAYSIZE(ServerVersions);
    const uint32_t ExpectedSuccessVersion = QUIC_VERSION_1_H;
    const uint16_t RetryMemoryLimit = 0;

    MsQuicSettings ClientSettings;
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);
    ClientSettings.SetVersionNegotiationExtEnabled(true);
    ClientSettings.SetIdleTimeoutMs(3000);

    MsQuicSettings ServerSettings;
    ServerSettings.SetDesiredVersionsList(ServerVersions, ServerVersionsLength);
    ServerSettings.SetVersionNegotiationExtEnabled(true);
    ServerSettings.SetIdleTimeoutMs(3000);

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
            sizeof(RetryMemoryLimit),
            &RetryMemoryLimit));
    ClearForcedRetryScope ClearForcedRetry;

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_SETTINGS,
            sizeof(ServerSettings),
            &ServerSettings));
    ClearGlobalVersionListScope ClearVersionsScope;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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


                TEST_EQUAL(Client.GetQuicVersion(), ExpectedSuccessVersion);
                TEST_EQUAL(Server->GetQuicVersion(), ExpectedSuccessVersion);
                TEST_FALSE(Client.GetStatistics().VersionNegotiation);
                TEST_TRUE(Client.GetStatistics().StatelessRetry);
            }
        }
    }
}

void
QuicTestCompatibleVersionNegotiationDefaultServer(
    _In_ int Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    )
{
    const uint32_t ClientVersions[] = { QUIC_VERSION_1_MS_H, QUIC_VERSION_1_H };
    const uint32_t ClientVersionsLength = ARRAYSIZE(ClientVersions);
    const uint32_t ExpectedSuccessVersion = QUIC_VERSION_1_H;
    const uint32_t ExpectedFailureVersion = QUIC_VERSION_1_MS_H;

    MsQuicSettings ClientSettings;
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);
    ClientSettings.SetVersionNegotiationExtEnabled(!DisableVNEClient);
    ClientSettings.SetIdleTimeoutMs(3000);

    MsQuicSettings ServerSettings;
    ServerSettings.SetVersionNegotiationExtEnabled(!DisableVNEServer);
    ServerSettings.SetIdleTimeoutMs(3000);

    //
    // Enable the VNE for server at the global level.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_SETTINGS,
            sizeof(ServerSettings),
            &ServerSettings));

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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

                if (DisableVNEClient || DisableVNEServer) {
                    TEST_EQUAL(Client.GetQuicVersion(), ExpectedFailureVersion);
                    TEST_EQUAL(Server->GetQuicVersion(), ExpectedFailureVersion);
                } else {
                    TEST_EQUAL(Client.GetQuicVersion(), ExpectedSuccessVersion);
                    TEST_EQUAL(Server->GetQuicVersion(), ExpectedSuccessVersion);
                }
                TEST_FALSE(Client.GetStatistics().VersionNegotiation);
            }
        }
    }
}

void
QuicTestCompatibleVersionNegotiationDefaultClient(
    _In_ int Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    )
{
    const uint32_t ServerVersions[] = { QUIC_VERSION_1_MS_H, QUIC_VERSION_1_H };
    const uint32_t ServerVersionsLength = ARRAYSIZE(ServerVersions);
    const uint32_t ExpectedSuccessVersion = QUIC_VERSION_1_MS_H;
    const uint32_t ExpectedFailureVersion = QUIC_VERSION_1_H;

    MsQuicSettings ClientSettings;
    ClientSettings.SetVersionNegotiationExtEnabled(!DisableVNEClient);
    ClientSettings.SetIdleTimeoutMs(3000);

    MsQuicSettings ServerSettings;
    ServerSettings.SetDesiredVersionsList(ServerVersions, ServerVersionsLength);
    ServerSettings.SetVersionNegotiationExtEnabled(!DisableVNEServer);
    ServerSettings.SetIdleTimeoutMs(3000);

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_SETTINGS,
            sizeof(ServerSettings),
            &ServerSettings));
    ClearGlobalVersionListScope ClearVersionsScope;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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

                if (DisableVNEClient || DisableVNEServer) {
                    TEST_EQUAL(Client.GetQuicVersion(), ExpectedFailureVersion);
                    TEST_EQUAL(Server->GetQuicVersion(), ExpectedFailureVersion);
                } else {
                    TEST_EQUAL(Client.GetQuicVersion(), ExpectedSuccessVersion);
                    TEST_EQUAL(Server->GetQuicVersion(), ExpectedSuccessVersion);
                }
                TEST_FALSE(Client.GetStatistics().VersionNegotiation);
            }
        }
    }
}

void
QuicTestIncompatibleVersionNegotiation(
    _In_ int Family
    )
{
    const uint32_t ClientVersions[] = { QUIC_VERSION_DRAFT_29_H, QUIC_VERSION_1_MS_H };
    const uint32_t ServerVersions[] = { QUIC_VERSION_1_MS_H };
    const uint32_t ClientVersionsLength = ARRAYSIZE(ClientVersions);
    const uint32_t ServerVersionsLength = ARRAYSIZE(ServerVersions);
    const uint32_t ExpectedResultVersion = QUIC_VERSION_1_MS_H;

    MsQuicSettings ClientSettings;
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);
    ClientSettings.SetIdleTimeoutMs(3000);

    MsQuicSettings ServerSettings;
    ServerSettings.SetDesiredVersionsList(ServerVersions, ServerVersionsLength);
    ServerSettings.SetIdleTimeoutMs(3000);

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_SETTINGS,
            sizeof(ServerSettings),
            &ServerSettings));
    ClearGlobalVersionListScope ClearVersionsScope;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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

                TEST_EQUAL(Client.GetQuicVersion(), ExpectedResultVersion);
                TEST_EQUAL(Server->GetQuicVersion(), ExpectedResultVersion);
                TEST_TRUE(Client.GetStatistics().VersionNegotiation);
            }
        }
    }
}

void
RunFailedVersionNegotiation(
    _In_reads_bytes_(ClientVersionsLength * sizeof(uint32_t))
        const uint32_t* ClientVersions,
    _In_reads_bytes_(ServerVersionsLength * sizeof(uint32_t))
         const uint32_t* ServerVersions,
    _In_ const uint32_t ClientVersionsLength,
    _In_ const uint32_t ServerVersionsLength,
    _In_ QUIC_STATUS ExpectedConnectionError,
    _In_ int Family
    )
{
    MsQuicSettings ClientSettings;
    ClientSettings.SetDesiredVersionsList(ClientVersions, ClientVersionsLength);
    ClientSettings.SetIdleTimeoutMs(2000);
    ClientSettings.SetDisconnectTimeoutMs(1000);

    MsQuicSettings ServerSettings;
    ServerSettings.SetDesiredVersionsList(ServerVersions, ServerVersionsLength);
    ServerSettings.SetIdleTimeoutMs(2000);
    ServerSettings.SetDisconnectTimeoutMs(1000);

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            NULL,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_SETTINGS,
            sizeof(ServerSettings),
            &ServerSettings));
    ClearGlobalVersionListScope ClearVersionsScope;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientSettings, ClientCredConfig);
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
                Client.SetExpectedTransportCloseStatus(ExpectedConnectionError);

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForShutdownComplete()) {
                    return;
                }
                TEST_FALSE(Client.GetIsConnected());

                TEST_EQUAL(nullptr, Server);

                TEST_EQUAL(Client.GetQuicVersion(), ClientVersions[0]);
                TEST_TRUE(Client.GetStatistics().VersionNegotiation);
                TEST_EQUAL(Client.GetTransportCloseStatus(), ExpectedConnectionError);
            }
        }
    }
}

void
QuicTestFailedVersionNegotiation(
    _In_ int Family
    )
{
    const uint32_t NoCommonClientVersions[] = { QUIC_VERSION_DRAFT_29_H };
    const uint32_t NoCommonServerVersions[] = { QUIC_VERSION_1_MS_H };

    RunFailedVersionNegotiation(
        NoCommonClientVersions,
        NoCommonServerVersions,
        ARRAYSIZE(NoCommonClientVersions),
        ARRAYSIZE(NoCommonServerVersions),
        QUIC_STATUS_VER_NEG_ERROR,
        Family);

    const uint32_t OriginalInVNClientVersions[] = { 0x0a0a0a0a, QUIC_VERSION_1_H }; // Random reserved version to force VN.
    const uint32_t OriginalInVNServerVersions[] = { 0x00000001, 0xabcd0000, 0xff00001d, 0x0a0a0a0a };

    RunFailedVersionNegotiation(
        OriginalInVNClientVersions,
        OriginalInVNServerVersions,
        ARRAYSIZE(OriginalInVNClientVersions),
        ARRAYSIZE(OriginalInVNServerVersions),
        QUIC_STATUS_CONNECTION_TIMEOUT,
        Family);
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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
QuicTestKeyUpdateRandomLoss(
    _In_ int Family,
    _In_ uint8_t RandomLossPercentage
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    const int Iterations = 10;

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        Listener.SetHasRandomLoss(true);

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
                Client.SetHasRandomLoss(true);

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

                {
                    RandomLossHelper LossHelper(RandomLossPercentage);

                    CxPlatSleep(100);

                    for (uint16_t i = 0; i < Iterations; ++i) {

                        //
                        // We don't care if this call succeeds, we just want to trigger it every time
                        //
                        Client.ForceKeyUpdate();
                        Server->ForceKeyUpdate();

                        //
                        // Send some data to perform the key update.
                        // TODO: Update this to send stream data, like QuicConnectAndPing does.
                        //
                        TEST_QUIC_SUCCEEDED(Client.SetPeerBidiStreamCount((uint16_t)(101 + i)));
                        TEST_EQUAL((uint16_t)(101 + i), Client.GetPeerBidiStreamCount());
                        CxPlatSleep(50);

                        //
                        // Force a client key update to occur again to check for double update
                        // while server is still waiting for key response.
                        //
                        Client.ForceKeyUpdate();

                        TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount((uint16_t)(100 + i)));
                        TEST_EQUAL((uint16_t)(100 + i), Server->GetPeerBidiStreamCount());
                        CxPlatSleep(50);
                    }

                    CxPlatSleep(100);
                }

                QUIC_STATISTICS Stats = Client.GetStatistics();
                if (Stats.Recv.DecryptionFailures) {
                    TEST_FAILURE("%llu server packets failed to decrypt!", Stats.Recv.DecryptionFailures);
                    return;
                }

                if (Stats.Misc.KeyUpdateCount < 1) {
                    TEST_FAILURE("%u Key updates occured. Expected at least 1", Stats.Misc.KeyUpdateCount);
                    return;
                }

                Stats = Server->GetStatistics();
                if (Stats.Recv.DecryptionFailures) {
                    TEST_FAILURE("%llu client packets failed to decrypt!", Stats.Recv.DecryptionFailures);
                    return;
                }

                if (Stats.Misc.KeyUpdateCount < 1) {
                    TEST_FAILURE("%u Key updates occured. Expected at least 1", Stats.Misc.KeyUpdateCount);
                    return;
                }

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }
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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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

                    //
                    // Force a client key update to occur again to check for double update
                    // while server is still waiting for key response.
                    //
                    if (ClientKeyUpdate) {
                        TEST_QUIC_SUCCEEDED(Client.ForceKeyUpdate());
                    }

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

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSelfSignedCredConfig);
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

void
QuicTestConnectClientCertificate(
    _In_ int Family,
    _In_ bool UseClientCertificate
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfigClientAuth);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientNoCertCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, UseClientCertificate ? ClientCertCredConfig : ClientNoCertCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));

        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            ServerAcceptCtx.ExpectedClientCertValidationResult = QUIC_STATUS_CERT_UNTRUSTED_ROOT;
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());
                if (!UseClientCertificate) {
                    Client.SetExpectedTransportCloseStatus(QUIC_STATUS_CLOSE_NOTIFY);
                }

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(UseClientCertificate, Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (UseClientCertificate) {
                    if (!Server->WaitForConnectionComplete()) {
                        return;
                    }
                } else {
                    Server->SetExpectedTransportCloseStatus(QUIC_STATUS_CLOSE_NOTIFY);
                }
                TEST_EQUAL(UseClientCertificate, Server->GetIsConnected());
            }
        }
    }
}

void
QuicTestInvalidAlpnLengths(
    void
    )
{
    int Lengths[] = { 0, QUIC_MAX_ALPN_LENGTH + 1 };
    char AlpnBuffer[QUIC_MAX_ALPN_LENGTH + 3]; // + 3 so it can always be 0 terminated
    for (int Len = 0; Len < (int)ARRAYSIZE(Lengths); Len++) {
        int AlpnLength = Lengths[Len];
        CxPlatZeroMemory(AlpnBuffer, sizeof(AlpnBuffer));
        for (int i = 0; i < AlpnLength; i++) {
            AlpnBuffer[i] = 'a';
        }
        MsQuicRegistration Registration;
        TEST_TRUE(Registration.IsValid());

        MsQuicAlpn Alpn(AlpnBuffer);

        MsQuicSettings Settings;
        Settings.SetIdleTimeoutMs(3000);

        MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
        TEST_FALSE(ServerConfiguration.IsValid());
    }
}

void
QuicTestValidAlpnLengths(
    void
    )
{
    char AlpnBuffer[QUIC_MAX_ALPN_LENGTH + 2]; // + 2 so it can always be 0 terminated
    for (int AlpnLength = 1; AlpnLength <= QUIC_MAX_ALPN_LENGTH; AlpnLength++) {
        CxPlatZeroMemory(AlpnBuffer, sizeof(AlpnBuffer));
        for (int i = 0; i < AlpnLength; i++) {
            AlpnBuffer[i] = 'a';
        }

        MsQuicRegistration Registration;
        TEST_TRUE(Registration.IsValid());

        MsQuicAlpn Alpn(AlpnBuffer);

        MsQuicSettings Settings;
        Settings.SetIdleTimeoutMs(3000);

        MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
        TEST_TRUE(ServerConfiguration.IsValid());

        MsQuicCredentialConfig ClientCredConfig;
        MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
        TEST_TRUE(ClientConfiguration.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;

        {
            TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
            TEST_TRUE(Listener.IsValid());
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
                            QUIC_LOCALHOST_FOR_AF(
                                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
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
                }
            }
        }
    }
}

void
QuicTestConnectExpiredServerCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, *Config);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    ClientCredConfig.Flags &= ~QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
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
                Client.SetExpectedTransportCloseStatus(QUIC_STATUS_EXPIRED_CERTIFICATE);

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(false, Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                Server->SetExpectedTransportCloseStatus(QUIC_STATUS_EXPIRED_CERTIFICATE);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(false, Server->GetIsConnected());
            }
        }
    }
}

void
QuicTestConnectValidServerCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, *Config);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    ClientCredConfig.Flags &= ~QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
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
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(true, Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(true, Server->GetIsConnected());
            }
        }
    }
}

void
QuicTestConnectValidClientCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfigClientAuth);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, *Config);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));

        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            ServerAcceptCtx.ExpectedClientCertValidationResult = QUIC_STATUS_SUCCESS;
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(true, Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(true, Server->GetIsConnected());
            }
        }
    }
}

void
QuicTestConnectExpiredClientCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(3000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfigClientAuth);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, *Config);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;

    {
        TestListener Listener(Registration, ListenerAcceptConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));

        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            ServerAcceptCtx.ExpectedClientCertValidationResult = QUIC_STATUS_CERT_EXPIRED;
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(Registration);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

                //
                // This test expects the server to accept the client
                // cert even though it gives a validation error.
                //
                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(true, Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_EQUAL(true, Server->GetIsConnected());
            }
        }
    }
}
