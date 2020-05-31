/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests handshake related features and functionality.

--*/

#include "precomp.h"

uint8_t RandomLossHelper::LossPercentage = 0;
QUIC_TEST_DATAPATH_HOOKS RandomLossHelper::DataPathFuncTable = {
    RandomLossHelper::ReceiveCallback,
    RandomLossHelper::SendCallback
};

_Function_class_(NEW_STREAM_CALLBACK)
static
void
ConnectionDoNothingCallback(
    _In_ TestConnection* /* Connection */,
    _In_ HQUIC /* StreamHandle */,
    _In_ QUIC_STREAM_OPEN_FLAGS /* Flags */
    )
{
    TEST_FAILURE("This callback should never be called!");
}

struct ServerAcceptContext {
    QUIC_EVENT NewConnectionReady;
    TestConnection** NewConnection;
    ServerAcceptContext(TestConnection** _NewConnection) :
        NewConnection(_NewConnection) {
        QuicEventInitialize(&NewConnectionReady, TRUE, FALSE);
    }
    ~ServerAcceptContext() {
        QuicEventUninitialize(NewConnectionReady);
    }
};

_Function_class_(NEW_CONNECTION_CALLBACK)
static
void
ListenerAcceptConnection(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    ServerAcceptContext* AcceptContext = (ServerAcceptContext*)Listener->Context;
    if (AcceptContext == nullptr) { // Prime Resumption scenario.
        auto NewConnection = new TestConnection(ConnectionHandle, ConnectionDoNothingCallback, true, true);
        if (NewConnection == nullptr || !NewConnection->IsValid()) {
            TEST_FAILURE("Failed to accept new TestConnection.");
            delete NewConnection;
            MsQuic->ConnectionClose(ConnectionHandle);
        } else {
            NewConnection->SetHasRandomLoss(Listener->GetHasRandomLoss());
        }
        return;
    }
    if (*AcceptContext->NewConnection != nullptr) { // Retry scenario.
        delete *AcceptContext->NewConnection;
        *AcceptContext->NewConnection = nullptr;
    }
    *AcceptContext->NewConnection = new TestConnection(ConnectionHandle, ConnectionDoNothingCallback, true);
    if (*AcceptContext->NewConnection == nullptr || !(*AcceptContext->NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *AcceptContext->NewConnection;
        *AcceptContext->NewConnection = nullptr;
        MsQuic->ConnectionClose(ConnectionHandle);
    } else {
        (*AcceptContext->NewConnection)->SetHasRandomLoss(Listener->GetHasRandomLoss());
    }
    QuicEventSet(AcceptContext->NewConnectionReady);
}

void
QuicTestConnect(
    _In_ int Family,
    _In_ bool ServerStatelessRetry,
    _In_ bool ClientUsesOldVersion,
    _In_ bool ClientRebind,
    _In_ bool ChangeMaxStreamID,
    _In_ bool MultipleALPNs,
    _In_ bool AsyncSecConfig,
    _In_ bool MultiPacketClientInitial,
    _In_ bool SessionResumption,
    _In_ uint8_t RandomLossPercentage
    )
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetPeerBidiStreamCount(4));
    MsQuicSession Session2("MsQuicTest2", "MsQuicTest");
    TEST_TRUE(Session2.IsValid());
    TEST_QUIC_SUCCEEDED(Session2.SetPeerBidiStreamCount(4));
    TEST_QUIC_SUCCEEDED(Session2.SetIdleTimeout(10000));

    StatelessRetryHelper RetryHelper(ServerStatelessRetry);
    PrivateTransportHelper TpHelper(MultiPacketClientInitial);
    RandomLossHelper LossHelper(RandomLossPercentage);

    if (RandomLossPercentage != 0) {
        TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(30000));
        TEST_QUIC_SUCCEEDED(Session.SetDisconnectTimeout(30000));
        TEST_QUIC_SUCCEEDED(Session2.SetIdleTimeout(30000));
        TEST_QUIC_SUCCEEDED(Session2.SetDisconnectTimeout(30000));
    } else {
        TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(10000));
        TEST_QUIC_SUCCEEDED(Session2.SetIdleTimeout(10000));
    }

    {
        TestListener Listener(
            MultipleALPNs ? Session2.Handle : Session.Handle,
            ListenerAcceptConnection,
            AsyncSecConfig);
        TEST_TRUE(Listener.IsValid());
        Listener.SetHasRandomLoss(RandomLossPercentage != 0);

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(&ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        if (SessionResumption) {
            TestScopeLogger logScope("PrimeResumption");
            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());
                Client.SetHasRandomLoss(RandomLossPercentage != 0);
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));
                if (!Client.WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Client.GetIsConnected());
                if (!Client.WaitForZeroRttTicket()) {
                    return;
                }
                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }
            }
        }

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
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
                    Client.SetExpectedResumed(true);
                }

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

                if (AsyncSecConfig) {
                    if (!QuicEventWaitWithTimeout(ServerAcceptCtx.NewConnectionReady, TestWaitTimeout)) {
                        TEST_FAILURE("Timed out waiting for server accept.");
                    } else if (Server == nullptr) {
                        TEST_FAILURE("Failed to accept server connection.");
                    } else {
                        TEST_QUIC_SUCCEEDED(
                            Server->SetSecurityConfig(SecurityConfig));
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

                if (SessionResumption) {
                    TEST_TRUE(Client.GetResumed());
                    TEST_TRUE(Server->GetResumed());
                }

                TEST_EQUAL(
                    Server->GetPeerBidiStreamCount(),
                    Client.GetLocalBidiStreamCount());

                if (ClientRebind) {
                    QuicAddr NewLocalAddr(QuicAddrFamily);
                    TEST_QUIC_SUCCEEDED(Client.SetLocalAddr(NewLocalAddr));
                    QuicSleep(100);
                    TEST_QUIC_SUCCEEDED(Client.GetLocalAddr(NewLocalAddr));
                    TEST_FALSE(Client.GetIsShutdown());

                    bool ServerAddressUpdated = false;
                    uint32_t Try = 0;
                    do {
                        if (Try != 0) {
                            QuicSleep(200);
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
                }

                if (ChangeMaxStreamID) {
                    TEST_QUIC_SUCCEEDED(Client.SetPeerBidiStreamCount(101));
                    TEST_EQUAL(101, Client.GetPeerBidiStreamCount());
                    QuicSleep(100);
                    TEST_EQUAL(101, Server->GetLocalBidiStreamCount());

                    TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount(100));
                    TEST_EQUAL(100, Server->GetPeerBidiStreamCount());
                    QuicSleep(100);
                    TEST_EQUAL(100, Client.GetLocalBidiStreamCount());
                }

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }

            if (RandomLossPercentage == 0) {
                TEST_TRUE(Server->GetPeerClosed());
                TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
            }
        }
    }
}

void
QuicTestConnectAndIdle(
    _In_ bool EnableKeepAlive
    )
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(3000));

    {
        TestListener Listener(Session.Handle, ListenerAcceptConnection);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

                if (!EnableKeepAlive) {
                    Client.SetExpectedTransportCloseStatus(QUIC_STATUS_CONNECTION_IDLE);
                }

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        AF_UNSPEC,
                        QUIC_LOCALHOST_FOR_AF(ServerLocalAddr.SockAddr.si_family),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

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

                QuicSleep(4000); // Wait for the first idle period to expire.

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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;

        TestConnection Client(
            Session.Handle,
            ConnectionDoNothingCallback,
            false);
        TEST_TRUE(Client.IsValid());

        Client.SetExpectedTransportCloseStatus(QUIC_STATUS_UNREACHABLE);
        TEST_QUIC_SUCCEEDED(
            Client.Start(
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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(3000));

    {
        TestListener Listener(Session.Handle, ListenerAcceptConnection);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.SetQuicVersion(168430090ul)); // Random reserved version to force VN.

                Client.SetExpectedTransportCloseStatus(QUIC_STATUS_VER_NEG_ERROR);
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));
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
QuicTestConnectBadAlpn(
    _In_ int Family
    )
{
    MsQuicSession GoodSession;
    TEST_TRUE(GoodSession.IsValid());
    TEST_QUIC_SUCCEEDED(GoodSession.SetIdleTimeout(3000));
    MsQuicSession BadSession("BadALPN"); // Incorrect ALPN
    TEST_TRUE(BadSession.IsValid());

    {
        TestListener Listener(GoodSession.Handle, ListenerAcceptConnection);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    BadSession.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

                Client.SetExpectedTransportCloseStatus(QUIC_STATUS_INTERNAL_ERROR);
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));
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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(3000));

    {
        TestListener Listener(Session.Handle, ListenerAcceptConnection);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

                QuicAddr RemoteAddr(Family == 4 ? AF_INET : AF_INET6, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));

                Client.SetExpectedTransportCloseStatus(QUIC_STATUS_INTERNAL_ERROR);
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        Family == 4 ? AF_INET : AF_INET6,
                        "badlocalhost",
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));
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
void
ListenerRejectConnection(
    _In_ TestListener* /*  Listener */,
    _In_ HQUIC ConnectionHandle
    )
{
    auto Connection = new TestConnection(ConnectionHandle, ConnectionDoNothingCallback, true, true);
    Connection->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_SPECIAL_ERROR);
}

void
QuicTestConnectServerRejected(
    _In_ int Family
    )
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(3000));

    {
        TestListener Listener(Session.Handle, ListenerRejectConnection, true);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            TestConnection Client(
                Session.Handle,
                ConnectionDoNothingCallback,
                false);
            TEST_TRUE(Client.IsValid());

            Client.SetExpectedTransportCloseStatus(QUIC_STATUS_USER_CANCELED);
            TEST_QUIC_SUCCEEDED(
                Client.Start(
                    QuicAddrFamily,
                    QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                    QuicAddrGetPort(&ServerLocalAddr.SockAddr)));
            if (!Client.WaitForConnectionComplete()) {
                return;
            }

            TEST_FALSE(Client.GetIsConnected());
            TEST_TRUE(Client.GetTransportClosed());
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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    if (UseKeyUpdateBytes) {
        Session.SetMaxBytesPerKey((uint64_t)KeyUpdateBytes);
    }

    {
        TestListener Listener(Session.Handle, ListenerAcceptConnection);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(&ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

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

                    QuicSleep(100);

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
                    QuicSleep(100);
                    TEST_EQUAL((uint16_t)(101+i), Server->GetLocalBidiStreamCount());

                    TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount((uint16_t)(100+i)));
                    TEST_EQUAL((uint16_t)(100+i), Server->GetPeerBidiStreamCount());
                    QuicSleep(100);
                    TEST_EQUAL((uint16_t)(100+i), Client.GetLocalBidiStreamCount());
                }

                QuicSleep(100);

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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerAcceptConnection);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(&ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        QuicAddrFamily,
                        QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

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

                    QuicSleep(100);

                    TEST_QUIC_SUCCEEDED(Client.ForceCidUpdate());

                    TEST_QUIC_SUCCEEDED(Client.SetPeerBidiStreamCount((uint16_t)(101+i)));
                    TEST_EQUAL((uint16_t)(101+i), Client.GetPeerBidiStreamCount());
                    QuicSleep(100);
                    TEST_EQUAL((uint16_t)(101+i), Server->GetLocalBidiStreamCount());

                    TEST_QUIC_SUCCEEDED(Server->SetPeerBidiStreamCount((uint16_t)(100+i)));
                    TEST_EQUAL((uint16_t)(100+i), Server->GetPeerBidiStreamCount());
                    QuicSleep(100);
                    TEST_EQUAL((uint16_t)(100+i), Client.GetLocalBidiStreamCount());
                }

                QuicSleep(100);

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
