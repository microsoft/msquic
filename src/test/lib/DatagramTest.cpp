/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests the unreliable datagram feature.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "DatagramTest.cpp.clog.h"
#endif

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
QuicTestDatagramNegotiation(
    _In_ int Family,
    _In_ bool DatagramReceiveEnabled
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetDatagramReceiveEnabled(true); // Always enabled on client.

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    Settings.SetDatagramReceiveEnabled(DatagramReceiveEnabled);
    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    uint8_t RawBuffer[] = "datagram";
    QUIC_BUFFER DatagramBuffer = { sizeof(RawBuffer), RawBuffer };

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

                TEST_TRUE(Client.GetDatagramSendEnabled()); // Datagrams start as enabled

                TEST_QUIC_SUCCEEDED(
                    MsQuic->DatagramSend(
                        Client.GetConnection(),
                        &DatagramBuffer,
                        1,
                        QUIC_SEND_FLAG_NONE,
                        nullptr));

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

                TEST_EQUAL(DatagramReceiveEnabled, Client.GetDatagramSendEnabled());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                TEST_TRUE(Server->GetDatagramSendEnabled()); // Client always enabled

                CxPlatSleep(100); // Necessary?

                if (DatagramReceiveEnabled) {
                    TEST_EQUAL(1, Client.GetDatagramsSent());
                } else {
                    TEST_EQUAL(1, Client.GetDatagramsCanceled());
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
QuicTestDatagramSend(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetDatagramReceiveEnabled(true);

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    uint8_t RawBuffer[] = "datagram";
    QUIC_BUFFER DatagramBuffer = { sizeof(RawBuffer), RawBuffer };

    SelectiveLossHelper LossHelper;

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

                TEST_TRUE(Client.GetDatagramSendEnabled());

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

                TEST_TRUE(Client.GetDatagramSendEnabled());

                TEST_NOT_EQUAL(nullptr, Server);
                if (!Server->WaitForConnectionComplete()) {
                    return;
                }
                TEST_TRUE(Server->GetIsConnected());

                TEST_TRUE(Server->GetDatagramSendEnabled());

                CxPlatSleep(100);

                TEST_QUIC_SUCCEEDED(
                    MsQuic->DatagramSend(
                        Client.GetConnection(),
                        &DatagramBuffer,
                        1,
                        QUIC_SEND_FLAG_NONE,
                        nullptr));

                CxPlatSleep(100);

                TEST_EQUAL(1, Client.GetDatagramsSent());

                CxPlatSleep(100);

                TEST_EQUAL(1, Client.GetDatagramsAcknowledged());

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
                LossHelper.DropPackets(1);

                TEST_QUIC_SUCCEEDED(
                    MsQuic->DatagramSend(
                        Client.GetConnection(),
                        &DatagramBuffer,
                        1,
                        QUIC_SEND_FLAG_NONE,
                        nullptr));

                CxPlatSleep(100);

                TEST_EQUAL(2, Client.GetDatagramsSent());

                CxPlatSleep(500);

                TEST_EQUAL(1, Client.GetDatagramsSuspectLost());
#endif

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                if (!Client.WaitForShutdownComplete()) {
                    return;
                }

                TEST_EQUAL(1, Client.GetDatagramsLost());

                TEST_FALSE(Client.GetPeerClosed());
                TEST_FALSE(Client.GetTransportClosed());
            }
        }
    }
}
