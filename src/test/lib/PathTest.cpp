/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Path Unittest

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "PathTest.cpp.clog.h"
#endif

struct PathTestContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent PeerAddrChangedEvent;

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestContext* Ctx = static_cast<PathTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->PeerAddrChangedEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED) {
            MsQuicSettings Settings;
            Conn->GetSettings(&Settings);
            Settings.IsSetFlags = 0;
            Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
            Conn->SetSettings(Settings);
            Ctx->PeerAddrChangedEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct ClientPathTestContext {
    CxPlatEvent PeerStreamsChanged;
    CxPlatEvent PeerAddrChanged;
};

static
QUIC_STATUS
QUIC_API
ClientCallback(
    _In_ MsQuicConnection* /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    ClientPathTestContext* ClientContext = static_cast<ClientPathTestContext*>(Context);
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
        ClientContext->PeerStreamsChanged.Set();
    } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED) {
        ClientContext->PeerAddrChanged.Set();
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestLocalPathChanges(
    const FamilyArgs& Params
    )
{
    const int Family = Params.Family;
    PathTestContext Context;
    ClientPathTestContext ClientContext;
    MsQuicRegistration Registration{true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicSettings Settings;
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);
    TEST_TRUE(Context.Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr OrigLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(OrigLocalAddr));
    ReplaceAddressHelper AddrHelper(OrigLocalAddr.SockAddr, OrigLocalAddr.SockAddr);

    uint16_t ServerPort = ServerLocalAddr.GetPort();
    for (int i = 0; i < 50; i++) {
        uint16_t NextPort = QuicAddrGetPort(&AddrHelper.New) + 1;
        if (NextPort == ServerPort) {
            // Skip the port if it is same as that of server
            // This is to avoid Loopback test failure
            NextPort++;
        }
        QuicAddrSetPort(&AddrHelper.New, NextPort);
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

        TEST_TRUE(Context.PeerAddrChangedEvent.WaitTimeout(1500));
        Context.PeerAddrChangedEvent.Reset();
        QuicAddr ServerRemoteAddr;
        TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerRemoteAddr));
        TEST_TRUE(QuicAddrCompare(&AddrHelper.New, &ServerRemoteAddr.SockAddr));
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
        TEST_TRUE(ClientContext.PeerStreamsChanged.WaitTimeout(1500));
        ClientContext.PeerStreamsChanged.Reset();
    }
}

void
QuicTestClientLocalAddrRebindWithMultiplePaths(
    _In_ int Family
    )
{
    PathTestContext ServerContext;
    ClientPathTestContext ClientContext;
    MsQuicRegistration Registration{true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicSettings Settings;
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr ServerRemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(ServerRemoteAddr));
    ReplaceAddressHelper AddrHelper(ServerRemoteAddr.SockAddr);
    AddrHelper.IncrementPort();

    //
    // Force the peer to send non-probing traffic so the client tracks a
    // secondary path before local address rebinding.
    //
    TEST_QUIC_SUCCEEDED(ServerContext.Connection->SetSettings(MsQuicSettings{}.SetKeepAlive(25)));
    TEST_TRUE(ClientContext.PeerAddrChanged.WaitTimeout(1500));

    QuicAddr NewLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(NewLocalAddr));
    NewLocalAddr.IncrementPort();
    if (NewLocalAddr.GetPort() == ServerLocalAddr.GetPort()) {
        NewLocalAddr.IncrementPort();
    }

    QUIC_STATUS Status = QUIC_STATUS_INVALID_STATE;
    for (uint32_t Try = 0; Try < 4; ++Try) {
        Status = Connection.SetLocalAddr(NewLocalAddr);
        if (Status != QUIC_STATUS_INVALID_STATE) {
            break;
        }
        CxPlatSleep(100);
    }
    TEST_QUIC_SUCCEEDED(Status);

    //
    // Keep traffic flowing briefly so any path challenge sends run after the
    // local address rebinding.
    //
    TEST_QUIC_SUCCEEDED(Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25)));
    CxPlatSleep(150);
}
