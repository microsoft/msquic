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
    CxPlatEvent PathAddedEvent;
    CxPlatEvent PathRemovedEvent;
    CxPlatEvent PeerStreamChangedEvent;

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
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_ADDED) {
            Ctx->PathAddedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_REMOVED) {
            Ctx->PathRemovedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            Ctx->PeerStreamChangedEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct PathTestClientContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent PathAddedEvent;
    CxPlatEvent PathRemovedEvent;
    CxPlatEvent PeerStreamChangedEvent;

    static QUIC_STATUS ClientCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestClientContext* Ctx = static_cast<PathTestClientContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_ADDED) {
            Ctx->PathAddedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_REMOVED) {
            Ctx->PathRemovedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            Ctx->PeerStreamChangedEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestLocalPathChanges(
    _In_ int Family
    )
{
    PathTestContext Context;
    PathTestClientContext ClientContext;
    CxPlatEvent PeerStreamsChanged;
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

    MsQuicConnection Connection(Registration, CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
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
        TEST_TRUE(ClientContext.PeerStreamChangedEvent.WaitTimeout(1500));
        ClientContext.PeerStreamChangedEvent.Reset();
    }
}

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
void
QuicTestProbePath(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN DeferConnIDGen,
    _In_ uint32_t DropPacketCount
    )
{
    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    if (DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ServerConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();

    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS,
            sizeof(SecondLocalAddr.SockAddr),
            &SecondLocalAddr.SockAddr);

        if (Status != QUIC_STATUS_SUCCESS) {
            delete ProbeHelper;
            SecondLocalAddr.IncrementPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);
        }
    } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (DeferConnIDGen) {
        BOOLEAN ReplaceExistingCids = FALSE;
        TEST_QUIC_SUCCEEDED(
            Context.Connection->SetParam(
                QUIC_PARAM_CONN_GENERATE_CONN_ID,
                sizeof(ReplaceExistingCids),
                &ReplaceExistingCids));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    QUIC_STATISTICS_V2 Stats;
    uint32_t Size = sizeof(Stats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(
            QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
            &Size,
            &Stats));
    TEST_EQUAL(Stats.RecvDroppedPackets, 0);
    delete ProbeHelper;
}

void
QuicTestMigration(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ QUIC_MIGRATION_TYPE Type
    )
{
    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();

    PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());

    if (Type == MigrateWithProbe || Type == DeleteAndMigrate) {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        do {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS,
                sizeof(SecondLocalAddr.SockAddr),
                &SecondLocalAddr.SockAddr);

            if (Status != QUIC_STATUS_SUCCESS) {
                delete ProbeHelper;
                SecondLocalAddr.IncrementPort();
                ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
            }
        } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);

        TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        delete ProbeHelper;

        QUIC_STATISTICS_V2 Stats;
        uint32_t Size = sizeof(Stats);
        TEST_QUIC_SUCCEEDED(
            Connection.GetParam(
                QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
                &Size,
                &Stats));
        TEST_EQUAL(Stats.RecvDroppedPackets, 0);

        if (Type == MigrateWithProbe) {
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(SecondLocalAddr.SockAddr),
                    &SecondLocalAddr.SockAddr));
        } else {
            QuicAddr ClientLocalAddr;
            TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));

            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_REMOVE_LOCAL_ADDRESS,
                    sizeof(ClientLocalAddr.SockAddr),
                    &ClientLocalAddr.SockAddr));
        }
    } else {
        //
        // Wait for handshake confirmation.
        //
        CxPlatSleep(100);

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        do {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                sizeof(SecondLocalAddr.SockAddr),
                &SecondLocalAddr.SockAddr);
            if (Status != QUIC_STATUS_SUCCESS) {
                SecondLocalAddr.IncrementPort();
            }
        } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);
    }


    TEST_TRUE(Context.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerRemoteAddr;
    TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerRemoteAddr));
    TEST_TRUE(QuicAddrCompare(&SecondLocalAddr.SockAddr, &ServerRemoteAddr.SockAddr));
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
    TEST_TRUE(ClientContext.PeerStreamChangedEvent.WaitTimeout(1500));
}

void
QuicTestMultipleLocalAddresses(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN DeferConnIDGen,
    _In_ uint32_t DropPacketCount
    )
{
    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    if (DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ServerConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    QuicAddr ClientLocalAddrs[4] = {QuicAddrFamily, QuicAddrFamily, QuicAddrFamily, QuicAddrFamily};
    for (uint8_t i = 0; i < 4; i++) {
        ClientLocalAddrs[i].SetPort(rand() % 65536);
        QUIC_STATUS Status;
        uint32_t Try = 0;
        do {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS,
                sizeof(ClientLocalAddrs[i].SockAddr),
                &ClientLocalAddrs[i].SockAddr);
            if (Status != QUIC_STATUS_ADDRESS_IN_USE) {
                TEST_QUIC_SUCCEEDED(Status);
                break;
            }
        } while (++Try < 3);
        TEST_QUIC_SUCCEEDED(Status);
    }

    PathProbeHelper ProbeHelpers[3] = {
        {ClientLocalAddrs[1].GetPort(), DropPacketCount, DropPacketCount},
        {ClientLocalAddrs[2].GetPort(), DropPacketCount, DropPacketCount},
        {ClientLocalAddrs[3].GetPort(), DropPacketCount, DropPacketCount}};

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    if (DeferConnIDGen) {
        BOOLEAN ReplaceExistingCids = FALSE;
        TEST_QUIC_SUCCEEDED(
            Context.Connection->SetParam(
                QUIC_PARAM_CONN_GENERATE_CONN_ID,
                sizeof(ReplaceExistingCids),
                &ReplaceExistingCids));
    }

    TEST_TRUE(ProbeHelpers[0].ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelpers[0].ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelpers[1].ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelpers[1].ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelpers[2].ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelpers[2].ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
}

void
QuicTestMultipath(
    _In_ int Family
    )
{
    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE),
        ServerSelfSignedCredConfig);

    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE),
        ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();
    
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr FirstLocalAddr, SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();

    PathProbeHelper* ProbeHelper = new PathProbeHelper(SecondLocalAddr.GetPort());

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS,
            sizeof(SecondLocalAddr.SockAddr),
            &SecondLocalAddr.SockAddr);

        if (Status != QUIC_STATUS_SUCCESS) {
            delete ProbeHelper;
            SecondLocalAddr.IncrementPort();
            ProbeHelper = new PathProbeHelper(SecondLocalAddr.GetPort());
        }
    } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    delete ProbeHelper;

    QUIC_STATISTICS_V2 Stats;
    uint32_t Size = sizeof(Stats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(
            QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
            &Size,
            &Stats));
    TEST_EQUAL(Stats.RecvDroppedPackets, 0);

    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(1500));
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(1500));
    
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(
            QUIC_PARAM_CONN_REMOVE_LOCAL_ADDRESS,
            sizeof(FirstLocalAddr.SockAddr),
            &FirstLocalAddr.SockAddr));

    TEST_TRUE(Context.PathRemovedEvent.WaitTimeout(1500));

    MsQuicSettings Settings;
    Context.Connection->GetSettings(&Settings);
    Settings.IsSetFlags = 0;
    Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
    Context.Connection->SetSettings(Settings);

    TEST_TRUE(ClientContext.PeerStreamChangedEvent.WaitTimeout(1500));

    Connection.GetSettings(&Settings);
    Settings.IsSetFlags = 0;
    Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
    Connection.SetSettings(Settings);

    TEST_TRUE(Context.PeerStreamChangedEvent.WaitTimeout(1500));

}
#endif
