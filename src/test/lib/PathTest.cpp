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
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    CxPlatEvent AddedPathValidatedEvent;
#endif

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestContext* Ctx = static_cast<PathTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->PeerAddrChangedEvent.Set();
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            Ctx->AddedPathValidatedEvent.Set();
#endif
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
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
        else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_VALIDATED) {
            QuicAddr LocalAddr, RemoteAddr;
            Conn->GetLocalAddr(LocalAddr);
            Conn->GetRemoteAddr(RemoteAddr);
            if (!QuicAddrCompare(&LocalAddr.SockAddr, Event->PATH_VALIDATED.LocalAddress) ||
                !QuicAddrCompare(&RemoteAddr.SockAddr, Event->PATH_VALIDATED.RemoteAddress)) {
                Ctx->AddedPathValidatedEvent.Set();
            }
        }
#endif
        return QUIC_STATUS_SUCCESS;
    }
};

struct PathTestClientContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent StreamCountEvent;

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestClientContext* Ctx = static_cast<PathTestClientContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->StreamCountEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            Ctx->StreamCountEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
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
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
        CxPlatEvent* StreamCountEvent = static_cast<CxPlatEvent*>(Context);
        StreamCountEvent->Set();
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

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
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
        TEST_TRUE(PeerStreamsChanged.WaitTimeout(1500));
        PeerStreamsChanged.Reset();
    }
}

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
static
QUIC_STATUS
QUIC_API
ClientCallback2(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_VALIDATED) {
        CxPlatEvent* AddedPathValidatedEvent = static_cast<CxPlatEvent*>(Context);
        QuicAddr LocalAddr, RemoteAddr;
        Connection->GetLocalAddr(LocalAddr);
        Connection->GetRemoteAddr(RemoteAddr);
        if (!QuicAddrCompare(&LocalAddr.SockAddr, Event->PATH_VALIDATED.LocalAddress) ||
            !QuicAddrCompare(&RemoteAddr.SockAddr, Event->PATH_VALIDATED.RemoteAddress)) {
            AddedPathValidatedEvent->Set();
        }
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestProbePath(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN DeferConnIDGen,
    _In_ uint32_t DropPacketCount
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
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

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.SetEphemeralPort();
    QuicAddr RemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(RemoteAddr));
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &RemoteAddr.SockAddr };
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (DeferConnIDGen) {
        TEST_QUIC_SUCCEEDED(
            Context.Connection->SetParam(
                QUIC_PARAM_CONN_GENERATE_CONN_ID,
                0,
                NULL));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    delete ProbeHelper;
}

void
QuicTestProbePathFailed(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
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

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.SetEphemeralPort();
    QuicAddr RemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(RemoteAddr));
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &RemoteAddr.SockAddr };
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    CxPlatSleep(5000);

    delete ProbeHelper;
}

void
QuicTestMigration(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ QUIC_MIGRATION_ADDRESS_TYPE AddressType,
    _In_ QUIC_MIGRATION_TYPE Type
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
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

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));
    MsQuicSettings Settings;
    Connection.GetSettings(&Settings);

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondAddr;
    QuicAddr PairAddr;
    QUIC_PATH_PARAM PathParam = { 0 };
    if (AddressType == NewLocalAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
    } else {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
        PairAddr.SetEphemeralPort();
    }

    if (Type == MigrateWithProbe || Type == DeleteAndMigrate) {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
        int Try = 0;

        do {
            if (AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
            } else {
                Status = Context.Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
            }
            if (QUIC_FAILED(Status)) {
                delete ProbeHelper;
                SecondAddr.SetEphemeralPort();
                ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
            }
        } while (QUIC_FAILED(Status) && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);

        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            if (ShareBinding) {
#if defined(_WIN32)
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    delete ProbeHelper;
                    return;
                } else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
#else
                TEST_QUIC_SUCCEEDED(Status);
#endif
            } else {
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    delete ProbeHelper;
                    return;
                } else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
            }
        } else if (AddressType == NewBothAddresses) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Try = 0;
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }

        TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        delete ProbeHelper;

        if (Type == MigrateWithProbe) {
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        } else {
            QuicAddr FirstServerLocalAddr, FirstClientLocalAddr;
            TEST_QUIC_SUCCEEDED(Context.Connection->GetLocalAddr(FirstServerLocalAddr));
            TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstClientLocalAddr));
            PathParam = { &FirstClientLocalAddr.SockAddr, &FirstServerLocalAddr.SockAddr };
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_REMOVE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        }
    } else {

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        do {
            if (AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
            } else {
                Status = Context.Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
            }
            if (QUIC_FAILED(Status)) {
                SecondAddr.SetEphemeralPort();
            }
        } while (QUIC_FAILED(Status) && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ACTIVATE_PATH,
                sizeof(PathParam),
                &PathParam);
            if (ShareBinding) {
#if defined(_WIN32)
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    return;
                }
                else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
#else
                TEST_QUIC_SUCCEEDED(Status);
#endif
            } else {
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    return;
                }
                else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
            }
        } else if (AddressType == NewBothAddresses) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Try = 0;
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
    }

    TEST_TRUE(Context.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerNewRemoteAddr, ServerNewLocalAddr;
    TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerNewRemoteAddr));
    TEST_QUIC_SUCCEEDED(Context.Connection->GetLocalAddr(ServerNewLocalAddr));
    if (AddressType == NewLocalAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
    } else {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
        TEST_TRUE(QuicAddrCompare(&PairAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    }
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
#if defined(_WIN32)
    if (Type != MigrateWithProbe && AddressType == NewRemoteAddress && Settings.QTIPEnabled) {
        TEST_FALSE(PeerStreamsChanged.WaitTimeout(1500));
    } else
#endif
    {
        TEST_TRUE(PeerStreamsChanged.WaitTimeout(1500));
    }
}

void
QuicTestAddPathBeforeStart(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN DeferConnIDGen
    )
{
    PathTestContext Context;
    CxPlatEvent AddedPathValidatedEvent;
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

    QuicAddr RemoteAddr(QuicAddrFamily);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&RemoteAddr.SockAddr);
        RemoteAddr.SetPort(ServerLocalAddr.GetPort());
    } else {
        if (Family == 4) {
            QuicAddrFromString("127.0.0.1", ServerLocalAddr.GetPort(), &RemoteAddr.SockAddr);
        } else {
            QuicAddrFromString("::1", ServerLocalAddr.GetPort(), &RemoteAddr.SockAddr);
        }
    }

    MsQuicConnection* Connection = nullptr;
    QuicAddr FirstLocalAddr(QuicAddrFamily), SecondLocalAddr(QuicAddrFamily);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Connection = new(std::nothrow) MsQuicConnection(Registration, CleanUpManual, ClientCallback2, &AddedPathValidatedEvent);
        TEST_QUIC_SUCCEEDED(Connection->GetInitStatus());

        if (ShareBinding) {
            Connection->SetShareUdpBinding();
        }

        FirstLocalAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection->SetParam(
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(FirstLocalAddr.SockAddr),
            &FirstLocalAddr.SockAddr));
        QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &RemoteAddr.SockAddr };
        
        TEST_QUIC_SUCCEEDED(Connection->SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam));

        TEST_QUIC_SUCCEEDED(Connection->Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
        TEST_TRUE(Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        if (Connection->TransportShutdownStatus == 0) {
            break;
        }
        Status = Connection->TransportShutdownStatus;
        delete Connection;
    } while (QUIC_FAILED(Status) && ++Try < 3);

    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    if (DeferConnIDGen) {
        TEST_QUIC_SUCCEEDED(Context.Connection->SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, 0, NULL));
    }

    TEST_TRUE(AddedPathValidatedEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(Context.AddedPathValidatedEvent.WaitTimeout(TestWaitTimeout * 20));

    delete Connection;
}

struct AddressDiscoveryTestContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent ObservedAddrEvent;
    QuicAddr ObservedAddress;

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        AddressDiscoveryTestContext* Ctx = static_cast<AddressDiscoveryTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->ObservedAddrEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS) {
            Ctx->ObservedAddress.SockAddr = *Event->NOTIFY_OBSERVED_ADDRESS.ObservedAddress;
            Ctx->ObservedAddrEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestAddressDiscovery(
    _In_ int Family
    )
{
    AddressDiscoveryTestContext ServerContext;
    AddressDiscoveryTestContext* ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, AddressDiscoveryTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    QuicAddr ClientLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    QuicAddr ServerObservedAddr(QuicAddrFamily);
    QuicAddr ClientObservedAddr(QuicAddrFamily);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&ServerObservedAddr.SockAddr);
        ServerObservedAddr.SetPort(ServerLocalAddr.GetPort());
        QuicAddrSetToDuoNicClient(&ClientLocalAddr.SockAddr);
    } else {
        if (Family == 4) {
            QuicAddrFromString("127.0.0.1", ServerLocalAddr.GetPort(), &ServerObservedAddr.SockAddr);
            QuicAddrFromString("127.0.0.1", 0, &ClientLocalAddr.SockAddr);
        } else {
            QuicAddrFromString("::1", ServerLocalAddr.GetPort(), &ServerObservedAddr.SockAddr);
            QuicAddrFromString("::1", 0, &ClientLocalAddr.SockAddr);
        }
    }

    MsQuicConnection* Connection = nullptr;
    ReplaceAddressHelper* ReplaceHelper = nullptr;
    uint32_t Try = 0;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    do {
        ClientContext = new(std::nothrow) AddressDiscoveryTestContext();
        Connection = new(std::nothrow) MsQuicConnection(Registration, CleanUpManual, AddressDiscoveryTestContext::ConnCallback, ClientContext);
        TEST_QUIC_SUCCEEDED(Connection->GetInitStatus());

        ClientLocalAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection->SetParam(
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(ClientLocalAddr.SockAddr),
            &ClientLocalAddr.SockAddr));
        ClientObservedAddr = ClientLocalAddr;
        ClientObservedAddr.IncrementPort();

        ReplaceHelper = new(std::nothrow) ReplaceAddressHelper(ClientLocalAddr.SockAddr, ClientObservedAddr.SockAddr);

        TEST_QUIC_SUCCEEDED(Connection->Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
        TEST_TRUE(Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        if (Connection->TransportShutdownStatus == 0) {
            break;
        }
        Status = Connection->TransportShutdownStatus;
        delete ReplaceHelper;
        delete Connection;
        delete ClientContext;            
    } while (QUIC_FAILED(Status) && ++Try < 3);

    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ClientContext->Connection);
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);
    TEST_TRUE(ClientContext->ObservedAddrEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(QuicAddrCompare(&ClientObservedAddr.SockAddr, &ClientContext->ObservedAddress.SockAddr));
    TEST_TRUE(ServerContext.ObservedAddrEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(QuicAddrCompare(&ServerObservedAddr.SockAddr, &ServerContext.ObservedAddress.SockAddr));
    Connection->Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext->ShutdownEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
    delete ReplaceHelper;
    delete Connection;
    delete ClientContext;
}

void
QuicTestServerProbePath(
    _In_ int Family,
    _In_ BOOLEAN DeferConnIDGen,
    _In_ uint32_t DropPacketCount
    )
{
    PathTestContext ClientContext;
    PathTestClientContext ServerContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetServerMigrationEnabled(TRUE);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    if (DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ClientConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestClientContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, PathTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondLocalAddr));
    SecondLocalAddr.SetEphemeralPort();
    QuicAddr SecondRemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondRemoteAddr));
    SecondRemoteAddr.SetEphemeralPort();
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
            sizeof(SecondRemoteAddr.SockAddr),
            &SecondRemoteAddr.SockAddr);

        if (QUIC_FAILED(Status)) {
            SecondRemoteAddr.SetEphemeralPort();
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    Try = 0;
    do {
        QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &SecondRemoteAddr.SockAddr };
        Status = ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (DeferConnIDGen) {
        TEST_QUIC_SUCCEEDED(Connection.SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, 0, NULL));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    delete ProbeHelper;
}

void
QuicTestServerMigration(
    _In_ int Family,
    _In_ QUIC_MIGRATION_ADDRESS_TYPE AddressType,
    _In_ QUIC_MIGRATION_TYPE Type
    )
{
    PathTestContext ClientContext;
    PathTestClientContext ServerContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetServerMigrationEnabled(TRUE);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestClientContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondAddr;
    QuicAddr PairAddr;
    QUIC_PATH_PARAM PathParam = { 0 };
    if (AddressType == NewLocalAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    } else {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
        PairAddr.SetEphemeralPort();
    }

    if (Type == MigrateWithProbe || Type == DeleteAndMigrate) {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
        int Try = 0;

        if (AddressType == NewLocalAddress) {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(PairAddr.SockAddr),
                &PairAddr.SockAddr);
#if defined(_WIN32)
            TEST_TRUE(QUIC_FAILED(Status));
            delete ProbeHelper;
            return;
#endif
        } else {
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
                if (QUIC_FAILED(Status)) {
                    delete ProbeHelper;
                    SecondAddr.SetEphemeralPort();
                    ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            TEST_TRUE(QUIC_FAILED(Status));
            delete ProbeHelper;
            return;
        } else {
            if (AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
            } else {
                PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            }
            Try = 0;
            do {
                Status = ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }

        TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        delete ProbeHelper;

        if (Type == MigrateWithProbe) {
            TEST_QUIC_SUCCEEDED(
                ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        } else {
            QuicAddr FirstServerLocalAddr, FirstClientLocalAddr;
            TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstServerLocalAddr));
            TEST_QUIC_SUCCEEDED(ServerContext.Connection->GetLocalAddr(FirstClientLocalAddr));
            PathParam = { &FirstClientLocalAddr.SockAddr, &FirstServerLocalAddr.SockAddr };
            TEST_QUIC_SUCCEEDED(
                ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_REMOVE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        }
    } else {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        if (AddressType == NewLocalAddress) {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(PairAddr.SockAddr),
                &PairAddr.SockAddr);
#if defined(_WIN32)
            TEST_TRUE(QUIC_FAILED(Status));
            return;
#endif
        } else {
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
                if (QUIC_FAILED(Status)) {
                    SecondAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ACTIVATE_PATH,
                sizeof(PathParam),
                &PathParam);
            TEST_TRUE(QUIC_FAILED(Status));
            return;
        } else {
            if (AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
            } else {
                PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            }
            Try = 0;
            do {
                Status = ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
    }

    TEST_TRUE(ClientContext.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerNewRemoteAddr, ServerNewLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(ServerNewRemoteAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ServerNewLocalAddr));
    if (AddressType == NewLocalAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    } else { // AddressType == NewBothAddresses
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
        TEST_TRUE(QuicAddrCompare(&PairAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    }
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
    TEST_TRUE(ServerContext.StreamCountEvent.WaitTimeout(1500));
}

#endif
