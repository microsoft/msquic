/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests various features related to the data path.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "DataTest.cpp.clog.h"
#endif
#if defined(_KERNEL_MODE)
static bool UseQTIP = false;
#elif defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
extern bool UseQTIP;
#endif

/*
    Helper function to estimate a maximum timeout for a test with a
    particular payload length.
*/
uint32_t
EstimateTimeoutMs(uint64_t Length)
{
    const uint64_t EstimatedHandshakeTime = 2000;
    const uint64_t EstimatedStreamOverhead = 1000;
    const uint64_t EstimatedRateBps = 1 * 1000 * 1000; // 1 MBps

    uint64_t TimeoutMs =
        EstimatedHandshakeTime +
        EstimatedStreamOverhead +
        (1000 * Length) / EstimatedRateBps;
#if QUIC_SEND_FAKE_LOSS
    TimeoutMs *= 10 * 100 * 100 / ((100 - QUIC_SEND_FAKE_LOSS) * (100 - QUIC_SEND_FAKE_LOSS));
#endif
    return (uint32_t)TimeoutMs;
}

struct PingStats
{
    const uint64_t PayloadLength;
    const uint32_t ConnectionCount;
    const uint32_t StreamCount;
    const bool FifoScheduling;
    const bool UnidirectionalStreams;
    const bool ServerInitiatedStreams;
    const bool ZeroRtt;
    const bool AllowDataIncomplete;
    const bool ServerKeyUpdate;
    const QUIC_STATUS ExpectedCloseStatus;

    volatile long ConnectionsComplete;
    volatile long SecretsIndex;

    CXPLAT_EVENT CompletionEvent;

    QUIC_BUFFER* ResumptionTicket {nullptr};

    QUIC_TLS_SECRETS* TlsSecrets {nullptr};

    PingStats(
        uint64_t _PayloadLength,
        uint32_t _ConnectionCount,
        uint32_t _StreamCount,
        bool _FifoScheduling,
        bool _UnidirectionalStreams,
        bool _ServerInitiatedStreams,
        bool _ZeroRtt,
        bool _AllowDataIncomplete = false,
        QUIC_STATUS _ExpectedCloseStatus = QUIC_STATUS_SUCCESS,
        bool _ServerKeyUpdate = false
        ) :
        PayloadLength(_PayloadLength),
        ConnectionCount(_ConnectionCount),
        StreamCount(_StreamCount),
        FifoScheduling(_FifoScheduling),
        UnidirectionalStreams(_UnidirectionalStreams),
        ServerInitiatedStreams(_ServerInitiatedStreams),
        ZeroRtt(_ZeroRtt),
        AllowDataIncomplete(_AllowDataIncomplete),
        ServerKeyUpdate(_ServerKeyUpdate),
        ExpectedCloseStatus(_ExpectedCloseStatus),
        ConnectionsComplete(0),
        SecretsIndex(0)
    {
        CxPlatEventInitialize(&CompletionEvent, FALSE, FALSE);
    }

    ~PingStats() {
        CxPlatEventUninitialize(CompletionEvent);
        CxPlatZeroMemory(&CompletionEvent, sizeof(CompletionEvent));
        if (ResumptionTicket) {
            CXPLAT_FREE(ResumptionTicket, QUIC_POOL_TEST);
        }
    }
};

struct PingConnState
{
    PingStats* Stats;
    TestConnection* Connection;
    volatile long StreamsComplete;

    ~PingConnState() {
        Stats = nullptr;
        Connection = nullptr;
    }

    PingStats* GetPingStats() { return Stats; }

    PingConnState(PingStats* stats, TestConnection* connection) :
        Stats(stats), Connection(connection), StreamsComplete(0)
    { }

    void OnStreamComplete() {
        if ((uint32_t)InterlockedIncrement(&StreamsComplete) == Stats->StreamCount) {
            if ((uint32_t)InterlockedIncrement(&Stats->ConnectionsComplete) == Stats->ConnectionCount) {
                CxPlatEventSet(Stats->CompletionEvent);
            }
        }
    }
};

_Function_class_(STREAM_SHUTDOWN_CALLBACK)
static
void
PingStreamShutdown(
    _In_ TestStream* Stream
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    PingConnState* ConnState = (PingConnState*)Stream->Context;

    // TODO - More Validation
    if (!Stream->GetSendShutdown()) {
        TEST_FAILURE("Send path not shut down.");
    }
    if (!ConnState->GetPingStats()->AllowDataIncomplete) {
        if (!Stream->GetAllDataSent()) {
            TEST_FAILURE("Not all data sent.");
        }
        if (!Stream->GetAllDataReceived()) {
            TEST_FAILURE("Not all data received.");
        }
    }

#if !QUIC_SEND_FAKE_LOSS
    if (!ConnState->GetPingStats()->ServerInitiatedStreams &&
        !ConnState->GetPingStats()->FifoScheduling &&
        ConnState->GetPingStats()->ZeroRtt) {
        if (Stream->GetBytesReceived() != 0 && // TODO - Support 0-RTT indication for Stream Open callback.
            !Stream->GetUsedZeroRtt()) {
            TEST_FAILURE("0-RTT wasn't used for stream data.");
        }
    }
#endif

    if (ConnState->StreamsComplete > 0 && ConnState->StreamsComplete % 2 == 0 && ConnState->Stats->ServerKeyUpdate) {
        if (QUIC_FAILED(ConnState->Connection->ForceKeyUpdate())) {
            TEST_FAILURE("Server ForceKeyUpdate failed.");
        }
    }

    if (ConnState->Connection->GetIsShutdown()) {
        TEST_TRUE(Stream->GetConnectionShutdown());
        TEST_EQUAL(ConnState->Connection->GetPeerClosed(), Stream->GetShutdownByApp());
        TEST_EQUAL(ConnState->Connection->GetPeerClosed(), Stream->GetClosedRemotely());
        TEST_EQUAL(ConnState->Connection->GetTransportClosed(), !Stream->GetShutdownByApp());
        TEST_EQUAL(ConnState->Connection->GetTransportClosed(), !Stream->GetClosedRemotely());
        if (ConnState->Connection->GetTransportClosed()) {
            TEST_EQUAL(ConnState->Connection->GetTransportCloseStatus(), Stream->GetConnectionCloseStatus());
        }
        if (ConnState->Connection->GetPeerClosed()) {
            TEST_EQUAL(ConnState->Connection->GetExpectedPeerCloseErrorCode(), Stream->GetConnectionErrorCode());
        }
    }

    ConnState->OnStreamComplete();

    delete Stream;
}

bool
SendPingBurst(
    _In_ TestConnection* Connection,
    _In_ uint32_t StreamCount,
    _In_ uint64_t PayloadLength
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    for (uint32_t i = 0; i < StreamCount; ++i) {
        auto Stream =
            Connection->NewStream(
                PingStreamShutdown,
                ((PingConnState*)Connection->Context)->Stats->UnidirectionalStreams ?
                    QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE,
                PayloadLength == 0 ? NEW_STREAM_START_NONE : NEW_STREAM_START_SYNC);
        if (Stream == nullptr) {
            return false;
        }
        Stream->Context = Connection->Context;
        if (!Stream->StartPing(PayloadLength)) {
            return false;
        }
    }

    return true;
}

_Function_class_(CONN_SHUTDOWN_COMPLETE_CALLBACK)
static
void
PingConnectionShutdown(
    _In_ TestConnection* Connection
    )
{
    auto ConnState = (PingConnState*)Connection->Context;
    auto ExpectedSuccess =
        ConnState->GetPingStats()->ExpectedCloseStatus == QUIC_STATUS_SUCCESS;
    delete ConnState;

    if (ExpectedSuccess) {
        TEST_FALSE(Connection->GetTransportClosed());
        TEST_FALSE(Connection->GetPeerClosed());
    }
}

_Function_class_(NEW_STREAM_CALLBACK)
static
void
ConnectionAcceptPingStream(
    _In_ TestConnection* Connection,
    _In_ HQUIC StreamHandle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags
    )
{
    TestScopeLogger logScope(__FUNCTION__);
    auto Stream = TestStream::FromStreamHandle(StreamHandle, PingStreamShutdown, Flags);
    if (Stream == nullptr || !Stream->IsValid()) {
        delete Stream;
        TEST_FAILURE("Failed to accept new TestStream.");
    } else {
        Stream->Context = Connection->Context;
    }
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerAcceptPingConnection(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    auto Connection = new(std::nothrow) TestConnection(ConnectionHandle, ConnectionAcceptPingStream);
    if (Connection == nullptr || !(Connection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete Connection;
        return false;
    }
    Connection->SetAutoDelete();

    auto Stats = (PingStats*)Listener->Context;
    Connection->Context = new(std::nothrow) PingConnState(Stats, Connection);
    Connection->SetShutdownCompleteCallback(PingConnectionShutdown);
    Connection->SetExpectedResumed(Stats->ZeroRtt);
    if (Stats->ExpectedCloseStatus != QUIC_STATUS_SUCCESS) {
        Connection->SetExpectedTransportCloseStatus(Stats->ExpectedCloseStatus);
        if (Stats->ExpectedCloseStatus == QUIC_STATUS_CONNECTION_TIMEOUT) {
            Connection->SetDisconnectTimeout(1000); // ms
        }
    }

    if (Stats->TlsSecrets) {
        auto Status = Connection->SetTlsSecrets(
            &(Stats->TlsSecrets[InterlockedIncrement(&Stats->SecretsIndex) - 1]));
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("SetParam(QUIC_TLS_SECRETS) failed with 0x%x", Status);
            return false;
        }
    }

    Connection->SetPriorityScheme(
        Stats->FifoScheduling ?
            QUIC_STREAM_SCHEDULING_SCHEME_FIFO :
            QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN);

    if (Stats->ServerInitiatedStreams) {
        SendPingBurst(
            Connection,
            Stats->StreamCount,
            Stats->PayloadLength);
    }

    return true;
}

TestConnection*
NewPingConnection(
    _In_ MsQuicRegistration& Registration,
    _In_ PingStats* ClientStats,
    _In_ bool UseSendBuffer
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    auto Connection = new(std::nothrow) TestConnection(Registration, ConnectionAcceptPingStream);
    if (Connection == nullptr || !(Connection)->IsValid()) {
        TEST_FAILURE("Failed to create new TestConnection.");
        delete Connection;
        return nullptr;
    }
    Connection->SetAutoDelete();

    if (UseSendBuffer) {
        if (QUIC_FAILED(Connection->SetUseSendBuffer(true))) {
            TEST_FAILURE("SetUseSendBuffer failed.");
            delete Connection;
            return nullptr;
        }
    }

    Connection->Context = new(std::nothrow) PingConnState(ClientStats, Connection);
    Connection->SetShutdownCompleteCallback(PingConnectionShutdown);
    Connection->SetExpectedResumed(ClientStats->ZeroRtt);
    if (ClientStats->ResumptionTicket) {
        Connection->SetResumptionTicket(ClientStats->ResumptionTicket);
    }

    Connection->SetPriorityScheme(
        ClientStats->FifoScheduling ?
            QUIC_STREAM_SCHEDULING_SCHEME_FIFO :
            QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN);

    if (ClientStats->ServerInitiatedStreams) {
        Connection->SetPeerUnidiStreamCount((uint16_t)ClientStats->StreamCount);
        Connection->SetPeerBidiStreamCount((uint16_t)ClientStats->StreamCount);
    }

    if (ClientStats->ConnectionCount > 1) {
        Connection->SetShareUdpBinding(true);
    }

    return Connection;
}

void
QuicTestConnectAndPing(
    _In_ int Family,
    _In_ uint64_t Length,
    _In_ uint32_t ConnectionCount,
    _In_ uint32_t StreamCount,
    _In_ uint32_t StreamBurstCount,
    _In_ uint32_t StreamBurstDelayMs,
    _In_ bool ServerStatelessRetry,
    _In_ bool /* ClientRebind */, // TODO - Use this
    _In_ bool ClientZeroRtt,
    _In_ bool ServerRejectZeroRtt,
    _In_ bool UseSendBuffer,
    _In_ bool UnidirectionalStreams,
    _In_ bool ServerInitiatedStreams,
    _In_ bool FifoScheduling
    )
{
    MsQuicRegistration Registration(NULL, QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT, true);
    TEST_TRUE(Registration.IsValid());

    const uint32_t TimeoutMs = EstimateTimeoutMs(Length) * StreamBurstCount;
    const uint16_t TotalStreamCount = (uint16_t)(StreamCount * StreamBurstCount);
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    PingStats ServerStats(Length, ConnectionCount, TotalStreamCount, FifoScheduling, UnidirectionalStreams, ServerInitiatedStreams, ClientZeroRtt && !ServerRejectZeroRtt, false, QUIC_STATUS_SUCCESS);
    PingStats ClientStats(Length, ConnectionCount, TotalStreamCount, FifoScheduling, UnidirectionalStreams, ServerInitiatedStreams, ClientZeroRtt && !ServerRejectZeroRtt);

    if (ServerRejectZeroRtt) {
        //
        // TODO: Validate new connections don't do 0-RTT
        //
    }

    UniquePtr<QUIC_TLS_SECRETS[]> ClientSecrets;
    UniquePtr<QUIC_TLS_SECRETS[]> ServerSecrets;
    if (ClientZeroRtt && !ServerRejectZeroRtt) {
        ClientSecrets.reset(
                new(std::nothrow) QUIC_TLS_SECRETS[ConnectionCount]);
        ServerSecrets.reset(
                new(std::nothrow) QUIC_TLS_SECRETS[ConnectionCount]);
        if (ClientSecrets == nullptr || ServerSecrets == nullptr) {
            return;
        }
        ServerStats.TlsSecrets = ServerSecrets.get();
    }

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    if (ClientZeroRtt) {
        Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT);
    }
    if (!ServerInitiatedStreams) {
        Settings.SetPeerBidiStreamCount(TotalStreamCount);
        Settings.SetPeerUnidiStreamCount(TotalStreamCount);
    }
    Settings.SetSendBufferingEnabled(UseSendBuffer);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    QUIC_TICKET_KEY_CONFIG GoodKey;
    CxPlatZeroMemory(&GoodKey, sizeof(GoodKey));
    GoodKey.MaterialLength = 64;

    QUIC_TICKET_KEY_CONFIG BadKey;
    CxPlatZeroMemory(&BadKey, sizeof(BadKey));
    BadKey.MaterialLength = 64;
    BadKey.Material[0] = 0xFF;

    if (ServerRejectZeroRtt) {
        TEST_QUIC_SUCCEEDED(ServerConfiguration.SetTicketKey(&GoodKey));
    }

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    if (ClientZeroRtt) {
        QuicTestPrimeResumption(
            QuicAddrFamily,
            Registration,
            ServerConfiguration,
            ClientConfiguration,
            &ClientStats.ResumptionTicket);
        if (!ClientStats.ResumptionTicket) {
            return;
        }
    }

    StatelessRetryHelper RetryHelper(ServerStatelessRetry);

    {
        if (ServerRejectZeroRtt) {
            TEST_QUIC_SUCCEEDED(ServerConfiguration.SetTicketKey(&BadKey));
        }
        TestListener Listener(
            Registration,
            ListenerAcceptPingConnection,
            ServerConfiguration
            );
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        Listener.Context = &ServerStats;

        TestConnection** ConnAlloc = new(std::nothrow) TestConnection*[ConnectionCount];
        if (ConnAlloc == nullptr) {
            return;
        }

        UniquePtrArray<TestConnection*> Connections(ConnAlloc);

        for (uint32_t i = 0; i < ClientStats.ConnectionCount; ++i) {
            Connections.get()[i] =
                NewPingConnection(
                    Registration,
                    &ClientStats,
                    UseSendBuffer);
            if (Connections.get()[i] == nullptr) {
                return;
            }
            if (ClientSecrets) {
                TEST_QUIC_SUCCEEDED(
                    Connections.get()[i]->SetTlsSecrets(&ClientSecrets[i]));
            }
        }

        QuicAddr LocalAddr;
        for (uint32_t j = 0; j < StreamBurstCount; ++j) {
            if (j != 0) {
                CxPlatSleep(StreamBurstDelayMs);
            }

            for (uint32_t i = 0; i < ClientStats.ConnectionCount; ++i) {
                if (!ServerInitiatedStreams &&
                    !SendPingBurst(
                        Connections.get()[i],
                        StreamCount,
                        Length)) {
                    return;
                }

                if (j == 0) {
                    QuicAddr RemoteAddr(QuicAddrFamily, true);
                    if (UseDuoNic) {
                        QuicAddrSetToDuoNic(&RemoteAddr.SockAddr);
                    }
                    TEST_QUIC_SUCCEEDED(Connections.get()[i]->SetRemoteAddr(RemoteAddr));

                    if (i != 0
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
                        && !UseQTIP
#endif
                    ) {
                        Connections.get()[i]->SetLocalAddr(LocalAddr);
                    }

                    TEST_QUIC_SUCCEEDED(
                        Connections.get()[i]->Start(
                            ClientConfiguration,
                            QuicAddrFamily,
                            ClientZeroRtt ? QUIC_LOCALHOST_FOR_AF(QuicAddrFamily) : nullptr,
                            ServerLocalAddr.GetPort()));

                    if (i == 0
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
                        && !UseQTIP
#endif
                    ) {
                        Connections.get()[i]->GetLocalAddr(LocalAddr);
                    }
                }
            }
        }

        if (!CxPlatEventWaitWithTimeout(ClientStats.CompletionEvent, TimeoutMs)) {
            TEST_FAILURE("Wait for clients to complete timed out after %u ms.", TimeoutMs);
            return;
        }

        if (!CxPlatEventWaitWithTimeout(ServerStats.CompletionEvent, TimeoutMs)) {
            TEST_FAILURE("Wait for server to complete timed out after %u ms.", TimeoutMs);
            return;
        }

        if (ClientSecrets) {
            for (auto i = 0u; i < ConnectionCount; i++) {
                auto ServerSecret = &ServerSecrets[i];
                bool Match = false;
                for (auto j = 0u; j < ConnectionCount; j++) {
                    auto ClientSecret = &ClientSecrets[j];
                    if (!memcmp(
                            ServerSecret->ClientRandom,
                            ClientSecret->ClientRandom,
                            sizeof(ClientSecret->ClientRandom))) {
                        if (Match) {
                            TEST_FAILURE("Multiple clients with the same ClientRandom?!");
                            return;
                        }

                        TEST_EQUAL(
                            ClientSecret->IsSet.ClientEarlyTrafficSecret,
                            ServerSecret->IsSet.ClientEarlyTrafficSecret);
                        TEST_EQUAL(
                            ClientSecret->SecretLength,
                            ServerSecret->SecretLength);
                        TEST_TRUE(
                            !memcmp(
                                ClientSecret->ClientEarlyTrafficSecret,
                                ServerSecret->ClientEarlyTrafficSecret,
                                ClientSecret->SecretLength));
                        Match = true;
                    }
                }
                if (!Match) {
                    TEST_FAILURE("Failed to match Server Secrets to any Client Secrets!");
                    return;
                }
            }
        }
    }
}

void
QuicTestServerDisconnect(
    void
    )
{
    PingStats ServerStats(UINT64_MAX - 1, 1, 1, TRUE, TRUE, TRUE, FALSE, TRUE, QUIC_STATUS_CONNECTION_TIMEOUT);
    PingStats ClientStats(UINT64_MAX - 1, 1, 1, TRUE, TRUE, TRUE, FALSE, TRUE);

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
        TestListener Listener(Registration, ListenerAcceptPingConnection, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        Listener.Context = &ServerStats;
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            TestConnection* Client =
                NewPingConnection(
                    Registration,
                    &ClientStats,
                    FALSE);
            if (Client == nullptr) {
                return;
            }
            TEST_QUIC_SUCCEEDED(Client->SetPeerUnidiStreamCount(1));

            TEST_QUIC_SUCCEEDED(
                Client->Start(
                    ClientConfiguration,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_TEST_LOOPBACK_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            CxPlatSleep(500); // Sleep for a little bit.

            Client->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
        }
    }
}

_Function_class_(STREAM_SHUTDOWN_CALLBACK)
static
void
IgnoreStreamShutdown(
    _In_ TestStream* Stream
    )
{
    delete Stream;
}

_Function_class_(NEW_STREAM_CALLBACK)
static
void
ConnectionAcceptAndIgnoreStream(
    _In_ TestConnection* Connection,
    _In_ HQUIC StreamHandle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags
    )
{
    TestScopeLogger logScope(__FUNCTION__);
    auto Stream = TestStream::FromStreamHandle(StreamHandle, IgnoreStreamShutdown, Flags);
    if (Stream == nullptr || !Stream->IsValid()) {
        delete Stream;
        TEST_FAILURE("Failed to accept new TestStream.");
    } else {
        Stream->Context = Connection->Context;
    }
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerAcceptConnectionAndStreams(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    ServerAcceptContext* AcceptContext = (ServerAcceptContext*)Listener->Context;
    *AcceptContext->NewConnection = new(std::nothrow) TestConnection(ConnectionHandle, ConnectionAcceptAndIgnoreStream);
    if (*AcceptContext->NewConnection == nullptr || !(*AcceptContext->NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *AcceptContext->NewConnection;
        *AcceptContext->NewConnection = nullptr;
        return false;
    }
    CxPlatEventSet(AcceptContext->NewConnectionReady);
    return true;
}

void
QuicTestClientDisconnect(
    bool StopListenerFirst
    )
{
    //
    // If the listener is stopped at the same time the server side of the
    // connection is silently closed, then the UDP binding will also be cleaned
    // up. This means the endpoint will no longer send Stateless Reset packets
    // back to the client as it continues to receive the client's UDP packets.
    //

    PingStats ClientStats(UINT64_MAX - 1, 1, 1, TRUE, TRUE, FALSE, FALSE, TRUE,
        StopListenerFirst ? QUIC_STATUS_CONNECTION_TIMEOUT : QUIC_STATUS_ABORTED);

    CxPlatEvent EventClientDeleted(true);

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(10000);
    Settings.SetPeerUnidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnectionAndStreams, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            TestConnection* Client =
                NewPingConnection(
                    Registration,
                    &ClientStats,
                    false);
            if (Client == nullptr) {
                return;
            }

            Client->SetDeletedEvent(&EventClientDeleted.Handle);

            Client->SetExpectedTransportCloseStatus(ClientStats.ExpectedCloseStatus);
            TEST_QUIC_SUCCEEDED(Client->SetDisconnectTimeout(1000)); // ms

            if (!SendPingBurst(
                    Client,
                    ClientStats.StreamCount,
                    ClientStats.PayloadLength)) {
                return;
            }

            TEST_QUIC_SUCCEEDED(
                Client->Start(
                    ClientConfiguration,
                    QUIC_ADDRESS_FAMILY_INET,
                    QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
                    ServerLocalAddr.GetPort()));

            if (!Client->WaitForConnectionComplete()) {
                return;
            }
            TEST_TRUE(Client->GetIsConnected());

            TEST_NOT_EQUAL(nullptr, Server);
            if (!Server->WaitForConnectionComplete()) {
                return;
            }
            TEST_TRUE(Server->GetIsConnected());

            if (StopListenerFirst) {
                Listener.Stop();
            }

            CxPlatSleep(15); // Sleep for just a bit.

            Server->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
        }

        if (!CxPlatEventWaitWithTimeout(EventClientDeleted.Handle, TestWaitTimeout)) {
            TEST_FAILURE("Wait for EventClientDeleted timed out after %u ms.", TestWaitTimeout);
        }
    }
}

void
QuicTestStatelessResetKey(
    )
{
    //
    // By changing the stateless reset key, the stateless reset packets the client
    // receives after the server side is shut down no longer match, eventually resulting
    // in a timeout on the client instead of an abort.
    //

    PingStats ClientStats(UINT64_MAX - 1, 1, 1, TRUE, TRUE, FALSE, FALSE, TRUE, QUIC_STATUS_CONNECTION_TIMEOUT);

    CxPlatEvent EventClientDeleted(true);

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(10000);
    Settings.SetPeerUnidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnectionAndStreams, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            UniquePtr<TestConnection> Server;
            ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
            Listener.Context = &ServerAcceptCtx;

            TestConnection* Client =
                NewPingConnection(
                    Registration,
                    &ClientStats,
                    false);
            if (Client == nullptr) {
                return;
            }

            Client->SetDeletedEvent(&EventClientDeleted.Handle);

            Client->SetExpectedTransportCloseStatus(ClientStats.ExpectedCloseStatus);
            TEST_QUIC_SUCCEEDED(Client->SetDisconnectTimeout(1000)); // ms

            if (!SendPingBurst(
                    Client,
                    ClientStats.StreamCount,
                    ClientStats.PayloadLength)) {
                return;
            }

            TEST_QUIC_SUCCEEDED(
                Client->Start(
                    ClientConfiguration,
                    QUIC_ADDRESS_FAMILY_INET,
                    QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
                    ServerLocalAddr.GetPort()));

            if (!Client->WaitForConnectionComplete()) {
                return;
            }
            TEST_TRUE(Client->GetIsConnected());

            TEST_NOT_EQUAL(nullptr, Server);
            if (!Server->WaitForConnectionComplete()) {
                return;
            }
            TEST_TRUE(Server->GetIsConnected());

            CxPlatSleep(15); // Sleep for just a bit.

            uint8_t StatelessResetKey[QUIC_STATELESS_RESET_KEY_LENGTH];
            CxPlatRandom(sizeof(StatelessResetKey), StatelessResetKey);
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY,
                    sizeof(StatelessResetKey),
                    StatelessResetKey));

            Server->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
        }

        if (!CxPlatEventWaitWithTimeout(EventClientDeleted.Handle, TestWaitTimeout)) {
            TEST_FAILURE("Wait for EventClientDeleted timed out after %u ms.", TestWaitTimeout);
        }
    }
}

struct AbortiveTestContext {
    AbortiveTestContext(
        _In_ HQUIC ServerConfiguration,
        _In_ bool ServerParam,
        _In_ QUIC_ABORTIVE_TRANSFER_FLAGS FlagsParam,
        _In_ uint32_t ExpectedErrorParam,
        _In_ QUIC_STREAM_SHUTDOWN_FLAGS ShutdownFlagsParam) :
            ServerConfiguration(ServerConfiguration),
            Flags(FlagsParam),
            ShutdownFlags(ShutdownFlagsParam),
            ExpectedError(ExpectedErrorParam),
            TestResult(0),
            Server(ServerParam)
    { }
    HQUIC ServerConfiguration;
    CxPlatEvent ConnectedEvent;
    CxPlatEvent StreamEvent;
    CxPlatEvent TestEvent;
    ConnectionScope Conn;
    StreamScope Stream;
    const QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
    QUIC_STREAM_SHUTDOWN_FLAGS ShutdownFlags;
    uint32_t ExpectedError;
    uint32_t TestResult;
    uint8_t Passed : 1;
    uint8_t Server : 1;
};


_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicAbortiveStreamHandler(
    _In_ HQUIC QuicStream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    AbortiveTestContext* TestContext = (AbortiveTestContext*) Context;
    const QUIC_ABORTIVE_TRANSFER_FLAGS* Flags = &TestContext->Flags;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            if (TestContext->Flags.PauseReceive) {
                Event->RECEIVE.TotalBufferLength = 0; // Pause by not draining
            }
            if (TestContext->Server &&
                !TestContext->Flags.ClientShutdown &&
                TestContext->Flags.SendDataOnStream) {
                Status =
                    MsQuic->StreamShutdown(
                        QuicStream,
                        TestContext->ShutdownFlags,
                        TestContext->ExpectedError);
                if (QUIC_FAILED(Status)) {
                    TestContext->Passed = false;
                    TestContext->TestResult = Status;
                }
                CxPlatEventSet(TestContext->TestEvent.Handle);
            }
            if (TestContext->Flags.PendReceive) {
                return QUIC_STATUS_PENDING;
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            if (TestContext->Server && Flags->ShutdownDirection == ShutdownSend) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_SEND_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                CxPlatEventSet(TestContext->TestEvent.Handle);
            } else if (!TestContext->Server && !Flags->ClientShutdown &&
                (Flags->ShutdownDirection == ShutdownBoth || Flags->ShutdownDirection == ShutdownSend)) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_SEND_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                CxPlatEventSet(TestContext->TestEvent.Handle);
                }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            TestContext->Passed = (TestContext->ExpectedError == Event->PEER_SEND_ABORTED.ErrorCode);
            TestContext->TestResult = (uint32_t) Event->PEER_SEND_ABORTED.ErrorCode;
            CxPlatEventSet(TestContext->TestEvent.Handle);
            break;
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            if (TestContext->Server && Flags->ShutdownDirection == ShutdownReceive) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_RECEIVE_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                CxPlatEventSet(TestContext->TestEvent.Handle);
            } else if (!TestContext->Server && !Flags->ClientShutdown &&
                (TestContext->Flags.ShutdownDirection == ShutdownBoth || TestContext->Flags.ShutdownDirection == ShutdownReceive)) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_RECEIVE_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                CxPlatEventSet(TestContext->TestEvent.Handle);
            }
            break;
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            if (!TestContext->Passed) {
                TestContext->Passed = false;
                TestContext->TestResult = (uint32_t) QUIC_STATUS_CONNECTION_IDLE;
            }
            if (!TestContext->Stream.Handle) {
                MsQuic->StreamClose(QuicStream);
            }
            break;
        case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
            break;
        default:
            break;
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicAbortiveConnectionHandler(
    _In_ HQUIC /* QuicConnection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    AbortiveTestContext* TestContext = (AbortiveTestContext*) Context;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            MsQuic->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream,
                (void*)QuicAbortiveStreamHandler,
                Context);

            if (TestContext->Server &&
                !TestContext->Flags.ClientShutdown &&
                !TestContext->Flags.SendDataOnStream) {
                Status =
                    MsQuic->StreamShutdown(
                        Event->PEER_STREAM_STARTED.Stream,
                        TestContext->ShutdownFlags,
                        TestContext->ExpectedError);
                if (QUIC_FAILED(Status)) {
                    TestContext->Passed = false;
                    TestContext->TestResult = Status;
                }
                CxPlatEventSet(TestContext->TestEvent.Handle);
            }
            CxPlatEventSet(TestContext->StreamEvent.Handle);
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_CONNECTED:
            CxPlatEventSet(TestContext->ConnectedEvent.Handle);
            __fallthrough;
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_RESUMED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
            return QUIC_STATUS_SUCCESS;
        default:
            TEST_FAILURE(
                "Invalid Connection event! Context: 0x%p, Event: %d",
                Context,
                Event->Type);
            return QUIC_STATUS_NOT_SUPPORTED;
    }
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicAbortiveListenerHandler(
    _In_ MsQuicListener* /* QuicListener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    AbortiveTestContext* TestContext = (AbortiveTestContext*)Context;
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            TestContext->Conn.Handle = Event->NEW_CONNECTION.Connection;
            MsQuic->SetCallbackHandler(TestContext->Conn.Handle, (void*) QuicAbortiveConnectionHandler, Context);
            return MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, TestContext->ServerConfiguration);
        case QUIC_LISTENER_EVENT_STOP_COMPLETE:
            return QUIC_STATUS_SUCCESS;
        default:
            TEST_FAILURE(
                "Invalid listener event! Context: 0x%p, Event: %d",
                Context,
                Event->Type);
            return QUIC_STATUS_INVALID_STATE;
    }
}

void
QuicAbortiveTransfers(
    _In_ int Family,
    _In_ QUIC_ABORTIVE_TRANSFER_FLAGS Flags
    )
{
    uint32_t TimeoutMs = 2000;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    /*
        Test Cases:
        *   Sender closes the stream before data has even been sent.
        *   Sender closes the stream immediately after data has been queued.
        *   Receiver closes stream as soon as it arrives.
        *   Receiver closes stream as soon as data arrives.
    */

    bool WaitForConnected = true;
    uint32_t ExpectedError = Flags.IntValue;

    uint16_t StreamCount = 1;
    int SendLength = 100;
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr;
    QuicBufferScope Buffer(SendLength);
    QUIC_STREAM_SHUTDOWN_FLAGS ShutdownFlags;
    switch (Flags.ShutdownDirection) {
        case ShutdownBoth:
            ShutdownFlags = QUIC_STREAM_SHUTDOWN_FLAG_ABORT;
            break;
        case ShutdownSend:
            ShutdownFlags = QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND;
            break;
        case ShutdownReceive:
            ShutdownFlags = QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE;
            break;
        default:
            TEST_FAILURE("Invalid stream shutdown direction, %d", Flags.ShutdownDirection);
            return;
    }

    {
        AbortiveTestContext ClientContext(nullptr, false, Flags, ExpectedError, ShutdownFlags), ServerContext(ServerConfiguration, true, Flags, ExpectedError, ShutdownFlags);

        MsQuicListener Listener(Registration, CleanUpManual, QuicAbortiveListenerHandler, &ServerContext);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        //
        // Start the client
        //
        QUIC_STATUS Status =
            MsQuic->ConnectionOpen(
                Registration,
                QuicAbortiveConnectionHandler,
                &ClientContext,
                &ClientContext.Conn.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                ClientContext.Conn.Handle,
                ClientConfiguration,
                QuicAddrFamily,
                QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (WaitForConnected) {
            if (!CxPlatEventWaitWithTimeout(ClientContext.ConnectedEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Client failed to get connected before timeout!");
                return;
            }
            if (!CxPlatEventWaitWithTimeout(ServerContext.ConnectedEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Server failed to get connected before timeout!");
                return;
            }
        }

        //
        // Create a stream on the client
        //
        QUIC_STREAM_OPEN_FLAGS StreamFlags =
            (Flags.UnidirectionalStream ?
                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE);
        Status =
            MsQuic->StreamOpen(
                ClientContext.Conn.Handle,
                StreamFlags,
                QuicAbortiveStreamHandler,
                &ClientContext,
                &ClientContext.Stream.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamOpen failed, 0x%x.", Status);
            return;
        }
        Status =
            MsQuic->StreamStart(
                ClientContext.Stream.Handle,
                QUIC_STREAM_START_FLAG_IMMEDIATE);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamStart failed, 0x%x.", Status);
            return;
        }

        if (!Flags.DelayStreamCreation) {
            QUIC_SETTINGS Settings{0};
            if (Flags.UnidirectionalStream) {
                Settings.PeerUnidiStreamCount = StreamCount;
                Settings.IsSet.PeerUnidiStreamCount = TRUE;
            } else {
                Settings.PeerBidiStreamCount = StreamCount;
                Settings.IsSet.PeerBidiStreamCount = TRUE;
            }
            Status =
                MsQuic->SetParam(
                    ServerContext.Conn.Handle,
                    QUIC_PARAM_CONN_SETTINGS,
                    sizeof(Settings),
                    &Settings);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_SETTINGS failed, 0x%x", Status);
                return;
            }
        }

        if (Flags.WaitForStream && !Flags.DelayStreamCreation) {
            if (!CxPlatEventWaitWithTimeout(ServerContext.StreamEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Server failed to get stream before timeout!");
                return;
            }
        }

        if (Flags.SendDataOnStream) {
            Status =
                MsQuic->StreamSend(
                    ClientContext.Stream.Handle,
                    Buffer,
                    1,
                    QUIC_SEND_FLAG_NONE,
                    nullptr); // send contxt
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->StreamSend failed, 0x%x.", Status);
                return;
            }
        }

        if (Flags.ClientShutdown && !Flags.DelayClientShutdown) {
            Status =
                MsQuic->StreamShutdown(
                    ClientContext.Stream.Handle,
                    ShutdownFlags,
                    ExpectedError);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->StreamShutdown failed, 0x%x.", Status);
                return;
            }
            CxPlatEventSet(ClientContext.TestEvent.Handle);
        }

        if (Flags.DelayStreamCreation) {
            QUIC_SETTINGS Settings{0};
            if (Flags.UnidirectionalStream) {
                Settings.PeerUnidiStreamCount = StreamCount;
                Settings.IsSet.PeerUnidiStreamCount = TRUE;
            } else {
                Settings.PeerBidiStreamCount = StreamCount;
                Settings.IsSet.PeerBidiStreamCount = TRUE;
            }
            Status =
                MsQuic->SetParam(
                    ServerContext.Conn.Handle,
                    QUIC_PARAM_CONN_SETTINGS,
                    sizeof(Settings),
                    &Settings);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_SETTINGS failed, 0x%x", Status);
                return;
            }
        }

        if (Flags.ClientShutdown && Flags.DelayClientShutdown) {
            Status =
                MsQuic->StreamShutdown(
                    ClientContext.Stream.Handle,
                    ShutdownFlags,
                    ExpectedError);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->StreamShutdown failed, 0x%x.", Status);
                return;
            }
            CxPlatEventSet(ClientContext.TestEvent.Handle);
        }

        //
        // In these test cases, the client won't receive any packets, so signal success.
        //
        if (Flags.ClientShutdown && Flags.UnidirectionalStream && Flags.ShutdownDirection == ShutdownReceive) {
            ServerContext.TestResult = ExpectedError;
            ServerContext.Passed = true;
            CxPlatEventSet(ServerContext.TestEvent.Handle);
        } else if (!Flags.ClientShutdown && Flags.UnidirectionalStream && Flags.ShutdownDirection == ShutdownSend) {
            ClientContext.TestResult = ExpectedError;
            ClientContext.Passed = true;
            CxPlatEventSet(ClientContext.TestEvent.Handle);
        }

        if (!Flags.ClientShutdown) {
            if (!CxPlatEventWaitWithTimeout(ClientContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Client failed to shutdown before timeout!");
                return;
            }
            if (!CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Server failed to shutdown before timeout!");
                return;
            }
            if (ExpectedError != ClientContext.TestResult) {
                TEST_FAILURE("Expected error (0x%x) is not equal to actual result (0x%x).", ExpectedError, ClientContext.TestResult);
            }
            TEST_EQUAL(ExpectedError, ClientContext.TestResult);
            TEST_TRUE(ClientContext.Passed);
        } else {
            if (!CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle,TimeoutMs )) {
                TEST_FAILURE("Server failed to shutdown before timeout!");
                return;
            }
            if (!CxPlatEventWaitWithTimeout(ClientContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Client failed to shutdown before timeout!");
                return;
            }
            if (ExpectedError != ServerContext.TestResult) {
                TEST_FAILURE("Expected error (0x%x) is not equal to actual result (0x%x).", ExpectedError, ServerContext.TestResult);
            }
            TEST_EQUAL(ExpectedError, ServerContext.TestResult);
            TEST_TRUE(ServerContext.Passed);
        }
    }
}

struct CancelOnLossContext
{
    CancelOnLossContext(bool IsDropScenario, bool IsServer, MsQuicConfiguration* Configuration)
        : IsDropScenario{ IsDropScenario }
        , IsServer{ IsServer }
        , Configuration{ Configuration }
    { }

    ~CancelOnLossContext() {
        delete Stream;
        Stream = nullptr;

        delete Connection;
        Connection = nullptr;
    }

    // Static parameters
    static constexpr uint64_t SuccessExitCode = 42;
    static constexpr uint64_t ErrorExitCode = 24;

    // State
    const bool IsDropScenario = false;
    const bool IsServer = false;
    const MsQuicConfiguration* Configuration = nullptr;
    MsQuicConnection* Connection = nullptr;
    MsQuicStream* Stream = nullptr;

    // Connection tracking
    CxPlatEvent ConnectedEvent = {};

    // Test case tracking
    uint64_t ExitCode = 0;
    CxPlatEvent SendPhaseEndedEvent = {};
};

_Function_class_(MsQuicStreamCallback)
QUIC_STATUS
QuicCancelOnLossStreamHandler(
    _In_ struct MsQuicStream* /* Stream */,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto TestContext = reinterpret_cast<CancelOnLossContext*>(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (TestContext->IsServer) { // only server receives
            TestContext->ExitCode = CancelOnLossContext::SuccessExitCode;
            TestContext->SendPhaseEndedEvent.Set();
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        if (TestContext->IsServer) { // server-side 'cancel on loss' detection
            TestContext->ExitCode = Event->PEER_SEND_ABORTED.ErrorCode;
            TestContext->SendPhaseEndedEvent.Set();
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (TestContext->IsServer) {
            TestContext->SendPhaseEndedEvent.Set();
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (!TestContext->IsServer) { // only client sends
            if (!TestContext->IsDropScenario) { // if drop scenario, we use 'cancel on loss' event
                TestContext->SendPhaseEndedEvent.Set();
            }
        }
        break;
    case QUIC_STREAM_EVENT_CANCEL_ON_LOSS:
        if (!TestContext->IsServer && TestContext->IsDropScenario) { // only client sends & only happens if in drop scenario
            Event->CANCEL_ON_LOSS.ErrorCode = CancelOnLossContext::ErrorExitCode;
            TestContext->SendPhaseEndedEvent.Set();
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(MsQuicConnectionCallback)
QUIC_STATUS
QuicCancelOnLossConnectionHandler(
    _In_ struct MsQuicConnection* /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto TestContext = reinterpret_cast<CancelOnLossContext*>(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        TestContext->Stream = new(std::nothrow) MsQuicStream(
            Event->PEER_STREAM_STARTED.Stream,
            CleanUpManual,
            QuicCancelOnLossStreamHandler,
            Context);
        break;
    case QUIC_CONNECTION_EVENT_CONNECTED:
        TestContext->ConnectedEvent.Set();
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicCancelOnLossSend(
    _In_ bool DropPackets
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(1'000);
    Settings.SetServerResumptionLevel(QUIC_SERVER_NO_RESUME);
    Settings.SetPeerBidiStreamCount(1);
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280); // avoid running path MTU discovery (PMTUD)

    uint8_t RawBuffer[] = "cancel on loss message";
    QUIC_BUFFER MessageBuffer = { sizeof(RawBuffer), RawBuffer };
    SelectiveLossHelper LossHelper; // used later to trigger packet drops

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    CancelOnLossContext ServerContext(DropPackets, true /* IsServer */, &ServerConfiguration);
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, QuicCancelOnLossConnectionHandler, &ServerContext);
    TEST_TRUE(Listener.IsValid());
    TEST_EQUAL(Listener.Start(Alpn), QUIC_STATUS_SUCCESS);
    QuicAddr ServerLocalAddr;
    TEST_EQUAL(Listener.GetLocalAddr(ServerLocalAddr), QUIC_STATUS_SUCCESS);

    CancelOnLossContext ClientContext(DropPackets, false /* IsServer */, &ClientConfiguration);
    ClientContext.Connection = new(std::nothrow) MsQuicConnection(
        Registration,
        CleanUpManual,
        QuicCancelOnLossConnectionHandler,
        &ClientContext);
    TEST_TRUE(ClientContext.Connection->IsValid());

    TEST_QUIC_SUCCEEDED(
        ClientContext.Connection->Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));

    // Wait for connection to be established.
    constexpr uint32_t EventWaitTimeoutMs{ 1'000 };
    if (!ClientContext.ConnectedEvent.WaitTimeout(EventWaitTimeoutMs)) {
        TEST_FAILURE("Client failed to get connected before timeout!");
        return;
    }
    if (!ServerContext.ConnectedEvent.WaitTimeout(EventWaitTimeoutMs)) {
        TEST_FAILURE("Server failed to get connected before timeout!");
        return;
    }

    // Sleep a bit to wait for all handshake packets to be exchanged.
    CxPlatSleep(100);

    // Set up stream.
    ClientContext.Stream = new(std::nothrow) MsQuicStream(
        *ClientContext.Connection,
        QUIC_STREAM_OPEN_FLAG_NONE,
        CleanUpManual,
        QuicCancelOnLossStreamHandler,
        &ClientContext);
    TEST_TRUE(ClientContext.Stream->IsValid());
    TEST_QUIC_SUCCEEDED(ClientContext.Stream->Start());
    TEST_QUIC_SUCCEEDED(ClientContext.Stream->Send(&MessageBuffer, 1, QUIC_SEND_FLAG_CANCEL_ON_LOSS));

    // If requested, drop packets.
    if (DropPackets) {
        LossHelper.DropPackets(1);
    }

    // Wait for the send phase to conclude.
    if (!ClientContext.SendPhaseEndedEvent.WaitTimeout(EventWaitTimeoutMs)) {
        TEST_FAILURE("Timed out waiting for send phase to conclude on client.");
        return;
    }
    if (!ServerContext.SendPhaseEndedEvent.WaitTimeout(EventWaitTimeoutMs)) {
        TEST_FAILURE("Timed out waiting for send phase to conclude on server.");
    }

    // Check results.
    if (DropPackets) {
        if (ServerContext.ExitCode != CancelOnLossContext::ErrorExitCode) {
            TEST_FAILURE("ServerContext.ExitCode %u != ErrorExitCode", ServerContext.ExitCode);
        }
    } else {
        if (ServerContext.ExitCode != CancelOnLossContext::SuccessExitCode) {
            TEST_FAILURE("ServerContext.ExitCode %u != SuccessExitCode", ServerContext.ExitCode);
        }
    }

    if (Listener.LastConnection) {
        Listener.LastConnection->Close();
    }
}

struct RecvResumeTestContext {
    RecvResumeTestContext(
        _In_ HQUIC ServerConfiguration,
        _In_ bool ServerParam,
        _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownTypeParam,
        _In_ QUIC_RECEIVE_RESUME_TYPE PauseTypeParam) :
            ServerConfiguration(ServerConfiguration),
            ShutdownType(ShutdownTypeParam),
            PauseType(PauseTypeParam),
            TestResult((uint32_t)QUIC_STATUS_INTERNAL_ERROR),
            Server(ServerParam),
            ReceiveCallbackCount(0)
    { }
    HQUIC ServerConfiguration;
    CxPlatEvent ConnectedEvent;
    CxPlatEvent StreamEvent;
    CxPlatEvent TestEvent;
    ConnectionScope Conn;
    StreamScope Stream;
    uint8_t* PendingBuffer;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    uint32_t ConsumeBufferAmount;
    uint32_t AvailableBuffer;
    uint32_t TestResult;
    uint8_t Passed : 1;
    uint8_t Server : 1;
    uint8_t ShutdownOnly : 1;
    uint8_t ReceiveCallbackCount : 3;
};

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicRecvResumeStreamHandler(
    _In_ HQUIC /*QuicStream*/,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    RecvResumeTestContext* TestContext = (RecvResumeTestContext*) Context;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            if (TestContext->Server) {

                if (Event->RECEIVE.BufferCount == 0 &&
                    (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN)) {
                    break; // Ignore FIN only receive indications.
                }

                if ((uint64_t)TestContext->ConsumeBufferAmount > Event->RECEIVE.TotalBufferLength) {
                    TEST_FAILURE("Not enough buffer received: %u (expected %u)",
                        (uint32_t)Event->RECEIVE.TotalBufferLength,
                        TestContext->ConsumeBufferAmount);
                    break;
                }

                TestContext->AvailableBuffer = (uint32_t)Event->RECEIVE.TotalBufferLength;
                Event->RECEIVE.TotalBufferLength = TestContext->ConsumeBufferAmount;

                if (TestContext->ReceiveCallbackCount == 0) {
                    if (TestContext->PauseType == ReturnStatusPending) {
                        if (Event->RECEIVE.BufferCount == 0) {
                            TEST_FAILURE("No buffers!");
                            break;
                        }
                        if (Event->RECEIVE.BufferCount > 1) {
                            TEST_FAILURE("Too many buffers! %u", Event->RECEIVE.BufferCount);
                            break;
                        }
                        TestContext->PendingBuffer = Event->RECEIVE.Buffers[0].Buffer;
                        Status = QUIC_STATUS_PENDING;
                    } else if(TestContext->PauseType == ReturnStatusContinue) {
                        TestContext->ConsumeBufferAmount = TestContext->AvailableBuffer - TestContext->ConsumeBufferAmount;
                        Status = QUIC_STATUS_CONTINUE;
                    }
                }

                TestContext->ReceiveCallbackCount++;
                //
                // Calculate test success/failure.
                //
                if (Event->RECEIVE.TotalBufferLength == TestContext->ConsumeBufferAmount) {
                    TestContext->Passed = true;
                    TestContext->TestResult = (uint32_t) QUIC_STATUS_SUCCESS;
                } else {
                    TestContext->TestResult = (uint32_t) QUIC_STATUS_INVALID_STATE;
                }
                if (TestContext->PauseType != ReturnStatusContinue || TestContext->ReceiveCallbackCount > 1) {
                    CxPlatEventSet(TestContext->TestEvent.Handle);
                }
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            if (TestContext->ShutdownType == GracefulShutdown) {
                if (TestContext->ShutdownOnly) {
                    CxPlatEventSet(TestContext->TestEvent.Handle);
                }
            } else {
                TestContext->Passed = false;
                TestContext->TestResult = (uint32_t) QUIC_STATUS_INVALID_STATE;
            }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            if (TestContext->ShutdownType == AbortShutdown) {
                TestContext->ConsumeBufferAmount = TestContext->AvailableBuffer;
                //
                // Don't hang waiting for a receive indication.
                //
                CxPlatEventSet(TestContext->TestEvent.Handle);
            } else {
                TestContext->Passed = false;
                TestContext->TestResult = (uint32_t) QUIC_STATUS_INVALID_STATE;
            }
            break;
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            TestContext->Passed = false;
            TestContext->TestResult = (uint32_t) QUIC_STATUS_INVALID_STATE;
            break;
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            if (!TestContext->Passed) {
                TestContext->Passed = false;
                TestContext->TestResult = (uint32_t) QUIC_STATUS_CONNECTION_IDLE;
            }
            break;
        case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
            break;
        default:
            break;
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicRecvResumeConnectionHandler(
    _In_ HQUIC /* QuicConnection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    RecvResumeTestContext* TestContext = (RecvResumeTestContext*) Context;
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            MsQuic->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream,
                (void*)QuicRecvResumeStreamHandler,
                Context);
            TestContext->Stream.Handle = Event->PEER_STREAM_STARTED.Stream;
            CxPlatEventSet(TestContext->StreamEvent.Handle);
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_CONNECTED:
            CxPlatEventSet(TestContext->ConnectedEvent.Handle);
            __fallthrough;
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_RESUMED:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
            __fallthrough;
        case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
            return QUIC_STATUS_SUCCESS;
        default:
            TEST_FAILURE(
                "Invalid Connection event! Context: 0x%p, Event: %d",
                Context,
                Event->Type);
            return QUIC_STATUS_NOT_SUPPORTED;
    }
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicRecvResumeListenerHandler(
    _In_ MsQuicListener* /* QuicListener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    RecvResumeTestContext* TestContext = (RecvResumeTestContext*)Context;
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            TestContext->Conn.Handle = Event->NEW_CONNECTION.Connection;
            MsQuic->SetCallbackHandler(TestContext->Conn.Handle, (void*) QuicRecvResumeConnectionHandler, Context);
            return MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, TestContext->ServerConfiguration);
        case QUIC_LISTENER_EVENT_STOP_COMPLETE:
            return QUIC_STATUS_SUCCESS;
        default:
            TEST_FAILURE(
                "Invalid listener event! Context: 0x%p, Event: %d",
                Context,
                Event->Type);
            return QUIC_STATUS_INVALID_STATE;
    }
}

void
QuicTestReceiveResume(
    _In_ int Family,
    _In_ int SendBytes,
    _In_ int ConsumeBytes,
    _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType,
    _In_ QUIC_RECEIVE_RESUME_TYPE PauseType,
    _In_ bool PauseFirst
    )
{
    uint32_t TimeoutMs = 2000;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    uint32_t SendSize = SendBytes;
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr;
    QuicBufferScope Buffer(SendSize);
    RecvResumeTestContext ServerContext(ServerConfiguration, true, ShutdownType, PauseType), ClientContext(nullptr, false, ShutdownType, PauseType);
    ServerContext.ConsumeBufferAmount = ConsumeBytes;

    {
        //
        // Start the server.
        //
        MsQuicListener Listener(Registration, CleanUpManual, QuicRecvResumeListenerHandler, &ServerContext);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        //
        // Start the client.
        //
        QUIC_STATUS Status =
            MsQuic->ConnectionOpen(
                Registration,
                QuicRecvResumeConnectionHandler,
                &ClientContext,
                &ClientContext.Conn.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                ClientContext.Conn.Handle,
                ClientConfiguration,
                QuicAddrFamily,
                QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (!CxPlatEventWaitWithTimeout(ClientContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Client failed to get connected before timeout!");
            return;
        }
        if (!CxPlatEventWaitWithTimeout(ServerContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get connected before timeout!");
            return;
        }

        QUIC_SETTINGS Settings{0};
        Settings.PeerUnidiStreamCount = 1;
        Settings.IsSet.PeerUnidiStreamCount = TRUE;
        Status =
            MsQuic->SetParam(
                ServerContext.Conn.Handle,
                QUIC_PARAM_CONN_SETTINGS,
                sizeof(Settings),
                &Settings);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_SETTINGS failed, 0x%x", Status);
            return;
        }

        Status =
            MsQuic->StreamOpen(
                ClientContext.Conn.Handle,
                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                QuicRecvResumeStreamHandler,
                &ClientContext,
                &ClientContext.Stream.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamOpen failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->StreamStart(
                ClientContext.Stream.Handle,
                QUIC_STREAM_START_FLAG_IMMEDIATE);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamStart failed, 0x%x.", Status);
            return;
        }

        if (!CxPlatEventWaitWithTimeout(ServerContext.StreamEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get stream before timeout!");
            return;
        }

        if (PauseFirst) {
            Status =
                MsQuic->StreamReceiveSetEnabled(
                    ServerContext.Stream.Handle,
                    FALSE);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("PauseFirst MsQuic->StreamReceiveSetEnabled(FALSE) failed, 0x%x", Status);
                return;
            }
        }

        Status =
            MsQuic->StreamSend(
                ClientContext.Stream.Handle,
                Buffer,
                1,
                QUIC_SEND_FLAG_NONE,
                nullptr); // send contxt
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamSend failed, 0x%x.", Status);
            return;
        }

        if (PauseFirst) {
            Status =
                MsQuic->StreamReceiveSetEnabled(
                    ServerContext.Stream.Handle,
                    TRUE);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("PauseFirst MsQuic->StreamReceiveSetEnabled(TRUE) failed, 0x%x", Status);
                return;
            }
        }

        //
        // Wait for send to be received/paused.
        //
        if (!CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get stream data/pause before timeout!");
            return;
        }

        //
        // Calculate next amount of buffer to consume, except for
        // STATUS_CONTINUE cases (because that always consumes all buffer).
        //
        if (PauseType != ReturnStatusContinue) {
            ServerContext.ConsumeBufferAmount = SendSize - ServerContext.ConsumeBufferAmount;
        }

        if (ShutdownType) {
            Status =
                MsQuic->StreamShutdown(
                    ClientContext.Stream.Handle,
                    (ShutdownType == GracefulShutdown) ?
                        QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL : QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                    ConsumeBytes + SendBytes);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->StreamShutdown failed, 0x%x", Status);
                return;
            }
        }

        if (PauseType == ReturnStatusPending) {
            if (ShutdownType == AbortShutdown) {
                //
                // Wait for the shutdown to be received to test if the buffer has been freed.
                //
                if (!CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
                    TEST_FAILURE("Server failed to get shutdown before timeout!");
                    return;
                }
                CxPlatSecureZeroMemory(ServerContext.PendingBuffer, SendSize);
            }
            //
            // Indicate the buffer has been consumed.
            //
            MsQuic->StreamReceiveComplete(
                ServerContext.Stream.Handle,
                SendBytes);
            ServerContext.AvailableBuffer = ServerContext.ConsumeBufferAmount;
        } else if (PauseType == ReturnConsumedBytes) {
            //
            // Resume receive callbacks.
            //
            Status =
                MsQuic->StreamReceiveSetEnabled(
                    ServerContext.Stream.Handle,
                    TRUE);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->StreamReceiveSetEnabled TRUE failed, 0x%x", Status);
                return;
            }

            if (!CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Server failed to resume receive before timeout!");
                return;
            }
        }

        //
        // Validate received amount is expected.
        //
        if (ServerContext.AvailableBuffer != ServerContext.ConsumeBufferAmount) {
            TEST_FAILURE("ServerContext.ConsumeBufferAmount was %u, expected %u",
                ServerContext.ConsumeBufferAmount,
                ServerContext.AvailableBuffer);
        }
        if (QUIC_STATUS_SUCCESS != ServerContext.TestResult) {
            TEST_FAILURE("ServerContext.TestResult was 0x%x, expected 0x%x",
                ServerContext.TestResult,
                QUIC_STATUS_SUCCESS);
        }
        TEST_TRUE(ServerContext.Passed);
    }
}

void
QuicTestReceiveResumeNoData(
    _In_ int Family,
    _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType
    )
{
    uint32_t TimeoutMs = 2000;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr;
    RecvResumeTestContext ServerContext(ServerConfiguration, true, ShutdownType, ReturnConsumedBytes), ClientContext(nullptr, false, ShutdownType, ReturnConsumedBytes);
    ServerContext.ShutdownOnly = true;

    {
        //
        // Start the server.
        //
        MsQuicListener Listener(Registration, CleanUpManual, QuicRecvResumeListenerHandler, &ServerContext);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        //
        // Start the client.
        //
        QUIC_STATUS Status =
            MsQuic->ConnectionOpen(
                Registration,
                QuicRecvResumeConnectionHandler,
                &ClientContext,
                &ClientContext.Conn.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                ClientContext.Conn.Handle,
                ClientConfiguration,
                QuicAddrFamily,
                QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (!CxPlatEventWaitWithTimeout(ClientContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Client failed to get connected before timeout!");
            return;
        }
        if (!CxPlatEventWaitWithTimeout(ServerContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get connected before timeout!");
            return;
        }

        QUIC_SETTINGS Settings{ 0 };
        Settings.PeerUnidiStreamCount = 1;
        Settings.IsSet.PeerUnidiStreamCount = TRUE;
        Status =
            MsQuic->SetParam(
                ServerContext.Conn.Handle,
                QUIC_PARAM_CONN_SETTINGS,
                sizeof(Settings),
                &Settings);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_SETTINGS failed, 0x%x", Status);
            return;
        }

        Status =
            MsQuic->StreamOpen(
                ClientContext.Conn.Handle,
                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                QuicRecvResumeStreamHandler,
                &ClientContext,
                &ClientContext.Stream.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamOpen failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->StreamStart(
                ClientContext.Stream.Handle,
                QUIC_STREAM_START_FLAG_IMMEDIATE);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamStart failed, 0x%x.", Status);
            return;
        }

        if (!CxPlatEventWaitWithTimeout(ServerContext.StreamEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get stream before timeout!");
            return;
        }

        Status =
            MsQuic->StreamReceiveSetEnabled(
                ServerContext.Stream.Handle,
                FALSE);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("PauseFirst MsQuic->StreamReceiveSetEnabled(FALSE) failed, 0x%x", Status);
            return;
        }

        Status =
            MsQuic->StreamShutdown(
                ClientContext.Stream.Handle,
                (ShutdownType == GracefulShutdown) ?
                    QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL : QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                QUIC_STATUS_SUCCESS);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamShutdown failed, 0x%x", Status);
            return;
        }

        if (ShutdownType == GracefulShutdown) {
            if (CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Server got shutdown event when it shouldn't have!");
                return;
            }
            Status =
                MsQuic->StreamReceiveSetEnabled(
                    ServerContext.Stream.Handle,
                    TRUE);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("PauseFirst MsQuic->StreamReceiveSetEnabled(TRUE) failed, 0x%x", Status);
                return;
            }
        }

        //
        // Validate the test was shutdown as expected.
        //
        if (!CxPlatEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get shutdown before timeout!");
            return;
        }
    }
}

struct AckSendDelayTestContext {
    AckSendDelayTestContext() :
        SendBuffer(1, 200)
    {};
    HQUIC ServerConfiguration;
    QuicSendBuffer SendBuffer;
    CxPlatEvent ServerStreamStartedEvent;
    CxPlatEvent ClientReceiveDataEvent;
    CxPlatEvent ServerConnectedEvent;
    ConnectionScope ServerConnection;
    ConnectionScope ClientConnection;
    StreamScope ServerStream;
    StreamScope ClientStream;
    uint64_t AckCountStart;
    uint64_t AckCountStop;
};

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicAckDelayStreamHandler(
    _In_ HQUIC QuicStream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    AckSendDelayTestContext* TestContext = (AckSendDelayTestContext*)Context;
    if (TestContext->ServerStream.Handle == QuicStream) {
        //
        // Server side
        //
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            Event->RECEIVE.TotalBufferLength = 0;
            Status = MsQuic->StreamSend(
                QuicStream,
                TestContext->SendBuffer.Buffers,
                TestContext->SendBuffer.BufferCount,
                QUIC_SEND_FLAG_FIN,
                nullptr);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("Server failed to send to send data back 0x%x", Status);
                return Status;
            }
            break;
        default:
            break;
        }
    } else {
        if (TestContext->ClientStream.Handle != QuicStream) {
            TEST_FAILURE("Client stream is wrong?! %p vs %p",
                TestContext->ClientStream.Handle,
                QuicStream);
            return QUIC_STATUS_INVALID_STATE;
        }
        //
        // Client side
        //
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE: {
            QUIC_STATISTICS_V2 Stats{};
            uint32_t StatsSize = sizeof(Stats);
            Status = MsQuic->GetParam(
                TestContext->ClientConnection.Handle,
                QUIC_PARAM_CONN_STATISTICS_V2,
                &StatsSize,
                &Stats);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("Client failed to query statistics on receive 0x%x", Status);
                return Status;
            }
            TestContext->AckCountStop = Stats.RecvValidAckFrames;
            Event->RECEIVE.TotalBufferLength = 0;
            CxPlatEventSet(TestContext->ClientReceiveDataEvent.Handle);
            break;
        }
        default:
            break;
        }
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicAckDelayConnectionHandler(
    _In_ HQUIC QuicConnection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    AckSendDelayTestContext* TestContext = (AckSendDelayTestContext*)Context;
    if (TestContext->ServerConnection == QuicConnection) {
        //
        // Server side
        //
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            CxPlatEventSet(TestContext->ServerConnectedEvent.Handle);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            MsQuic->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream,
                (void*)QuicAckDelayStreamHandler,
                Context);
            TestContext->ServerStream.Handle = Event->PEER_STREAM_STARTED.Stream;
            CxPlatEventSet(TestContext->ServerStreamStartedEvent.Handle);
            break;
        default:
            break;
        }
    } else {
        if(TestContext->ClientConnection.Handle != QuicConnection) {
            TEST_FAILURE("Client connection is wrong?! %p vs %p",
                TestContext->ClientConnection.Handle,
                QuicConnection);
            return QUIC_STATUS_INVALID_STATE;
        }
        //
        // Client side
        //
        switch(Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            // CxPlatEventSet(TestContext->ServerConnectedEvent.Handle);
            break;
        default:
            break;
        }
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
static
QUIC_STATUS
QUIC_API
QuicAckDelayListenerHandler(
    _In_ MsQuicListener* /* QuicListener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    AckSendDelayTestContext* TestContext = (AckSendDelayTestContext*)Context;
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            TestContext->ServerConnection.Handle = Event->NEW_CONNECTION.Connection;
            MsQuic->SetCallbackHandler(TestContext->ServerConnection.Handle, (void*) QuicAckDelayConnectionHandler, Context);
            return MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, TestContext->ServerConfiguration);
        case QUIC_LISTENER_EVENT_STOP_COMPLETE:
            return QUIC_STATUS_SUCCESS;
        default:
            TEST_FAILURE(
                "Invalid listener event! Context: 0x%p, Event: %d",
                Context,
                Event->Type);
            return QUIC_STATUS_INVALID_STATE;
    }
}

void
QuicTestAckSendDelay(
    _In_ int Family
    )
{
    const uint32_t TimeoutMs = 3000;
    const uint32_t AckDelayMs = 1000;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings{};
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);
    Settings.SetIdleTimeoutMs(TimeoutMs);
    Settings.SetMaxAckDelayMs(AckDelayMs);
    Settings.SetPeerBidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr;

    {
        AckSendDelayTestContext TestContext {};

        TestContext.ServerConfiguration = ServerConfiguration;
        //
        // Start the server.
        //
        MsQuicListener Listener(Registration, CleanUpManual, QuicAckDelayListenerHandler, &TestContext);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        //
        // Start the client.
        //
        QUIC_STATUS Status =
            MsQuic->ConnectionOpen(
                Registration,
                QuicAckDelayConnectionHandler,
                &TestContext,
                &TestContext.ClientConnection.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                TestContext.ClientConnection.Handle,
                ClientConfiguration,
                QuicAddrFamily,
                QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (!CxPlatEventWaitWithTimeout(TestContext.ServerConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get connected before timeout!");
            return;
        }

        //
        // Wait for connection to go silent before continuing
        //
        CxPlatSleep(100);

        QUIC_STATISTICS_V2 Stats{};
        uint32_t StatsSize = sizeof(Stats);
        Status =
            MsQuic->GetParam(
                TestContext.ClientConnection.Handle,
                QUIC_PARAM_CONN_STATISTICS_V2,
                &StatsSize,
                &Stats);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Client failed to query statistics at start 0x%x", Status);
            return;
        }
        TestContext.AckCountStart = Stats.RecvValidAckFrames;
        Status =
            MsQuic->StreamOpen(
                TestContext.ClientConnection.Handle,
                QUIC_STREAM_OPEN_FLAG_NONE,
                QuicAckDelayStreamHandler,
                &TestContext,
                &TestContext.ClientStream.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Client failed to open stream 0x%x", Status);
            return;
        }
        Status =
            MsQuic->StreamSend(
                TestContext.ClientStream.Handle,
                TestContext.SendBuffer.Buffers,
                TestContext.SendBuffer.BufferCount,
                QUIC_SEND_FLAG_START,
                nullptr);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Client failed to send data 0x%x", Status);
        }

        if (!CxPlatEventWaitWithTimeout(TestContext.ClientReceiveDataEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Client failed to receive data before timeout!");
            return;
        }

        TEST_EQUAL(TestContext.AckCountStop - TestContext.AckCountStart, 1);
    }
}

struct AbortRecvTestContext {
    QUIC_ABORT_RECEIVE_TYPE Type;
    CxPlatEvent ServerStreamRecv;
    CxPlatEvent ServerStreamShutdown;
    MsQuicStream* ServerStream {nullptr};
};

QUIC_STATUS
AbortRecvStreamCallback(
    _In_ MsQuicStream* Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto TestContext = (AbortRecvTestContext*)Context;
    if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
        TestContext->ServerStreamRecv.Set();
        if (TestContext->Type == QUIC_ABORT_RECEIVE_PAUSED) {
            Event->RECEIVE.TotalBufferLength = 0;
        } else if (TestContext->Type == QUIC_ABORT_RECEIVE_PENDING) {
            return QUIC_STATUS_PENDING;
        }
    } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
        TestContext->ServerStreamShutdown.Set();
        Stream->ConnectionShutdown(1);
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
AbortRecvConnCallback(
    _In_ MsQuicConnection* /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto TestContext = (AbortRecvTestContext*)Context;
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        TestContext->ServerStream = new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, AbortRecvStreamCallback, Context);
        if (TestContext->Type == QUIC_ABORT_RECEIVE_INCOMPLETE) {
            TestContext->ServerStreamRecv.Set();
        }
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestAbortReceive(
    _In_ QUIC_ABORT_RECEIVE_TYPE Type
    )
{
    MsQuicRegistration Registration;
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    AbortRecvTestContext RecvContext { Type };
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, AbortRecvConnCallback, &RecvContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

    MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());

    uint8_t RawBuffer[100];
    QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
    if (Type == QUIC_ABORT_RECEIVE_INCOMPLETE) {
        TEST_QUIC_SUCCEEDED(Stream.Start(QUIC_STREAM_START_FLAG_IMMEDIATE));
    } else {
        TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));
    }

    TEST_TRUE(RecvContext.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
    TEST_QUIC_SUCCEEDED(RecvContext.ServerStream->Shutdown(1));
    TEST_TRUE(RecvContext.ServerStreamShutdown.WaitTimeout(TestWaitTimeout));
}

struct EcnTestContext {
    CxPlatEvent ServerStreamRecv;
    CxPlatEvent ServerStreamShutdown;
    MsQuicStream* ServerStream {nullptr};
    bool ServerStreamHasShutdown {false};

    static QUIC_STATUS StreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (EcnTestContext*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            TestContext->ServerStreamRecv.Set();
        } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ServerStreamHasShutdown = true;
            TestContext->ServerStreamShutdown.Set();
            Stream->ConnectionShutdown(1);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto TestContext = (EcnTestContext*)Context;
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            TestContext->ServerStream = new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestEcn(
    _In_ int Family
    )
{
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    //
    // Postive ECN test.
    //
    {
        TestScopeLogger logScope("Postive ECN test");
        MsQuicRegistration Registration;
        TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

        MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1), ServerSelfSignedCredConfig);
        TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

        MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetEcnEnabled(true), MsQuicCredentialConfig());
        TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

        EcnTestContext Context;
        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, EcnTestContext::ConnCallback, &Context);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, QuicAddrFamily, QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily), ServerLocalAddr.GetPort()));

        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());

        //
        // Open a stream, send some data and a FIN.
        //
        uint8_t RawBuffer[100];
        QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
        TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

        TEST_TRUE(Context.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
        CxPlatSleep(50);

        TEST_TRUE(Context.ServerStreamShutdown.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(Context.ServerStreamHasShutdown);

        QUIC_STATISTICS_V2 Stats;
        Connection.GetStatistics(&Stats);
        TEST_TRUE(Stats.EcnCapable);
    }

    //
    // Negative ECN test: network erasing ECT bit or incorrectly modifying ECT bit.
    //
    TestScopeLogger logScope1("network erasing ECT bit or incorrectly modifying ECT bit");
    for (int EcnType = CXPLAT_ECN_NON_ECT; EcnType <= CXPLAT_ECN_ECT_1; ++EcnType) {
        EcnModifyHelper EctEraser;
        MsQuicRegistration Registration;
        TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

        MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1), ServerSelfSignedCredConfig);
        TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

        MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetEcnEnabled(true), MsQuicCredentialConfig());
        TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

        EcnTestContext Context;
        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, EcnTestContext::ConnCallback, &Context);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        EctEraser.SetEcnType((CXPLAT_ECN_TYPE)EcnType);
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, QuicAddrFamily, QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily), ServerLocalAddr.GetPort()));

        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());

        //
        // Open a stream, send some data and a FIN.
        //
        uint8_t RawBuffer[100];
        QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
        TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

        TEST_TRUE(Context.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
        CxPlatSleep(50);
        TEST_TRUE(Context.ServerStreamShutdown.WaitTimeout(TestWaitTimeout));

        QUIC_STATISTICS_V2 Stats;
        Connection.GetStatistics(&Stats);
        TEST_FALSE(Stats.EcnCapable);
    }

    //
    // Negative ECN test: network erasing ECT bit or incorrectly modifying ECT bit after successful ECN validation.
    //
    TestScopeLogger logScope2("network erasing ECT bit or incorrectly modifying ECT bit successful ECN validation");
    for (int EcnType = CXPLAT_ECN_NON_ECT; EcnType <= CXPLAT_ECN_ECT_1; ++EcnType) {
        MsQuicRegistration Registration;
        TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

        MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1), ServerSelfSignedCredConfig);
        TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

        MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetEcnEnabled(true), MsQuicCredentialConfig());
        TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

        EcnTestContext Context;
        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, EcnTestContext::ConnCallback, &Context);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, QuicAddrFamily, QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily), ServerLocalAddr.GetPort()));

        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());

        //
        // Open a stream, send some data.
        //
        uint8_t RawBuffer[100];
        QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
        TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START));
        TEST_TRUE(Context.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
        CxPlatSleep(50);
        QUIC_STATISTICS_V2 Stats;
        Connection.GetStatistics(&Stats);
        TEST_TRUE(Stats.EcnCapable);

        //
        // Send some more data.
        //
        EcnModifyHelper EctEraser;
        EctEraser.SetEcnType((CXPLAT_ECN_TYPE)EcnType);
        QUIC_BUFFER AnotherBuffer { sizeof(RawBuffer), RawBuffer };
        TEST_QUIC_SUCCEEDED(Stream.Send(&AnotherBuffer, 1, QUIC_SEND_FLAG_FIN));
        TEST_TRUE(Context.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
        CxPlatSleep(50);
        TEST_TRUE(Context.ServerStreamShutdown.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(Context.ServerStreamHasShutdown);
        Connection.GetStatistics(&Stats);
        TEST_FALSE(Stats.EcnCapable);
    }
}

struct SlowRecvTestContext {
    CxPlatEvent ServerStreamRecv;
    CxPlatEvent ServerStreamShutdown;
    MsQuicStream* ServerStream {nullptr};
    bool ServerStreamHasShutdown {false};

    static QUIC_STATUS StreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (SlowRecvTestContext*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            TestContext->ServerStreamRecv.Set();
            return QUIC_STATUS_PENDING;
        } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ServerStreamHasShutdown = true;
            TestContext->ServerStreamShutdown.Set();
            Stream->ConnectionShutdown(1);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto TestContext = (SlowRecvTestContext*)Context;
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            TestContext->ServerStream = new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestSlowReceive(
    void
    )
{
    MsQuicRegistration Registration;
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    SlowRecvTestContext Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, SlowRecvTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

    MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());

    //
    // Open a stream, send some data and a FIN.
    //
    uint8_t RawBuffer[100];
    QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
    TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    //
    // Wait for the first received data on the server side. The handler always
    // returns pending, so make sure that pending is respected (no shutdown).
    //
    TEST_TRUE(Context.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
    CxPlatSleep(50);
    TEST_FALSE(Context.ServerStreamHasShutdown);

    //
    // Complete the receive and drain only the first half of the data, and then
    // repeat the steps above to make sure we get another receive and it doesn't
    // shutdown the stream.
    //
    Context.ServerStream->ReceiveComplete(50);
    TEST_QUIC_SUCCEEDED(Context.ServerStream->ReceiveSetEnabled()); // Need to reenable because the partial receive completion pauses additional events.
    TEST_TRUE(Context.ServerStreamRecv.WaitTimeout(TestWaitTimeout));
    CxPlatSleep(50);
    TEST_FALSE(Context.ServerStreamHasShutdown);

    //
    // Receive the rest of the data and make sure the shutdown is then delivered.
    //
    Context.ServerStream->ReceiveComplete(50);
    TEST_TRUE(Context.ServerStreamShutdown.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ServerStreamHasShutdown);
}

struct NthAllocFailTestContext {
    CxPlatEvent ServerStreamRecv;
    CxPlatEvent ServerStreamShutdown;
    MsQuicStream* ServerStream {nullptr};
    bool ServerStreamHasShutdown {false};

    static QUIC_STATUS StreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (NthAllocFailTestContext*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            TestContext->ServerStreamRecv.Set();
        } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ServerStreamHasShutdown = true;
            TestContext->ServerStreamShutdown.Set();
            Stream->ConnectionShutdown(1);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto TestContext = (NthAllocFailTestContext*)Context;
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            TestContext->ServerStream = new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct AllocFailScope {
    ~AllocFailScope() {
        int32_t Zero = 0;
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE,
            sizeof(Zero),
            &Zero);
    }
};

#define CONTINUE_ON_FAIL(__condition) { \
    QUIC_STATUS __status = __condition; \
    if (QUIC_FAILED(__status)) { \
        continue; \
    } \
}

void
QuicTestNthAllocFail(
    )
{
    AllocFailScope Scope{};

    for (uint32_t i = 100; i > 1; i--) {
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE,
                sizeof(i),
                &i));

        CxPlatWatchdog Watchdog(2000);

        MsQuicRegistration Registration(true);
        CONTINUE_ON_FAIL(Registration.GetInitStatus());

        MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1), ServerSelfSignedCredConfig);
        CONTINUE_ON_FAIL(ServerConfiguration.GetInitStatus());

        MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
        CONTINUE_ON_FAIL(ClientConfiguration.GetInitStatus());

        NthAllocFailTestContext RecvContext {};
        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, NthAllocFailTestContext::ConnCallback, &RecvContext);
        CONTINUE_ON_FAIL(Listener.GetInitStatus());
        CONTINUE_ON_FAIL(Listener.Start("MsQuicTest"));
        QuicAddr ServerLocalAddr;
        CONTINUE_ON_FAIL(Listener.GetLocalAddr(ServerLocalAddr));

        MsQuicConnection Connection(Registration);
        CONTINUE_ON_FAIL(Connection.GetInitStatus());
        CONTINUE_ON_FAIL(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
        CONTINUE_ON_FAIL(Stream.GetInitStatus());

        uint8_t RawBuffer[100];
        QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
        CONTINUE_ON_FAIL(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

        RecvContext.ServerStreamRecv.WaitTimeout(10);
        RecvContext.ServerStreamShutdown.WaitTimeout(10);
    }
}

struct StreamPriorityTestContext {
    QUIC_UINT62 ReceiveEvents[3];
    uint32_t CurrentReceiveCount {0};
    CxPlatEvent AllReceivesComplete;

    static QUIC_STATUS StreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamPriorityTestContext*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            if (TestContext->CurrentReceiveCount >= ARRAYSIZE(ReceiveEvents)) {
                TEST_FAILURE("Too many receive events!");
            } else {
                Stream->GetID(&TestContext->ReceiveEvents[TestContext->CurrentReceiveCount++]);
                if (TestContext->CurrentReceiveCount == ARRAYSIZE(ReceiveEvents)) {
                    TestContext->AllReceivesComplete.Set();
                }
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestStreamPriority(
    )
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(3), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamPriorityTestContext Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamPriorityTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    uint8_t RawBuffer[100];
    QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };

    MsQuicStream Stream1(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream1.SetPriority(0xFFFF));
    TEST_QUIC_SUCCEEDED(Stream1.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    MsQuicStream Stream2(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream2.SetPriority(0xFFFF));
    TEST_QUIC_SUCCEEDED(Stream2.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    MsQuicStream Stream3(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream3.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream3.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    TEST_QUIC_SUCCEEDED(Stream1.SetPriority(0)); // Change to lowest priority

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    TEST_TRUE(Context.AllReceivesComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ReceiveEvents[0] == Stream2.ID());
    TEST_TRUE(Context.ReceiveEvents[1] == Stream3.ID());
    TEST_TRUE(Context.ReceiveEvents[2] == Stream1.ID());
}

void
QuicTestStreamPriorityInfiniteLoop(
    )
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(3), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamPriorityTestContext Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamPriorityTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    uint8_t RawBuffer[100];
    QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };

    QUIC_STREAM_SCHEDULING_SCHEME Value = QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN;
    Connection.SetParam(QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME, sizeof(Value), &Value);

    MsQuicStream Stream1(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream1.SetPriority(0));
    TEST_QUIC_SUCCEEDED(Stream1.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    MsQuicStream Stream2(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream2.SetPriority(0));
    TEST_QUIC_SUCCEEDED(Stream2.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    MsQuicStream Stream3(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream3.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream3.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    QUIC_STATISTICS_V2 Stats;
    Connection.GetStatistics(&Stats);

    TEST_TRUE(Context.AllReceivesComplete.WaitTimeout(TestWaitTimeout));
}

struct StreamDifferentAbortErrors {
    QUIC_UINT62 PeerSendAbortErrorCode {0};
    QUIC_UINT62 PeerRecvAbortErrorCode {0};
    BOOLEAN ConnectionShutdown {FALSE};
    BOOLEAN ConnectionShutdownByApp {FALSE};
    BOOLEAN ConnectionClosedRemotely {FALSE};
    QUIC_UINT62 ConnectionErrorCode {0};
    QUIC_STATUS ConnectionCloseStatus {0};

    CxPlatEvent StreamShutdownComplete;

    static QUIC_STATUS StreamCallback(_In_ MsQuicStream*, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamDifferentAbortErrors*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED) {
            TestContext->PeerRecvAbortErrorCode = Event->PEER_RECEIVE_ABORTED.ErrorCode;
        } else if (Event->Type == QUIC_STREAM_EVENT_PEER_SEND_ABORTED) {
            TestContext->PeerSendAbortErrorCode = Event->PEER_SEND_ABORTED.ErrorCode;
        } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ConnectionShutdown = Event->SHUTDOWN_COMPLETE.ConnectionShutdown;
            TestContext->ConnectionShutdownByApp = Event->SHUTDOWN_COMPLETE.ConnectionShutdownByApp;
            TestContext->ConnectionClosedRemotely = Event->SHUTDOWN_COMPLETE.ConnectionClosedRemotely;
            TestContext->ConnectionErrorCode = Event->SHUTDOWN_COMPLETE.ConnectionErrorCode;
            TestContext->ConnectionCloseStatus = Event->SHUTDOWN_COMPLETE.ConnectionCloseStatus;
            TestContext->StreamShutdownComplete.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestStreamDifferentAbortErrors(
    )
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerBidiStreamCount(1), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamDifferentAbortErrors Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamDifferentAbortErrors::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    const QUIC_UINT62 RecvShutdownErrorCode = 0x1234567890;
    const QUIC_UINT62 SendShutdownErrorCode = 0x9876543210;

    MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
    TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream.Start());
    TEST_QUIC_SUCCEEDED(Stream.Shutdown(RecvShutdownErrorCode, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE));
    TEST_QUIC_SUCCEEDED(Stream.Shutdown(SendShutdownErrorCode, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    TEST_TRUE(Context.StreamShutdownComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.PeerRecvAbortErrorCode == RecvShutdownErrorCode);
    TEST_TRUE(Context.PeerSendAbortErrorCode == SendShutdownErrorCode);
    TEST_FALSE(Context.ConnectionShutdown);
    TEST_FALSE(Context.ConnectionShutdownByApp);
    TEST_FALSE(Context.ConnectionClosedRemotely);
    TEST_EQUAL(0, Context.ConnectionErrorCode);
    TEST_EQUAL(0, Context.ConnectionCloseStatus);
}

struct StreamAbortRecvFinRace {
    CxPlatEvent ClientStreamShutdownComplete;

    static QUIC_STATUS ClientStreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamAbortRecvFinRace*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE) {
            Stream->Shutdown(0, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE | QUIC_STREAM_SHUTDOWN_FLAG_INLINE);
        } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ClientStreamShutdownComplete.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ServerStreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void*, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->Type == QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN) {
            Stream->Shutdown(0, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL | QUIC_STREAM_SHUTDOWN_FLAG_INLINE);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, ServerStreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestStreamAbortRecvFinRace(
    )
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerBidiStreamCount(1), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamAbortRecvFinRace Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamAbortRecvFinRace::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE, CleanUpManual, StreamAbortRecvFinRace::ClientStreamCallback, &Context);
    TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream.Start());
    TEST_QUIC_SUCCEEDED(Stream.Shutdown(0, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    TEST_TRUE(Context.ClientStreamShutdownComplete.WaitTimeout(TestWaitTimeout));
}

struct StreamAbortConnFlowControl {
    CxPlatEvent ClientStreamShutdownComplete;
    uint32_t StreamCount {0};

    static QUIC_STATUS ClientStreamCallback(_In_ MsQuicStream*, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamAbortConnFlowControl*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ClientStreamShutdownComplete.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ServerStreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void*, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            Event->RECEIVE.TotalBufferLength = 0;
            Stream->Shutdown(0, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto TestContext = (StreamAbortConnFlowControl*)Context;
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, TestContext->StreamCount++ == 0 ? ServerStreamCallback : MsQuicStream::NoOpCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestStreamAbortConnFlowControl(
    )
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetPeerUnidiStreamCount(1).SetConnFlowControlWindow(100), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamAbortConnFlowControl Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamAbortConnFlowControl::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    uint8_t RawBuffer[100];
    QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };

    MsQuicStream Stream1(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    TEST_QUIC_SUCCEEDED(Stream1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream1.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    MsQuicStream Stream2(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, CleanUpManual, StreamAbortConnFlowControl::ClientStreamCallback, &Context);
    TEST_QUIC_SUCCEEDED(Stream2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream2.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    TEST_TRUE(Context.ClientStreamShutdownComplete.WaitTimeout(TestWaitTimeout));
}

struct StreamBlockUnblockConnFlowControl {
    CxPlatEvent ClientStreamShutdownComplete;
    CxPlatEvent ClientStreamSendComplete;
    CxPlatEvent ServerStreamReceive;
    CxPlatEvent ServerConnectionPeerNeedsStreams;
    uint16_t NeedsStreamCount {0};

    static QUIC_STATUS ClientStreamCallback(_In_ MsQuicStream*, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamBlockUnblockConnFlowControl*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE && !Event->SEND_COMPLETE.Canceled) {
            TestContext->ClientStreamSendComplete.Set();
        } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ClientStreamShutdownComplete.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ServerStreamCallback(_In_ MsQuicStream* Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamBlockUnblockConnFlowControl*)Context;
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            TestContext->ServerStreamReceive.Set();
        } else if (Event->Type == QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN) {
            Stream->Shutdown(0, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ServerConnCallback(_In_ MsQuicConnection* Connection, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto TestContext = (StreamBlockUnblockConnFlowControl*)Context;

        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, ServerStreamCallback, Context);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS) {
            TestContext->NeedsStreamCount += 1;
            TestContext->ServerConnectionPeerNeedsStreams.Set();
            if (Event->PEER_NEEDS_STREAMS.Bidirectional) {
                Connection->SetSettings(MsQuicSettings{}.SetPeerBidiStreamCount(TestContext->NeedsStreamCount));
            } else {
                Connection->SetSettings(MsQuicSettings{}.SetPeerUnidiStreamCount(TestContext->NeedsStreamCount));
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

};

void
QuicTestStreamBlockUnblockConnFlowControl(
    _In_ BOOLEAN Bidirectional
    )
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    // Server flow control: UnidirectionalStream : 0, BidirectionalStream : 0
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetConnFlowControlWindow(200), ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamBlockUnblockConnFlowControl Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamBlockUnblockConnFlowControl::ServerConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    uint8_t RawBuffer[100];
    QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };

    QUIC_STREAM_OPEN_FLAGS StreamOpenFlags = Bidirectional ? QUIC_STREAM_OPEN_FLAG_NONE : QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;

    MsQuicStream Stream1(Connection, StreamOpenFlags, CleanUpManual, StreamBlockUnblockConnFlowControl::ClientStreamCallback, &Context);
    TEST_QUIC_SUCCEEDED(Stream1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream1.Send(&Buffer, 1, QUIC_SEND_FLAG_START));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    // Server should indicate PeerNeedStreams for Stream1
    TEST_TRUE(Context.ServerConnectionPeerNeedsStreams.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ClientStreamSendComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ServerStreamReceive.WaitTimeout(TestWaitTimeout));
    Context.ClientStreamSendComplete.Reset();
    Context.ServerStreamReceive.Reset();
    Context.ServerConnectionPeerNeedsStreams.Reset();
    TEST_TRUE(Context.NeedsStreamCount == 1);

    MsQuicStream Stream2(Connection, StreamOpenFlags, CleanUpManual, StreamBlockUnblockConnFlowControl::ClientStreamCallback, &Context);
    TEST_QUIC_SUCCEEDED(Stream2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream2.Send(&Buffer, 1, QUIC_SEND_FLAG_START));
    // Server should indicate PeerNeedStreams for Stream2
    TEST_TRUE(Context.ServerConnectionPeerNeedsStreams.WaitTimeout(TestWaitTimeout));
    // 2nd Stream
    TEST_TRUE(Context.ClientStreamSendComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ServerStreamReceive.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.NeedsStreamCount == 2);

    // Shutdown 1st Stream
    Stream1.Shutdown(0, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL);
    TEST_TRUE(Context.ClientStreamShutdownComplete.WaitTimeout(1000));

    Context.ClientStreamSendComplete.Reset();
    Context.ServerStreamReceive.Reset();
    Context.ServerConnectionPeerNeedsStreams.Reset();
    TEST_FALSE(Context.ServerConnectionPeerNeedsStreams.WaitTimeout(TestWaitTimeout));

    // 3rd Stream
    MsQuicStream Stream3(Connection, StreamOpenFlags, CleanUpManual, StreamBlockUnblockConnFlowControl::ClientStreamCallback, &Context);
    TEST_QUIC_SUCCEEDED(Stream3.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream3.Send(&Buffer, 1, QUIC_SEND_FLAG_START));
    // Server should not indicate PeerNeedStreams
    TEST_FALSE(Context.ServerConnectionPeerNeedsStreams.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ClientStreamSendComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ServerStreamReceive.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.NeedsStreamCount == 2);
}

void
QuicTestConnectAndIdleForDestCidChange(
    void
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(9000);
    Settings.SetDestCidUpdateIdleTimeoutMs(2000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerAcceptConnectionAndStreams, ServerConfiguration);
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

                TEST_QUIC_SUCCEEDED(Client.SetShareUdpBinding(true));

                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
                        QUIC_ADDRESS_FAMILY_UNSPEC,
                        QUIC_TEST_LOOPBACK_FOR_AF(
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

                {
                    TestStream* Stream = Client.NewStream(+[](TestStream*){},
                                                            QUIC_STREAM_OPEN_FLAG_NONE,
                                                            NEW_STREAM_START_SYNC);
                    Stream->Context = Client.Context;

                    TEST_TRUE(Stream->IsValid());
                    TEST_TRUE(Stream->StartPing(1)); // Send Fin

                    delete Stream;

                    auto DestCidUpdateCount = Client.GetDestCidUpdateCount();

                    CxPlatSleep(6000); // Wait for the first idle period to send another ping to the stream.

                    Stream = Client.NewStream(+[](TestStream*){},
                                                            QUIC_STREAM_OPEN_FLAG_NONE,
                                                            NEW_STREAM_START_SYNC);

                    // Send Fin
                    TEST_TRUE(Stream->IsValid());
                    TEST_TRUE(Stream->StartPing(1));

                    delete Stream;

                    TEST_TRUE(Client.GetDestCidUpdateCount() >= DestCidUpdateCount + 1);
                }

                Client.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
                Server->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, QUIC_TEST_NO_ERROR);
            }
        }
    }
}

#define BUFFER_SIZE 30000
#define RELIABLE_SIZE 5000
#define BUFFER_SIZE_MULTI_SENDS 10000
#define RELIABLE_SIZE_MULTI_SENDS 20000
//
// These Context Structs are useful helpers for the StreamReliableReset test suite.
// It keeps track of the order of absolute offsets of all the send requests received, and the total number of bytes received.
// If everything works, SendCompleteOrder MUST be monotonically increasing.
//
struct SendContext {
    BOOLEAN Successful;
    uint64_t SeqNum;
};
struct StreamReliableReset {

    CxPlatEvent ClientStreamShutdownComplete;
    CxPlatEvent ServerStreamShutdownComplete;
    uint64_t ReceivedBufferSize;
    uint64_t SequenceNum;
    QUIC_UINT62 ShutdownErrorCode;
    static QUIC_STATUS ClientStreamCallback(_In_ MsQuicStream*, _In_opt_ void* ClientContext, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamReliableReset*)ClientContext;
        if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ClientStreamShutdownComplete.Set();
        }
        // Get the send context of the Event
        if (Event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE) {
            auto Context = (SendContext*)Event->SEND_COMPLETE.ClientContext;
            Context->Successful = Event->SEND_COMPLETE.Canceled == FALSE;
            Context->SeqNum = TestContext->SequenceNum++;
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ServerStreamCallback(_In_ MsQuicStream*, _In_opt_ void* ServerContext, _Inout_ QUIC_STREAM_EVENT* Event) {
        auto TestContext = (StreamReliableReset*)ServerContext;
        if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
            TestContext->ReceivedBufferSize += Event->RECEIVE.TotalBufferLength;
        }
        if (Event->Type == QUIC_STREAM_EVENT_PEER_SEND_ABORTED) {
            TestContext->ShutdownErrorCode = Event->PEER_SEND_ABORTED.ErrorCode;
        }
        if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
            TestContext->ServerStreamShutdownComplete.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, ServerStreamCallback, Context);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
void
QuicTestStreamReliableReset(
    )
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings TestSettings;
    TestSettings.SetReliableResetEnabled(true);
    TestSettings.SetPeerBidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", TestSettings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", TestSettings, MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamReliableReset Context;
    UniquePtrArray<uint8_t> SendDataBuffer = UniquePtrArray<uint8_t>(new(std::nothrow) uint8_t[BUFFER_SIZE]);

    QUIC_BUFFER SendBuffer { BUFFER_SIZE, SendDataBuffer.get() };
    Context.ReceivedBufferSize = 0;

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamReliableReset::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);
    TEST_TRUE(Listener.LastConnection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Listener.LastConnection->HandshakeComplete);
    CxPlatSleep(50); // Wait for things to idle out

#if DEBUG
    for (uint64_t Bitmap = 0; Bitmap < 8; ++Bitmap) {
        char Name[64]; sprintf_s(Name, sizeof(Name), "Try Reliably Shutting Down Stream %llu", (unsigned long long)Bitmap);
        TestScopeLogger logScope(Name);
        BitmapLossHelper LossHelper(Bitmap);
#else
    {
#endif
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE, CleanUpManual, StreamReliableReset::ClientStreamCallback, &Context);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Stream.Start());
        SendContext send1 = {FALSE, 0};
        TEST_QUIC_SUCCEEDED(Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_DELAY_SEND, &send1));
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Stream.SetReliableOffset(UINT64_MAX));
        TEST_QUIC_SUCCEEDED(Stream.SetReliableOffset(RELIABLE_SIZE));
        const QUIC_UINT62 AbortSendShutdownErrorCode = 0x696969696969;
        const QUIC_UINT62 AbortRecvShutdownErrorCode = 0x420420420420;
        TEST_QUIC_SUCCEEDED(Stream.Shutdown(AbortSendShutdownErrorCode, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND)); // Queues up a shutdown operation.
        TEST_QUIC_SUCCEEDED(Stream.Shutdown(AbortRecvShutdownErrorCode, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE));
        TEST_QUIC_STATUS(QUIC_STATUS_INVALID_STATE, Stream.SetReliableOffset(RELIABLE_SIZE));
        // Should behave similar to QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, with some restrictions.
        TEST_TRUE(Context.ClientStreamShutdownComplete.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(Context.ServerStreamShutdownComplete.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(Context.ReceivedBufferSize >= RELIABLE_SIZE);

        // We shouldn't be able to change ReliableSize now that the stream has already been reset.
        TEST_QUIC_STATUS(QUIC_STATUS_INVALID_STATE, Stream.SetReliableOffset(1));

        // Test that the error code we got was for the SEND shutdown.
        TEST_TRUE(Context.ShutdownErrorCode == AbortSendShutdownErrorCode);
    }
}

void
QuicTestStreamReliableResetMultipleSends(
    )
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings TestSettings;
    TestSettings.SetReliableResetEnabled(true);
    TestSettings.SetPeerBidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", TestSettings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", TestSettings, MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    StreamReliableReset Context;
    UniquePtrArray<uint8_t> SendDataBuffer = UniquePtrArray<uint8_t>(new(std::nothrow) uint8_t[BUFFER_SIZE_MULTI_SENDS]);

    QUIC_BUFFER SendBuffer { BUFFER_SIZE_MULTI_SENDS, SendDataBuffer.get() };
    Context.ReceivedBufferSize = 0;
    Context.SequenceNum = 0;
    Context.ShutdownErrorCode = 0;

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, StreamReliableReset::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);
    TEST_TRUE(Listener.LastConnection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Listener.LastConnection->HandshakeComplete);
    CxPlatSleep(50); // Wait for things to idle out

    MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE, CleanUpManual, StreamReliableReset::ClientStreamCallback, &Context);
    TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Stream.Start());
    SendContext send1 = {FALSE, 0};
    SendContext send2 = {FALSE, 0};
    SendContext send3 = {FALSE, 0};
    SendContext send4 = {FALSE, 0};
    SendContext send5 = {FALSE, 0};
    SendContext send6 = {FALSE, 0};
    TEST_QUIC_SUCCEEDED(Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_DELAY_SEND, &send1));
    TEST_QUIC_SUCCEEDED(Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_DELAY_SEND, &send2));
    TEST_QUIC_SUCCEEDED(Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_DELAY_SEND, &send3));
    TEST_QUIC_SUCCEEDED(Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_DELAY_SEND, &send4));
    TEST_QUIC_SUCCEEDED(Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_DELAY_SEND, &send5));
    TEST_QUIC_SUCCEEDED(Stream.SetReliableOffset(RELIABLE_SIZE_MULTI_SENDS));

    const QUIC_UINT62 AbortShutdownErrorCode = 0x696969696969;
    TEST_QUIC_SUCCEEDED(Stream.Shutdown(AbortShutdownErrorCode));

    //
    // An app shouldn't be sending after it just called shutdown, but we want to make sure this
    // doesn't cause a memory leak or other problems.
    //
    Stream.Send(&SendBuffer, 1, QUIC_SEND_FLAG_NONE, &send6); // This may or may not succeed (race condition).


    TEST_TRUE(Context.ClientStreamShutdownComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ServerStreamShutdownComplete.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.ReceivedBufferSize >= RELIABLE_SIZE_MULTI_SENDS);

    // Test order of completion, and that our first 2 sends MUST be successful.
    TEST_TRUE(send1.Successful);
    TEST_TRUE(send2.Successful);
    TEST_TRUE(send1.SeqNum < send2.SeqNum);
    TEST_TRUE(send2.SeqNum < send3.SeqNum);
    TEST_TRUE(send3.SeqNum < send4.SeqNum);
    TEST_TRUE(send4.SeqNum < send5.SeqNum);

    // Test Error code matches what we sent.
    TEST_TRUE(Context.ShutdownErrorCode == AbortShutdownErrorCode);
}
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET
