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

    QUIC_EVENT CompletionEvent;

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
        ExpectedCloseStatus(_ExpectedCloseStatus),
        ServerKeyUpdate(_ServerKeyUpdate),
        ConnectionsComplete(0)
    {
        QuicEventInitialize(&CompletionEvent, FALSE, FALSE);
    }

    ~PingStats() {
        QuicEventUninitialize(CompletionEvent);
        QuicZeroMemory(&CompletionEvent, sizeof(CompletionEvent));
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
                QuicEventSet(Stats->CompletionEvent);
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
        TEST_FAILURE("Send path not shutdown.");
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
                    QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE);
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
    if (ConnState->GetPingStats()->ExpectedCloseStatus == QUIC_STATUS_SUCCESS) {
        TEST_FALSE(Connection->GetTransportClosed());
        TEST_FALSE(Connection->GetPeerClosed());
    }
    delete ConnState;
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
void
ListenerAcceptPingConnection(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    auto Connection = new TestConnection(ConnectionHandle, ConnectionAcceptPingStream);
    if (Connection == nullptr || !(Connection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete Connection;
        MsQuic->ConnectionClose(ConnectionHandle);
        return;
    }
    Connection->SetAutoDelete();

    auto Stats = (PingStats*)Listener->Context;
    Connection->Context = new PingConnState(Stats, Connection);
    Connection->SetShutdownCompleteCallback(PingConnectionShutdown);
    Connection->SetExpectedResumed(Stats->ZeroRtt);
    if (Stats->ExpectedCloseStatus != QUIC_STATUS_SUCCESS) {
        Connection->SetExpectedTransportCloseStatus(Stats->ExpectedCloseStatus);
        if (Stats->ExpectedCloseStatus == QUIC_STATUS_CONNECTION_TIMEOUT) {
            Connection->SetDisconnectTimeout(1000); // ms
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
}

TestConnection*
NewPingConnection(
    _In_ MsQuicSession& Session,
    _In_ PingStats* ClientStats,
    _In_ bool UseSendBuffer
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    auto Connection = new TestConnection(Session, ConnectionAcceptPingStream);
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

    Connection->Context = new PingConnState(ClientStats, Connection);
    Connection->SetShutdownCompleteCallback(PingConnectionShutdown);
    Connection->SetExpectedResumed(ClientStats->ZeroRtt);

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
    const uint32_t TimeoutMs = EstimateTimeoutMs(Length) * StreamBurstCount;
    const uint16_t TotalStreamCount = (uint16_t)(StreamCount * StreamBurstCount);
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;

    PingStats ServerStats(Length, ConnectionCount, TotalStreamCount, FifoScheduling, UnidirectionalStreams, ServerInitiatedStreams, ClientZeroRtt && !ServerRejectZeroRtt, false, QUIC_STATUS_SUCCESS);
    PingStats ClientStats(Length, ConnectionCount, TotalStreamCount, FifoScheduling, UnidirectionalStreams, ServerInitiatedStreams, ClientZeroRtt && !ServerRejectZeroRtt);

    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    Session.SetAutoCleanup();
    if (ClientZeroRtt) {
        Session.SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT);
    }
    if (!ServerInitiatedStreams) {
        TEST_QUIC_SUCCEEDED(Session.SetPeerUnidiStreamCount(TotalStreamCount));
        TEST_QUIC_SUCCEEDED(Session.SetPeerBidiStreamCount(TotalStreamCount));
    }

    if (ServerRejectZeroRtt) {
        uint8_t NewTicketKey[44] = {1};
        //
        // TODO: Validate new connections don't do 0-RTT
        //
        TEST_QUIC_SUCCEEDED(Session.SetTlsTicketKey(NewTicketKey));
    }

    if (ClientZeroRtt) {
        bool Success;
        QuicTestPrimeResumption(Session, QuicAddrFamily, Success);
        if (!Success) {
            return;
        }
    }

    StatelessRetryHelper RetryHelper(ServerStatelessRetry);

    {
        TestListener Listener(Session.Handle, ListenerAcceptPingConnection, false, UseSendBuffer);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        if (ServerRejectZeroRtt) {
            uint8_t NewTicketKey[44] = {0};
            TEST_QUIC_SUCCEEDED(Session.SetTlsTicketKey(NewTicketKey));
        }

        Listener.Context = &ServerStats;

        UniquePtrArray<TestConnection*> Connections(new TestConnection*[ConnectionCount]);

        for (uint32_t i = 0; i < ClientStats.ConnectionCount; ++i) {
            Connections.get()[i] =
                NewPingConnection(
                    Session,
                    &ClientStats,
                    UseSendBuffer);
            if (Connections.get()[i] == nullptr) {
                return;
            }
        }

        QuicAddr LocalAddr;
        for (uint32_t j = 0; j < StreamBurstCount; ++j) {
            if (j != 0) {
                QuicSleep(StreamBurstDelayMs);
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
                    TEST_QUIC_SUCCEEDED(Connections.get()[i]->SetRemoteAddr(RemoteAddr));

                    if (i != 0) {
                        Connections.get()[i]->SetLocalAddr(LocalAddr);
                    }
                    TEST_QUIC_SUCCEEDED(
                        Connections.get()[i]->Start(
                            QuicAddrFamily,
                            ClientZeroRtt ? QUIC_LOCALHOST_FOR_AF(QuicAddrFamily) : nullptr,
                            ServerLocalAddr.GetPort()));
                    if (i == 0) {
                        Connections.get()[i]->GetLocalAddr(LocalAddr);
                    }
                }
            }
        }

        if (!QuicEventWaitWithTimeout(ClientStats.CompletionEvent, TimeoutMs)) {
            TEST_FAILURE("Wait for clients to complete timed out after %u ms.", TimeoutMs);
            return;
        }

        if (!QuicEventWaitWithTimeout(ServerStats.CompletionEvent, TimeoutMs)) {
            TEST_FAILURE("Wait for server to complete timed out after %u ms.", TimeoutMs);
            return;
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

    {
        MsQuicSession Session;
        TEST_TRUE(Session.IsValid());
        TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(10000)); // Fallback (test failure) timeout

        {
            TestListener Listener(Session.Handle, ListenerAcceptPingConnection);
            TEST_TRUE(Listener.IsValid());
            Listener.Context = &ServerStats;
            TEST_QUIC_SUCCEEDED(Listener.Start());

            QuicAddr ServerLocalAddr;
            TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

            {
                TestConnection* Client =
                    NewPingConnection(
                        Session,
                        &ClientStats,
                        FALSE);
                if (Client == nullptr) {
                    return;
                }
                TEST_QUIC_SUCCEEDED(Client->SetPeerUnidiStreamCount(1));

                TEST_QUIC_SUCCEEDED(
                    Client->Start(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));


                QuicSleep(100); // Sleep for a little bit.

                Client->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
            }
        }
    } // Scope exit waits on Session closure, which waits for connection closures.
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
void
ListenerAcceptConnectionAndStreams(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    ServerAcceptContext* AcceptContext = (ServerAcceptContext*)Listener->Context;
    *AcceptContext->NewConnection = new TestConnection(ConnectionHandle, ConnectionAcceptAndIgnoreStream);
    if (*AcceptContext->NewConnection == nullptr || !(*AcceptContext->NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *AcceptContext->NewConnection;
        *AcceptContext->NewConnection = nullptr;
        MsQuic->ConnectionClose(ConnectionHandle);
    }
    QuicEventSet(AcceptContext->NewConnectionReady);
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

    {
        MsQuicSession Session;
        TEST_TRUE(Session.IsValid());
        TEST_QUIC_SUCCEEDED(Session.SetIdleTimeout(10000)); // Fallback (test failure) timeout
        TEST_QUIC_SUCCEEDED(Session.SetPeerUnidiStreamCount(1));

        {
            TestListener Listener(Session.Handle, ListenerAcceptConnectionAndStreams);
            TEST_TRUE(Listener.IsValid());
            TEST_QUIC_SUCCEEDED(Listener.Start());

            QuicAddr ServerLocalAddr;
            TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

            TestConnection* Client;
            {
                UniquePtr<TestConnection> Server;
                ServerAcceptContext ServerAcceptCtx((TestConnection**)&Server);
                Listener.Context = &ServerAcceptCtx;

                Client =
                    NewPingConnection(
                        Session,
                        &ClientStats,
                        false);
                if (Client == nullptr) {
                    return;
                }

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
                        AF_INET,
                        QUIC_LOCALHOST_FOR_AF(AF_INET),
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

                QuicSleep(15); // Sleep for just a bit.

                Server->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
            }

            (void)Client->WaitForShutdownComplete();
        }
    } // Scope exit waits on Session closure, which waits for connection closures.
}

struct AbortiveTestContext {
    AbortiveTestContext(
        _In_ bool ServerParam,
        _In_ QUIC_ABORTIVE_TRANSFER_FLAGS FlagsParam,
        _In_ uint32_t ExpectedErrorParam,
        _In_ QUIC_STREAM_SHUTDOWN_FLAGS ShutdownFlagsParam) :
            Flags(FlagsParam), ExpectedError(ExpectedErrorParam), Server(ServerParam), ShutdownFlags(ShutdownFlagsParam), TestResult(0)
    { }
    EventScope ConnectedEvent;
    EventScope StreamEvent;
    EventScope TestEvent;
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
                QuicEventSet(TestContext->TestEvent.Handle);
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            if (TestContext->Server && Flags->ShutdownDirection == ShutdownSend) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_SEND_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                QuicEventSet(TestContext->TestEvent.Handle);
            } else if (!TestContext->Server && !Flags->ClientShutdown &&
                (Flags->ShutdownDirection == ShutdownBoth || Flags->ShutdownDirection == ShutdownSend)) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_SEND_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                QuicEventSet(TestContext->TestEvent.Handle);
                }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            TestContext->Passed = (TestContext->ExpectedError == Event->PEER_SEND_ABORTED.ErrorCode);
            TestContext->TestResult = (uint32_t) Event->PEER_SEND_ABORTED.ErrorCode;
            QuicEventSet(TestContext->TestEvent.Handle);
            break;
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            if (TestContext->Server && Flags->ShutdownDirection == ShutdownReceive) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_RECEIVE_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                QuicEventSet(TestContext->TestEvent.Handle);
            } else if (!TestContext->Server && !Flags->ClientShutdown &&
                (TestContext->Flags.ShutdownDirection == ShutdownBoth || TestContext->Flags.ShutdownDirection == ShutdownReceive)) {
                TestContext->Passed = (TestContext->ExpectedError == Event->PEER_RECEIVE_ABORTED.ErrorCode);
                TestContext->TestResult = (uint32_t) Event->PEER_RECEIVE_ABORTED.ErrorCode;
                QuicEventSet(TestContext->TestEvent.Handle);
            }
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
                (void*) QuicAbortiveStreamHandler,
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
                QuicEventSet(TestContext->TestEvent.Handle);
            }
            TestContext->Stream.Handle = Event->PEER_STREAM_STARTED.Stream;
            QuicEventSet(TestContext->StreamEvent.Handle);
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_CONNECTED:
            QuicEventSet(TestContext->ConnectedEvent.Handle);
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
    _In_ HQUIC /* QuicListener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    AbortiveTestContext* TestContext = (AbortiveTestContext*) Context;
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            TestContext->Conn.Handle = Event->NEW_CONNECTION.Connection;
            MsQuic->SetCallbackHandler(TestContext->Conn.Handle, (void*) QuicAbortiveConnectionHandler, Context);
            Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
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
    uint32_t TimeoutMs = 500;
    MsQuicSession Session;

    TEST_TRUE(Session.IsValid());
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
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
    QuicAddr ServerLocalAddr;
    QuicBufferScope Buffer(SendLength);
    uint32_t StreamCountType = (Flags.UnidirectionalStream) ?
        QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT : QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT;
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
        AbortiveTestContext ClientContext(false, Flags, ExpectedError, ShutdownFlags), ServerContext(true, Flags, ExpectedError, ShutdownFlags);

        ListenerScope Listener;
        QUIC_STATUS Status =
            MsQuic->ListenerOpen(
                Session,
                QuicAbortiveListenerHandler,
                &ServerContext,
                &Listener.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ListenerOpen failed, 0x%x.", Status);
            return;
        }

        Status = MsQuic->ListenerStart(Listener.Handle, nullptr);

        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ListenerStart failed, 0x%x.", Status);
            return;
        }

        uint32_t Size = sizeof(ServerLocalAddr.SockAddr);
        Status =
            MsQuic->GetParam(
                Listener.Handle,
                QUIC_PARAM_LEVEL_LISTENER,
                QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                &Size,
                &(ServerLocalAddr.SockAddr));
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->GetParam failed, 0x%x.", Status);
            return;
        }

        //
        // Start the client
        //
        Status =
            MsQuic->ConnectionOpen(
                Session,
                QuicAbortiveConnectionHandler,
                &ClientContext,
                &ClientContext.Conn.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        uint32_t CertFlags =
            QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA |
            QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID;
        Status =
            MsQuic->SetParam(
                ClientContext.Conn.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertFlags),
                &CertFlags);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam(CERT_VALIDATION_FLAGS) failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                ClientContext.Conn.Handle,
                QuicAddrFamily,
                QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (WaitForConnected) {
            if (!QuicEventWaitWithTimeout(ClientContext.ConnectedEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Client failed to get connected before timeout!");
                return;
            }
            if (!QuicEventWaitWithTimeout(ServerContext.ConnectedEvent.Handle, TimeoutMs)) {
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
            Status =
                MsQuic->SetParam(
                    ServerContext.Conn.Handle,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    StreamCountType,
                    sizeof(StreamCount),
                    &StreamCount);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_PEER_*DI_STREAM_COUNT(%d) failed, 0x%x", StreamCountType, Status);
                return;
            }
        }

        if (Flags.WaitForStream && !Flags.DelayStreamCreation) {
            if (!QuicEventWaitWithTimeout(ServerContext.StreamEvent.Handle, TimeoutMs)) {
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
            QuicEventSet(ClientContext.TestEvent.Handle);
        }

        if (Flags.DelayStreamCreation) {
            Status =
                MsQuic->SetParam(
                    ServerContext.Conn.Handle,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    StreamCountType,
                    sizeof(StreamCount),
                    &StreamCount);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_PEER_*DI_STREAM_COUNT(%d) failed, 0x%x", StreamCountType, Status);
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
            QuicEventSet(ClientContext.TestEvent.Handle);
        }

        //
        // In these test cases, the client won't receive any packets, so signal success.
        //
        if (Flags.ClientShutdown && Flags.UnidirectionalStream && Flags.ShutdownDirection == ShutdownReceive) {
            ServerContext.TestResult = ExpectedError;
            ServerContext.Passed = true;
            QuicEventSet(ServerContext.TestEvent.Handle);
        } else if (!Flags.ClientShutdown && Flags.UnidirectionalStream && Flags.ShutdownDirection == ShutdownSend) {
            ClientContext.TestResult = ExpectedError;
            ClientContext.Passed = true;
            QuicEventSet(ClientContext.TestEvent.Handle);
        }

        if (!Flags.ClientShutdown) {
            if (!QuicEventWaitWithTimeout(ClientContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Client failed to shutdown before timeout!");
                return;
            }
            if (!QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
                TEST_FAILURE("Server failed to shutdown before timeout!");
                return;
            }
            if (ExpectedError != ClientContext.TestResult) {
                TEST_FAILURE("Expected error (0x%x) is not equal to actual result (0x%x).", ExpectedError, ClientContext.TestResult);
            }
            TEST_EQUAL(ExpectedError, ClientContext.TestResult);
            TEST_TRUE(ClientContext.Passed);
        } else {
            if (!QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle,TimeoutMs )) {
                TEST_FAILURE("Server failed to shutdown before timeout!");
                return;
            }
            if (!QuicEventWaitWithTimeout(ClientContext.TestEvent.Handle, TimeoutMs)) {
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

struct RecvResumeTestContext {
    RecvResumeTestContext(
        _In_ bool ServerParam,
        _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownTypeParam,
        _In_ QUIC_RECEIVE_RESUME_TYPE PauseTypeParam) :
            ShutdownType(ShutdownTypeParam), PauseType(PauseTypeParam), Server(ServerParam), TestResult((uint32_t)QUIC_STATUS_INTERNAL_ERROR), ReceiveCallbackCount(0)
    { }
    EventScope ConnectedEvent;
    EventScope StreamEvent;
    EventScope TestEvent;
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

                TestContext->AvailableBuffer = (uint32_t) Event->RECEIVE.TotalBufferLength;
                Event->RECEIVE.TotalBufferLength = TestContext->ConsumeBufferAmount;

                if (TestContext->ReceiveCallbackCount == 0) {
                    if (TestContext->PauseType == ReturnStatusPending) {
                        if (Event->RECEIVE.BufferCount > 1) {
                            TEST_FAILURE("Too many buffers! %u", Event->RECEIVE.BufferCount);
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
                    QuicEventSet(TestContext->TestEvent.Handle);
                }
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            if (TestContext->ShutdownType == GracefulShutdown) {
                if (TestContext->ShutdownOnly) {
                    QuicEventSet(TestContext->TestEvent.Handle);
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
                QuicEventSet(TestContext->TestEvent.Handle);
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
                (void*) QuicRecvResumeStreamHandler,
                Context);
            TestContext->Stream.Handle = Event->PEER_STREAM_STARTED.Stream;
            QuicEventSet(TestContext->StreamEvent.Handle);
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_CONNECTED:
            QuicEventSet(TestContext->ConnectedEvent.Handle);
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
    _In_ HQUIC /* QuicListener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    RecvResumeTestContext* TestContext = (RecvResumeTestContext*) Context;
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            TestContext->Conn.Handle = Event->NEW_CONNECTION.Connection;
            MsQuic->SetCallbackHandler(TestContext->Conn.Handle, (void*) QuicRecvResumeConnectionHandler, Context);
            Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
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
    uint32_t TimeoutMs = 500;
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    uint32_t SendSize = SendBytes;
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
    QuicAddr ServerLocalAddr;
    QuicBufferScope Buffer(SendSize);
    RecvResumeTestContext ServerContext(true, ShutdownType, PauseType), ClientContext(false, ShutdownType, PauseType);
    ServerContext.ConsumeBufferAmount = ConsumeBytes;

    {
        //
        // Start the server.
        //
        ListenerScope Listener;
        QUIC_STATUS Status =
            MsQuic->ListenerOpen(
                Session,
                QuicRecvResumeListenerHandler,
                &ServerContext,
                &Listener.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ListenerOpen failed, 0x%x.", Status);
            return;
        }

        Status = MsQuic->ListenerStart(Listener.Handle, nullptr);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ListenerStart failed, 0x%x.", Status);
            return;
        }

        uint32_t Size = sizeof(ServerLocalAddr.SockAddr);
        Status =
            MsQuic->GetParam(
                Listener.Handle,
                QUIC_PARAM_LEVEL_LISTENER,
                QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                &Size,
                &ServerLocalAddr.SockAddr);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->GetParam failed, 0x%x.", Status);
            return;
        }

        //
        // Start the client.
        //
        Status =
            MsQuic->ConnectionOpen(
                Session,
                QuicRecvResumeConnectionHandler,
                &ClientContext,
                &ClientContext.Conn.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        uint32_t CertFlags =
            QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA |
            QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID;
        Status =
            MsQuic->SetParam(
                ClientContext.Conn.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertFlags),
                &CertFlags);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam(CERT_VALIDATION_FLAGS) failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                ClientContext.Conn.Handle,
                QuicAddrFamily,
                QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (!QuicEventWaitWithTimeout(ClientContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Client failed to get connected before timeout!");
            return;
        }
        if (!QuicEventWaitWithTimeout(ServerContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get connected before timeout!");
            return;
        }

        uint32_t StreamCount = 1;
        uint16_t ParamType = QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT;
        Status =
            MsQuic->SetParam(
                ServerContext.Conn.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                ParamType,
                sizeof(ParamType),
                &StreamCount);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT failed, 0x%x", Status);
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

        if (!QuicEventWaitWithTimeout(ServerContext.StreamEvent.Handle, TimeoutMs)) {
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
        if (!QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
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
                if (!QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
                    TEST_FAILURE("Server failed to get shutdown before timeout!");
                    return;
                }
                QuicSecureZeroMemory(ServerContext.PendingBuffer, SendSize);
            }
            //
            // Indicate the buffer has been consumed.
            //
            Status =
                MsQuic->StreamReceiveComplete(
                    ServerContext.Stream.Handle,
                    SendBytes);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE(
                    "MsQuic->StreamReceiveComplete %d failed, 0x%x",
                    SendBytes,
                    Status);
                return;
            }
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

            if (!QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
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
    uint32_t TimeoutMs = 500;
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
    QuicAddr ServerLocalAddr;
    RecvResumeTestContext ServerContext(true, ShutdownType, ReturnConsumedBytes), ClientContext(false, ShutdownType, ReturnConsumedBytes);
    ServerContext.ShutdownOnly = true;

    {
        //
        // Start the server.
        //
        ListenerScope Listener;
        QUIC_STATUS Status =
            MsQuic->ListenerOpen(
                Session,
                QuicRecvResumeListenerHandler,
                &ServerContext,
                &Listener.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ListenerOpen failed, 0x%x.", Status);
            return;
        }

        Status = MsQuic->ListenerStart(Listener.Handle, nullptr);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ListenerStart failed, 0x%x.", Status);
            return;
        }

        uint32_t Size = sizeof(ServerLocalAddr.SockAddr);
        Status =
            MsQuic->GetParam(
                Listener.Handle,
                QUIC_PARAM_LEVEL_LISTENER,
                QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                &Size,
                &ServerLocalAddr.SockAddr);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->GetParam failed, 0x%x.", Status);
            return;
        }

        //
        // Start the client.
        //
        Status =
            MsQuic->ConnectionOpen(
                Session,
                QuicRecvResumeConnectionHandler,
                &ClientContext,
                &ClientContext.Conn.Handle);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
            return;
        }

        uint32_t CertFlags =
            QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA |
            QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID;
        Status =
            MsQuic->SetParam(
                ClientContext.Conn.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertFlags),
                &CertFlags);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam(CERT_VALIDATION_FLAGS) failed, 0x%x.", Status);
            return;
        }

        Status =
            MsQuic->ConnectionStart(
                ClientContext.Conn.Handle,
                QuicAddrFamily,
                QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                ServerLocalAddr.GetPort());
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->ConnectionStart failed, 0x%x.", Status);
            return;
        }

        if (!QuicEventWaitWithTimeout(ClientContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Client failed to get connected before timeout!");
            return;
        }
        if (!QuicEventWaitWithTimeout(ServerContext.ConnectedEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get connected before timeout!");
            return;
        }

        uint32_t StreamCount = 1;
        uint16_t ParamType = QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT;
        Status =
            MsQuic->SetParam(
                ServerContext.Conn.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                ParamType,
                sizeof(ParamType),
                &StreamCount);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT failed, 0x%x", Status);
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

        if (!QuicEventWaitWithTimeout(ServerContext.StreamEvent.Handle, TimeoutMs)) {
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
            if (QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
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
        if (!QuicEventWaitWithTimeout(ServerContext.TestEvent.Handle, TimeoutMs)) {
            TEST_FAILURE("Server failed to get shutdown before timeout!");
            return;
        }
    }
}
