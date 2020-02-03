/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Unittest

--*/

#include "precomp.h"

#include "quic_trace.h"
#ifdef QUIC_LOGS_WPP
#include "quictest.tmh"
#endif

//#define QUIC_TEST_DISABLE_DNS 1

#define OLD_SUPPORTED_VERSION       QUIC_VERSION_1_MS_H
#define LATEST_SUPPORTED_VERSION    QUIC_VERSION_LATEST_H

const uint16_t TestUdpPortBase = 0x8000;

const QuicAddr GetLocalAddr(int Family)
{
    return Family == 4 ? QuicAddr(AF_INET, true) : QuicAddr(AF_INET6, true);
}

void QuicTestInitialize()
{
#ifdef QUIC_NO_ENCRYPTION
    uint8_t Disabled = FALSE;
    if (QUIC_FAILED(
        MsQuic->SetParam(
            MsQuic->Registration,
            QUIC_PARAM_LEVEL_REGISTRATION,
            QUIC_PARAM_REGISTRATION_ENCRYPTION,
            sizeof(Disabled),
            &Disabled))) {
        QuicTraceLogError("[test] Disabling encryption failed");
    }
#endif
}

void QuicTestCleanup()
{
}

struct TestScopeLogger
{
    const char* Name;
    TestScopeLogger(const char* name) : Name(name) {
        QuicTraceLogInfo("[test]---> %s", Name);
    }
    ~TestScopeLogger() {
        QuicTraceLogInfo("[test]<--- %s", Name);
    }
};

_Function_class_(NEW_CONNECTION_CALLBACK)
static
void
ListenerDoNothingCallback(
    _In_ TestListener* /* Listener */,
    _In_ HQUIC /* ConnectionHandle */
    )
{
    TEST_FAILURE("This callback should never be called!");
}

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

void QuicTestCreateListener()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
    }
}

void QuicTestStartListener()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());
    }

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(AF_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerImplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());

        QuicAddr LocalAddress(Family == 4 ? AF_INET : AF_INET6);
        TEST_QUIC_SUCCEEDED(Listener.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListeners()
{
    MsQuicSession Session1;
    TEST_TRUE(Session1.IsValid());
    MsQuicSession Session2("MsQuicTest2");
    TEST_TRUE(Session2.IsValid());

    {
        TestListener Listener1(Session1.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start());

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Session2.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_SUCCEEDED(Listener2.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListenersSameALPN()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener1(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start());

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Listener2.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerExplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());

        QuicAddr LocalAddress(GetLocalAddr(Family), TestUdpPortBase);
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Listener.Start(&LocalAddress.SockAddr);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}

void QuicTestCreateConnection()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestConnection Connection(Session.Handle, ConnectionDoNothingCallback, false);
        TEST_TRUE(Connection.IsValid());
    }
}

void QuicTestBindConnectionImplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestConnection Connection(Session.Handle, ConnectionDoNothingCallback, false);
        TEST_TRUE(Connection.IsValid());

        QuicAddr LocalAddress(Family == 4 ? AF_INET : AF_INET6);
        TEST_QUIC_SUCCEEDED(Connection.SetLocalAddr(LocalAddress));
    }
}

void QuicTestBindConnectionExplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestConnection Connection(Session.Handle, ConnectionDoNothingCallback, false);
        TEST_TRUE(Connection.IsValid());

        QuicAddr LocalAddress(GetLocalAddr(Family), TestUdpPortBase);
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Connection.SetLocalAddr(LocalAddress);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
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
    }
    QuicEventSet(AcceptContext->NewConnectionReady);
}

struct StatelessRetryHelper
{
    bool DoRetry;
    StatelessRetryHelper(bool Enabled) : DoRetry(Enabled) {
        if (DoRetry) {
            uint16_t value = 0;
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Registration,
                    QUIC_PARAM_LEVEL_REGISTRATION,
                    QUIC_PARAM_REGISTRATION_RETRY_MEMORY_PERCENT,
                    sizeof(value),
                    &value));
        }
    }
    ~StatelessRetryHelper() {
        if (DoRetry) {
            uint16_t value = 65;
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Registration,
                    QUIC_PARAM_LEVEL_REGISTRATION,
                    QUIC_PARAM_REGISTRATION_RETRY_MEMORY_PERCENT,
                    sizeof(value),
                    &value));
        }
    }
};

#define PRIVATE_TP_TYPE   77
#define PRIVATE_TP_LENGTH 2345

struct PrivateTransportHelper : QUIC_PRIVATE_TRANSPORT_PARAMETER
{
    PrivateTransportHelper(bool Enabled) {
        if (Enabled) {
            Type = PRIVATE_TP_TYPE;
            Length = PRIVATE_TP_LENGTH;
            Buffer = new uint8_t[PRIVATE_TP_LENGTH];
            TEST_TRUE(Buffer != nullptr);
        } else {
            Buffer = nullptr;
        }
    }
    ~PrivateTransportHelper() {
        delete [] Buffer;
    }
};

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
    _In_ bool SessionResumption
    )
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetPeerBidiStreamCount(4));
    MsQuicSession Session2("MsQuicTest2");
    TEST_TRUE(Session2.IsValid());
    TEST_QUIC_SUCCEEDED(Session2.SetPeerBidiStreamCount(4));

    StatelessRetryHelper RetryHelper(ServerStatelessRetry);
    PrivateTransportHelper TpHelper(MultiPacketClientInitial);

    {
        TestListener Listener(Session.Handle, ListenerAcceptConnection, AsyncSecConfig);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr(QuicAddrFamily);
        TEST_QUIC_SUCCEEDED(Listener.Start(&ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        TestListener Listener2(Session2.Handle, ListenerAcceptConnection, AsyncSecConfig);
        TEST_TRUE(Listener2.IsValid());
        if (MultipleALPNs) {
            TEST_QUIC_SUCCEEDED(Listener2.Start(&ServerLocalAddr.SockAddr));
        }

        if (SessionResumption) {
            TestScopeLogger logScope("PrimeResumption");
            {
                TestConnection Client(
                    MultipleALPNs ? Session2.Handle : Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());
                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif
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
            Listener2.Context = &ServerAcceptCtx;

            {
                TestConnection Client(
                    MultipleALPNs ? Session2.Handle : Session.Handle,
                    ConnectionDoNothingCallback,
                    false);
                TEST_TRUE(Client.IsValid());

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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif

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

#if !QUIC_SEND_FAKE_LOSS
            TEST_TRUE(Server->GetPeerClosed());
            TEST_EQUAL(Server->GetPeerCloseErrorCode(), QUIC_TEST_NO_ERROR);
#endif
        }
    }
}

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
        ConnState->GetPingStats()->ZeroRtt) {
        if (Stream->GetBytesReceived() != 0 && // TODO - Support 0-RTT indication for Stream Open callback.
            !Stream->GetUsedZeroRtt()) {
            TEST_FAILURE("0-RTT wasn't used for stream data.");
        }
    }
#endif

    if (ConnState->StreamsComplete > 0 && ConnState->StreamsComplete % 2 == 0 && ConnState->Stats->ServerKeyUpdate) {
        ConnState->Connection->ForceKeyUpdate();
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

    if (Listener->Context != nullptr) {
        auto Connection = new TestConnection(ConnectionHandle, ConnectionAcceptPingStream, true, true);
        if (Connection == nullptr || !(Connection)->IsValid()) {
            TEST_FAILURE("Failed to accept new TestConnection.");
            delete Connection;
            MsQuic->ConnectionClose(ConnectionHandle);
            return;
        }

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

        if (Stats->ServerInitiatedStreams) {
            SendPingBurst(
                Connection,
                Stats->StreamCount,
                Stats->PayloadLength);
        }

    } else {
        auto Connection = new TestConnection(ConnectionHandle, ConnectionDoNothingCallback, true, true);
        if (Connection == nullptr || !(Connection)->IsValid()) {
            TEST_FAILURE("Failed to accept new TestConnection.");
            delete Connection;
            MsQuic->ConnectionClose(ConnectionHandle);
            return;
        }
    }
}

TestConnection*
NewPingConnection(
    _In_ HQUIC SessionHandle,
    _In_ PingStats* ClientStats,
    _In_ bool UseSendBuffer
    )
{
    TestScopeLogger logScope(__FUNCTION__);

    auto Connection = new TestConnection(SessionHandle, ConnectionAcceptPingStream, false, true, UseSendBuffer);
    if (Connection == nullptr || !(Connection)->IsValid()) {
        TEST_FAILURE("Failed to create new TestConnection.");
        delete Connection;
        return nullptr;
    }

    Connection->Context = new PingConnState(ClientStats, Connection);
    Connection->SetShutdownCompleteCallback(PingConnectionShutdown);
    Connection->SetExpectedResumed(ClientStats->ZeroRtt);

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
    _In_ bool ServerInitiatedStreams
    )
{
    const uint32_t TimeoutMs = EstimateTimeoutMs(Length) * StreamBurstCount;
    const uint16_t TotalStreamCount = (uint16_t)(StreamCount * StreamBurstCount);

    PingStats ServerStats(Length, ConnectionCount, TotalStreamCount, UnidirectionalStreams, ServerInitiatedStreams, ClientZeroRtt && !ServerRejectZeroRtt, false, QUIC_STATUS_SUCCESS);
    PingStats ClientStats(Length, ConnectionCount, TotalStreamCount, UnidirectionalStreams, ServerInitiatedStreams, ClientZeroRtt && !ServerRejectZeroRtt);

    MsQuicSession Session("MsQuicTest", true);
    TEST_TRUE(Session.IsValid());
    if (!ServerInitiatedStreams) {
        TEST_QUIC_SUCCEEDED(Session.SetPeerUnidiStreamCount(TotalStreamCount));
        TEST_QUIC_SUCCEEDED(Session.SetPeerBidiStreamCount(TotalStreamCount));
    }

    if (ServerRejectZeroRtt) {
        uint8_t NewTicketKey[44] = {1};
        TEST_QUIC_SUCCEEDED(Session.SetTlsTicketKey(NewTicketKey));
    }

    StatelessRetryHelper RetryHelper(ServerStatelessRetry);

    {
        TestListener Listener(Session.Handle, ListenerAcceptPingConnection, false, UseSendBuffer);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        if (ClientZeroRtt) {
            TestScopeLogger logScope("PrimeZeroRtt");
            {
                TestConnection Client(Session.Handle, ConnectionDoNothingCallback, false);
                TEST_TRUE(Client.IsValid());
                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif
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

        if (ServerRejectZeroRtt) {
            uint8_t NewTicketKey[44] = {0};
            TEST_QUIC_SUCCEEDED(Session.SetTlsTicketKey(NewTicketKey));
        }

        Listener.Context = &ServerStats;

        UniquePtrArray<TestConnection*> Connections(new TestConnection*[ConnectionCount]);

        for (uint32_t i = 0; i < ClientStats.ConnectionCount; ++i) {
            Connections.get()[i] =
                NewPingConnection(
                    Session.Handle,
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
                            QuicAddrGetPort(&ServerLocalAddr.SockAddr)));
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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(AF_INET, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif

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
QuicTestServerDisconnect(
    void
    )
{
    PingStats ServerStats(UINT64_MAX - 1, 1, 1, TRUE, TRUE, FALSE, TRUE, QUIC_STATUS_CONNECTION_TIMEOUT);
    PingStats ClientStats(UINT64_MAX - 1, 1, 1, TRUE, TRUE, FALSE, TRUE);

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
                        Session.Handle,
                        &ClientStats,
                        FALSE);
                if (Client == nullptr) {
                    return;
                }
                TEST_QUIC_SUCCEEDED(Client->SetPeerUnidiStreamCount(1));

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(AF_INET, true);
                TEST_QUIC_SUCCEEDED(Client->SetRemoteAddr(RemoteAddr));
                #endif

                TEST_QUIC_SUCCEEDED(
                    Client->Start(
                        ServerLocalAddr.SockAddr.si_family,
                        QUIC_LOCALHOST_FOR_AF(ServerLocalAddr.SockAddr.si_family),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));


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
    *AcceptContext->NewConnection = new TestConnection(ConnectionHandle, ConnectionAcceptAndIgnoreStream, true);
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

    PingStats ClientStats(UINT64_MAX - 1, 1, 1, TRUE, FALSE, FALSE, TRUE,
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
                        Session.Handle,
                        &ClientStats,
                        FALSE);
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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(AF_INET, true);
                TEST_QUIC_SUCCEEDED(Client->SetRemoteAddr(RemoteAddr));
                #endif

                TEST_QUIC_SUCCEEDED(
                    Client->Start(
                        AF_INET,
                        QUIC_LOCALHOST_FOR_AF(AF_INET),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

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

        #if QUIC_TEST_DISABLE_DNS
        QuicAddr RemoteAddr(Family == 4 ? AF_INET : AF_INET6, true);
        TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
        #endif

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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif

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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif

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

            #if QUIC_TEST_DISABLE_DNS
            QuicAddr RemoteAddr(QuicAddrFamily, true);
            TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
            #endif

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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif

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
                        Client.ForceKeyUpdate();
                    }

                    if (ServerKeyUpdate) {
                        Server->ForceKeyUpdate();
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
            } else {
                TestContext->Stream.Handle = Event->PEER_STREAM_STARTED.Stream;
            }
            QuicEventSet(TestContext->StreamEvent.Handle);
            return QUIC_STATUS_SUCCESS;
        case QUIC_CONNECTION_EVENT_CONNECTED:
            QuicEventSet(TestContext->ConnectedEvent.Handle);
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
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
        AbortiveTestContext ServerContext(true, Flags, ExpectedError, ShutdownFlags), ClientContext(false, Flags, ExpectedError, ShutdownFlags);

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
                QuicAddrGetPort(&ServerLocalAddr.SockAddr));
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

                #if QUIC_TEST_DISABLE_DNS
                QuicAddr RemoteAddr(QuicAddrFamily, true);
                TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
                #endif

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
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
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
                QuicAddrGetPort(&ServerLocalAddr.SockAddr));
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
                QuicAddrGetPort(&ServerLocalAddr.SockAddr));
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
