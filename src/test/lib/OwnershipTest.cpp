#include "precomp.h"
#ifdef QUIC_CLOG
#include "OwnershipTest.cpp.clog.h"
#endif

struct OwnershipState {
    long ShutdownCount{0};
    CxPlatEvent StateEvent;
    long StreamAppClose{0};
    long ConnAppClose{0};
};

struct ConnectionWrapper {
    HQUIC Connection {nullptr};
    ~ConnectionWrapper() noexcept {
        if (Connection) {
            MsQuic->ConnectionClose(Connection);
        }
    }
};

struct StreamWrapper {
    HQUIC Stream {nullptr};
    ~StreamWrapper() noexcept {
        if (Stream) {
            MsQuic->StreamClose(Stream);
        }
    }
};

_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
OwnershipConnCallback(
    HQUIC,
    void* Context,
    QUIC_CONNECTION_EVENT* Event
    )
{
    OwnershipState* State = reinterpret_cast<OwnershipState*>(Context);
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            State->StateEvent.Set();
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            InterlockedIncrement((volatile long*)&State->ShutdownCount);
            State->StateEvent.Set();
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

void QuicTestRegistrationShutdownBeforeConnOpen()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

    HQUIC Connection = nullptr;
    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            OwnershipConnCallback,
            nullptr,
            &Connection);

    TEST_QUIC_STATUS(QUIC_STATUS_INVALID_STATE, Status);
}

void QuicTestRegistrationShutdownAfterConnOpen()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    OwnershipState State;
    ConnectionWrapper Conn;
    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            OwnershipConnCallback,
            &State,
            &Conn.Connection);

    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);

    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

    // Call something that will hit the worker thread, that will ensure conn has
    // been triggered
    QUIC_STATISTICS_V2 Stats;
    uint32_t StatsSize = sizeof(Stats);
    Status =
        MsQuic->GetParam(
            Conn.Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Stats);
    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);
    TEST_EQUAL(0, State.ShutdownCount);
}

void QuicTestRegistrationShutdownAfterConnOpenBeforeStart()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration Configuration(Registration, Alpn, ClientCredConfig);

    OwnershipState State;
    ConnectionWrapper Conn;
    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            OwnershipConnCallback,
            &State,
            &Conn.Connection);

    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);

    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

    // Call something that will hit the worker thread, that will ensure conn has
    // been triggered
    QUIC_STATISTICS_V2 Stats;
    uint32_t StatsSize = sizeof(Stats);
    Status =
        MsQuic->GetParam(
            Conn.Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Stats);
    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);
    TEST_EQUAL(0, State.ShutdownCount);

    Status =
        MsQuic->ConnectionStart(
            Conn.Connection,
            Configuration,
            QUIC_ADDRESS_FAMILY_INET,
            "localhost",
            4454);
    TEST_QUIC_SUCCEEDED(Status);

    StatsSize = sizeof(Stats);
    Status =
        MsQuic->GetParam(
            Conn.Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Stats);
    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);
    TEST_TRUE(State.StateEvent.WaitTimeout(2000));
    TEST_EQUAL(1, State.ShutdownCount);
}

void QuicTestRegistrationShutdownAfterConnOpenAndStart()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicRegistration ServerRegistration{true};
    TEST_TRUE(ServerRegistration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(ServerRegistration, Alpn, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(ServerRegistration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    OwnershipState State;
    ConnectionWrapper Conn;
    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            OwnershipConnCallback,
            &State,
            &Conn.Connection);

    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);

    // Call something that will hit the worker thread, that will ensure conn has
    // been triggered
    QUIC_STATISTICS_V2 Stats;
    uint32_t StatsSize = sizeof(Stats);
    Status =
        MsQuic->GetParam(
            Conn.Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Stats);
    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);
    TEST_EQUAL(0, State.ShutdownCount);

    Status =
        MsQuic->ConnectionStart(
            Conn.Connection,
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort());
    TEST_TRUE(State.StateEvent.WaitTimeout(2000));
    State.StateEvent.Reset();

    StatsSize = sizeof(Stats);
    Status =
        MsQuic->GetParam(
            Conn.Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Stats);
    TEST_QUIC_STATUS(QUIC_STATUS_SUCCESS, Status);
    TEST_EQUAL(0, State.ShutdownCount);

    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

    TEST_TRUE(State.StateEvent.WaitTimeout(2000));
    TEST_EQUAL(1, State.ShutdownCount);
}
