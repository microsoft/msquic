/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Event Callback tests

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "EventTest.cpp.clog.h"
#endif

#define QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION   1
#define QUIC_EVENT_ACTION_SHUTDOWN_STREAM       2

const uint8_t StreamPayload[64] = {0x1};
const QUIC_BUFFER StreamBuffer = { sizeof(StreamPayload), (uint8_t*)StreamPayload };

struct StreamEventValidator {
    bool Success;
    bool Optional;
    QUIC_STREAM_EVENT_TYPE Type;
    uint8_t Actions;
    StreamEventValidator(QUIC_STREAM_EVENT_TYPE type, uint8_t actions = 0, bool optional = false) : Success(false),
        Optional(optional), Type(type), Actions(actions) { }
    void Validate(_In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->Type != Type) {
            if (!Optional) {
                TEST_FAILURE("StreamEventValidator: Expected %u. Actual %u", Type, Event->Type);
            }
            return;
        }
        if (!ValidateMore(Stream, Event)) {
            return;
        }
        Success = true;
        if (Actions & QUIC_EVENT_ACTION_SHUTDOWN_STREAM) {
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        }
        if (Actions & QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION) {
            MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
    virtual bool ValidateMore(_In_ HQUIC, _Inout_ QUIC_STREAM_EVENT*) { return true; }
    virtual ~StreamEventValidator() { }
};

struct StreamStartCompleteEventValidator : StreamEventValidator {
    BOOLEAN PeerAccepted;
    StreamStartCompleteEventValidator(bool PeerAccepted = false, uint8_t actions = 0, bool optional = false) :
        StreamEventValidator(QUIC_STREAM_EVENT_START_COMPLETE, actions, optional),
        PeerAccepted(PeerAccepted ? TRUE : FALSE) { }
    virtual bool ValidateMore(_In_ HQUIC, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->START_COMPLETE.PeerAccepted != PeerAccepted) {
            TEST_FAILURE("PeerAccepted mismatch: Expected %u. Actual %u", PeerAccepted, Event->START_COMPLETE.PeerAccepted);
            return false;
        }
        return true;
    }
};

struct StreamPeerRecvAbortEventValidator : StreamEventValidator {
    QUIC_UINT62 ErrorCode;
    StreamPeerRecvAbortEventValidator(QUIC_UINT62 errorcode, uint8_t actions = 0, bool optional = false) :
        StreamEventValidator(QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED, actions, optional),
        ErrorCode(errorcode) { }
    virtual bool ValidateMore(_In_ HQUIC, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->PEER_RECEIVE_ABORTED.ErrorCode != ErrorCode) {
            TEST_FAILURE("PeerRecvAbort mismatch: Expected %llu. Actual %llu", ErrorCode, Event->PEER_RECEIVE_ABORTED.ErrorCode);
            return false;
        }
        return true;
    }
};

struct StreamValidator {
    HQUIC Handle;
    StreamEventValidator** ExpectedEvents;
    uint32_t CurrentEvent;
    CxPlatEvent Complete;
    StreamValidator(StreamEventValidator** expectedEvents) :
        Handle(nullptr), ExpectedEvents(expectedEvents), CurrentEvent(0), Complete(true) { }
    ~StreamValidator() {
        if (Handle) {
            MsQuic->StreamClose(Handle);
            Handle = nullptr;
        }
        for (uint32_t i = 0; ExpectedEvents[i] != nullptr; ++i) {
            delete ExpectedEvents[i];
        }
        delete [] ExpectedEvents;
    }
    void ValidateEvent(_Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE ||
            Event->Type == QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE) {
            return;// Ignore these type of events
        }

        do {
            TEST_NOT_EQUAL(ExpectedEvents[CurrentEvent], nullptr);
            ExpectedEvents[CurrentEvent]->Validate(Handle, Event);
        } while (!ExpectedEvents[CurrentEvent]->Success &&
                 ExpectedEvents[CurrentEvent]->Optional &&
                 ++CurrentEvent);

        if (ExpectedEvents[++CurrentEvent] == nullptr) {
            Complete.Set();
        }
    }
    bool Success() const { return ExpectedEvents[CurrentEvent] == nullptr; }
};

struct ConnEventValidator {
    bool Success;
    bool Optional;
    bool Resumed;
    QUIC_CONNECTION_EVENT_TYPE Type;
    uint8_t Actions;
    ConnEventValidator(QUIC_CONNECTION_EVENT_TYPE type, uint8_t actions = 0, bool optional = false, bool resumed = false) : Success(false),
        Optional(optional), Resumed(resumed), Type(type), Actions(actions) { }
    virtual void Validate(_In_ HQUIC Connection, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type != Type) {
            if (!Optional) {
                TEST_FAILURE("ConnEventValidator: Expected %u. Actual %u", Type, Event->Type);
            }
            return;
        }
        if (Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            if ((bool)Event->CONNECTED.SessionResumed != Resumed) {
                if (!Optional) {
                    TEST_FAILURE(
                        "ConnEventValidator: SessionResumed: Expected: %hhu. Actual: %hhu",
                        Resumed,
                        Event->CONNECTED.SessionResumed);
                }
                return;
            }
        }
        Success = true;
        if (Actions & QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION) {
            MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
    virtual ~ConnEventValidator() { }
};

struct ConnValidator {
    HQUIC Handle;
    HQUIC Configuration;
    ConnEventValidator** ExpectedEvents;
    uint32_t CurrentEvent;
    CxPlatEvent Complete;
    CxPlatEvent HandshakeComplete;
    ConnValidator(HQUIC Configuration = nullptr) :
        Handle(nullptr), Configuration(Configuration),
        ExpectedEvents(nullptr), CurrentEvent(0), Complete(true) { }
    ConnValidator(ConnEventValidator** expectedEvents, HQUIC Configuration = nullptr) :
        Handle(nullptr), Configuration(Configuration),
        ExpectedEvents(expectedEvents), CurrentEvent(0), Complete(true) { }
    ~ConnValidator() {
        if (Handle) {
            MsQuic->ConnectionClose(Handle);
            Handle = nullptr;
        }
        if (ExpectedEvents) {
            for (uint32_t i = 0; ExpectedEvents[i] != nullptr; ++i) {
                delete ExpectedEvents[i];
            }
            delete [] ExpectedEvents;
        }
    }
    void SetExpectedEvents(ConnEventValidator** expectedEvents) {
        ExpectedEvents = expectedEvents;
    }
    void ValidateEvent(_Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type == QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED) {
            //
            // Ideal processor changed events can come at any time. There is no
            // way to have a consistent test that validates them. So just
            // ignore them and validate all other events.
            //
            return;
        }

        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            HandshakeComplete.Set();
        }

        do {
            TEST_NOT_EQUAL(ExpectedEvents[CurrentEvent], nullptr);
            ExpectedEvents[CurrentEvent]->Validate(Handle, Event);
        } while (!ExpectedEvents[CurrentEvent]->Success &&
                 ExpectedEvents[CurrentEvent]->Optional &&
                 ++CurrentEvent);

        if (ExpectedEvents[++CurrentEvent] == nullptr) {
            Complete.Set();
        }
    }
    bool Success() const { return ExpectedEvents[CurrentEvent] == nullptr; }
};

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
StreamValidatorCallback(
    _In_ HQUIC /* Stream */,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    StreamValidator* Validator = (StreamValidator*)Context;
    Validator->ValidateEvent(Event);
    return QUIC_STATUS_SUCCESS;
}

struct NewStreamEventValidator : ConnEventValidator {
    StreamValidator* Stream;
    QUIC_STREAM_OPEN_FLAGS Flags;
    NewStreamEventValidator(StreamValidator* stream, QUIC_STREAM_OPEN_FLAGS flags = QUIC_STREAM_OPEN_FLAG_NONE) :
        ConnEventValidator(QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED),
        Stream(stream), Flags(flags) { }
    virtual void Validate(_In_ HQUIC /* Connection */, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        if (Event->Type != Type) {
            if (!Optional) {
                TEST_FAILURE("NewStreamEventValidator: Expected %u. Actual %u", Type, Event->Type);
            }
            return;
        }
        if (Event->PEER_STREAM_STARTED.Flags != Flags) {
            TEST_FAILURE("NewStreamEventValidator: Expected flags %u. Actual %u", Flags, Event->PEER_STREAM_STARTED.Flags);
            return;
        }
        Stream->Handle = Event->PEER_STREAM_STARTED.Stream;
        MsQuic->SetCallbackHandler(
            Event->PEER_STREAM_STARTED.Stream,
            (void *)StreamValidatorCallback,
            Stream);
        Success = true;
    }
};

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ConnValidatorCallback(
    _In_ HQUIC /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    ConnValidator* Validator = (ConnValidator*)Context;
    Validator->ValidateEvent(Event);
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ConnServerResumptionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /*Context*/,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ListenerEventValidatorCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        _Analysis_assume_(Context != nullptr);
        ConnValidator* Validator = (ConnValidator*)Context;
        Validator->Handle = Event->NEW_CONNECTION.Connection;
        MsQuic->SetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            (void *)ConnValidatorCallback,
            Validator);
        return
            MsQuic->ConnectionSetConfiguration(
                Event->NEW_CONNECTION.Connection,
                Validator->Configuration);
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ListenerEventResumptionCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        MsQuic->SetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            (void *)ConnServerResumptionCallback,
            nullptr);

        return
            MsQuic->ConnectionSetConfiguration(
                Event->NEW_CONNECTION.Connection,
                (HQUIC)Context);
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestValidateConnectionEvents1(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    ConnValidator Client(
        new(std::nothrow) ConnEventValidator* [4] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        },
        ServerConfiguration
    );

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));
}

void
QuicTestValidateConnectionEvents2(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    ConnValidator Client(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new(std::nothrow) ConnEventValidator* [4] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        },
        ServerConfiguration
    );

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));
}

void
QuicTestValidateConnectionEvents3(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_BUFFER* ResumptionTicket = nullptr;
    QuicTestPrimeResumption(
        QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
        Registration,
        ServerConfiguration,
        ClientConfiguration,
        &ResumptionTicket);
    if (!ResumptionTicket) {
        return;
    }

    ConnValidator Client(
        new(std::nothrow) ConnEventValidator* [4] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION, false, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new(std::nothrow) ConnEventValidator* [8] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        },
        ServerConfiguration
    );

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_CONN_RESUMPTION_TICKET,
            ResumptionTicket->Length,
            ResumptionTicket->Buffer));
    CXPLAT_FREE(ResumptionTicket, QUIC_POOL_TEST);
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));
}

void QuicTestValidateConnectionEvents(uint32_t Test)
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    { // Listener Scope

    MsQuicListener Listener(Registration, ListenerEventValidatorCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    typedef void (*TestFunc)(MsQuicRegistration& Registration, HQUIC Listener, QuicAddr& ServerLocalAddr);
    const TestFunc Tests[] = {
        QuicTestValidateConnectionEvents1,
        QuicTestValidateConnectionEvents2,
        QuicTestValidateConnectionEvents3
    };

    Tests[Test](Registration, Listener, ServerLocalAddr);

    } // Listener Scope
}

void
QuicTestValidateStreamEvents1(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [5] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_NONE));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents2(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [5] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [8] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_IMMEDIATE));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents3(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // First send buffer
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // Second send buffer
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // FIN
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_IMMEDIATE));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Client.HandshakeComplete.WaitTimeout(1000));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_NONE,
            nullptr));
    CxPlatSleep(20);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_NONE,
            nullptr));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents4(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [6] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // Both send buffers
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // FIN
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_IMMEDIATE));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Client.HandshakeComplete.WaitTimeout(1000));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_DELAY_SEND,
            nullptr));
    CxPlatSleep(20);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_NONE,
            nullptr));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents5(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [8] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_ACCEPTED),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [5] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_NONE | QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents6(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [6] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            nullptr,
            0,
            QUIC_SEND_FLAG_START,
            nullptr));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            nullptr,
            0,
            QUIC_SEND_FLAG_START,
            nullptr));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Client.HandshakeComplete.WaitTimeout(1000));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_FIN,
            nullptr));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents7(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [4] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [6] {
            new(std::nothrow) StreamPeerRecvAbortEventValidator(0),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_NONE));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0xFFFF));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}


void
QuicTestValidateStreamEvents8(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1).SetMinimumMtu(1280).SetMaximumMtu(1280);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings().SetMinimumMtu(1280).SetMaximumMtu(1280), MsQuicCredentialConfig());
    TEST_TRUE(ClientConfiguration.IsValid());

    { // Connections scope
    ConnValidator Client, Server(ServerConfiguration);

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Registration,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));

    { // Stream scope

    StreamValidator ClientStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamStartCompleteEventValidator(),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [7] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // First send buffer
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // Second send buffer
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE), // FIN
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [7] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new(std::nothrow) NewStreamEventValidator(&ServerStream),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamOpen(
            Client.Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            StreamValidatorCallback,
            &ClientStream,
            &ClientStream.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamStart(
            ClientStream.Handle,
            QUIC_STREAM_START_FLAG_IMMEDIATE));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_TEST_LOOPBACK_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Client.HandshakeComplete.WaitTimeout(1000));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_START,
            nullptr));
    CxPlatSleep(20);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            ClientStream.Handle,
            &StreamBuffer,
            1,
            QUIC_SEND_FLAG_START,
            nullptr));

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(
        MsQuic->StreamShutdown(
            ClientStream.Handle,
            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
            0));

    TEST_TRUE(Client.Complete.WaitTimeout(2000));
    TEST_TRUE(Server.Complete.WaitTimeout(1000));

    } // Stream scope
    } // Connections scope
}

void QuicTestValidateStreamEvents(uint32_t Test)
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    { // Listener Scope

    MsQuicListener Listener(Registration, ListenerEventValidatorCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start(Alpn));

    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    typedef void (*TestFunc)(MsQuicRegistration& Registration, HQUIC Listener, QuicAddr& ServerLocalAddr);
    const TestFunc Tests[] = {
        QuicTestValidateStreamEvents1,
        QuicTestValidateStreamEvents2,
        QuicTestValidateStreamEvents3,
        QuicTestValidateStreamEvents4,
        QuicTestValidateStreamEvents5,
        QuicTestValidateStreamEvents6,
        QuicTestValidateStreamEvents7,
        QuicTestValidateStreamEvents8
    };

    Tests[Test](Registration, Listener, ServerLocalAddr);

    } // Listener Scope
}
