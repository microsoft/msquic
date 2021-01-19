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

#define CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION   1
#define CXPLAT_EVENT_ACTION_SHUTDOWN_STREAM       2

struct StreamEventValidator {
    bool Success;
    bool Optional;
    QUIC_STREAM_EVENT_TYPE Type;
    uint8_t Actions;
    StreamEventValidator(QUIC_STREAM_EVENT_TYPE type, uint8_t actions = 0, bool optional = false) : Success(false),
        Optional(optional), Type(type), Actions(actions) { }
    virtual void Validate(_In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->Type != Type) {
            if (!Optional) {
                TEST_FAILURE("StreamEventValidator: Expected %u. Actual %u", Type, Event->Type);
            }
            return;
        }
        Success = true;
        if (Actions & CXPLAT_EVENT_ACTION_SHUTDOWN_STREAM) {
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        }
        if (Actions & CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION) {
            MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
    virtual ~StreamEventValidator() { }
};

struct StreamValidator {
    HQUIC Handle;
    StreamEventValidator** ExpectedEvents;
    uint32_t CurrentEvent;
    CXPLAT_EVENT Complete;
    StreamValidator(StreamEventValidator** expectedEvents) :
        Handle(nullptr), ExpectedEvents(expectedEvents), CurrentEvent(0) {
        CxPlatEventInitialize(&Complete, TRUE, FALSE);
    }
    ~StreamValidator() {
        if (Handle) {
            MsQuic->StreamClose(Handle);
            Handle = nullptr;
        }
        for (uint32_t i = 0; ExpectedEvents[i] != nullptr; ++i) {
            delete ExpectedEvents[i];
        }
        delete [] ExpectedEvents;
        CxPlatEventUninitialize(Complete);
    }
    void ValidateEvent(_Inout_ QUIC_STREAM_EVENT* Event) {
        do {
            TEST_NOT_EQUAL(ExpectedEvents[CurrentEvent], nullptr);
            ExpectedEvents[CurrentEvent]->Validate(Handle, Event);
        } while (!ExpectedEvents[CurrentEvent]->Success &&
                 ExpectedEvents[CurrentEvent]->Optional &&
                 ++CurrentEvent);

        if (ExpectedEvents[++CurrentEvent] == nullptr) {
            CxPlatEventSet(Complete);
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
        if (Actions & CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION) {
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
    CXPLAT_EVENT Complete;
    ConnValidator(HQUIC Configuration = nullptr) :
        Handle(nullptr), Configuration(Configuration),
        ExpectedEvents(nullptr), CurrentEvent(0) {
        CxPlatEventInitialize(&Complete, TRUE, FALSE);
    }
    ConnValidator(ConnEventValidator** expectedEvents, HQUIC Configuration = nullptr) :
        Handle(nullptr), Configuration(Configuration),
        ExpectedEvents(expectedEvents), CurrentEvent(0) {
        CxPlatEventInitialize(&Complete, TRUE, FALSE);
    }
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
        CxPlatEventUninitialize(Complete);
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

        do {
            TEST_NOT_EQUAL(ExpectedEvents[CurrentEvent], nullptr);
            ExpectedEvents[CurrentEvent]->Validate(Handle, Event);
        } while (!ExpectedEvents[CurrentEvent]->Success &&
                 ExpectedEvents[CurrentEvent]->Optional &&
                 ++CurrentEvent);

        if (ExpectedEvents[++CurrentEvent] == nullptr) {
            CxPlatEventSet(Complete);
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
    _Analysis_assume_(Context != NULL);
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
    MsQuic->SetCallbackHandler(
        Event->NEW_CONNECTION.Connection,
        (void *)ConnServerResumptionCallback,
        nullptr);

    return
        MsQuic->ConnectionSetConfiguration(
            Event->NEW_CONNECTION.Connection,
            (HQUIC)Context);
}

void
QuicTestValidateConnectionEvents1(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    ConnValidator Client(
        new(std::nothrow) ConnEventValidator* [4] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true), // This comes AFTER shutdown in miTLS
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true), // This comes AFTER shutdown in miTLS
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
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(CxPlatEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Server.Complete, 1000));
}

void
QuicTestValidateConnectionEvents2(
    _In_ MsQuicRegistration& Registration,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    TestScopeLogger ScopeLogger(__FUNCTION__);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
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
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION),
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
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(CxPlatEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Server.Complete, 1000));
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
    Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_BUFFER* ResumptionTicket = nullptr;
    QuicTestPrimeResumption(
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
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION, false, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new(std::nothrow) ConnEventValidator* [8] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMED),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true, true), // This comes AFTER shutdown in miTLS
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true, true), // This comes AFTER shutdown in miTLS
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
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_RESUMPTION_TICKET,
            ResumptionTicket->Length,
            ResumptionTicket->Buffer));
    CXPLAT_FREE(ResumptionTicket, QUIC_POOL_TEST);
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            ClientConfiguration,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_LOCALHOST_FOR_AF(QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

    TEST_TRUE(CxPlatEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Server.Complete, 1000));
}

void QuicTestValidateConnectionEvents()
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    { // Listener Scope

    ListenerScope Listener;
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            ListenerEventValidatorCallback,
            nullptr,
            &Listener.Handle));
    TEST_QUIC_SUCCEEDED(MsQuic->ListenerStart(Listener.Handle, Alpn, Alpn.Length(), nullptr));

    QuicAddr ServerLocalAddr;
    uint32_t ServerLocalAddrSize = sizeof(ServerLocalAddr.SockAddr);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LEVEL_LISTENER,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &ServerLocalAddrSize,
            &ServerLocalAddr.SockAddr));

    QuicTestValidateConnectionEvents1(Registration, Listener.Handle, ServerLocalAddr);
    QuicTestValidateConnectionEvents2(Registration, Listener.Handle, ServerLocalAddr);
#ifndef QUIC_DISABLE_0RTT_TESTS
    QuicTestValidateConnectionEvents3(Registration, Listener.Handle, ServerLocalAddr);
#endif

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
    Settings.SetPeerBidiStreamCount(1);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
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
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_START_COMPLETE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new(std::nothrow) StreamEventValidator* [5] {
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_RECEIVE),
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, CXPLAT_EVENT_ACTION_SHUTDOWN_STREAM),
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
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(CxPlatEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Server.Complete, 1000));

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
    Settings.SetPeerBidiStreamCount(1);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
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
            new(std::nothrow) StreamEventValidator(QUIC_STREAM_EVENT_START_COMPLETE),
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
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, CXPLAT_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED, 0, true), // TODO - Schannel does resumption regardless
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new(std::nothrow) ConnEventValidator* [6] {
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true), // This comes AFTER shutdown in miTLS
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT),
            new(std::nothrow) ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, true), // This comes AFTER shutdown in miTLS
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
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(CxPlatEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(CxPlatEventWaitWithTimeout(Server.Complete, 1000));

    } // Stream scope
    } // Connections scope
}

void QuicTestValidateStreamEvents()
{
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    { // Listener Scope

    ListenerScope Listener;
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            ListenerEventValidatorCallback,
            nullptr,
            &Listener.Handle));
    TEST_QUIC_SUCCEEDED(MsQuic->ListenerStart(Listener.Handle,  Alpn, Alpn.Length(), nullptr));

    QuicAddr ServerLocalAddr;
    uint32_t ServerLocalAddrSize = sizeof(ServerLocalAddr.SockAddr);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LEVEL_LISTENER,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &ServerLocalAddrSize,
            &ServerLocalAddr.SockAddr));

    QuicTestValidateStreamEvents1(Registration, Listener.Handle, ServerLocalAddr);
    QuicTestValidateStreamEvents2(Registration, Listener.Handle, ServerLocalAddr);

    } // Listener Scope
}
