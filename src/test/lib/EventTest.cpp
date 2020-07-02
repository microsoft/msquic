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

#define RESUMPTION_BUFFER_LENGTH 2048
uint8_t SerializedResumptionStorage[sizeof(QUIC_BUFFER) + RESUMPTION_BUFFER_LENGTH];

struct StreamEventValidator {
    bool Success;
    bool Optional;
    QUIC_STREAM_EVENT_TYPE Type;
    uint8_t Actions;
    StreamEventValidator(QUIC_STREAM_EVENT_TYPE type, uint8_t actions = 0, bool optional = false) : Success(false),
        Type(type), Actions(actions), Optional(optional) { }
    virtual void Validate(_In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event) {
        if (Event->Type != Type) {
            if (!Optional) {
                TEST_FAILURE("StreamEventValidator: Expected %u. Actual %u", Type, Event->Type);
            }
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
    virtual ~StreamEventValidator() { }
};

struct StreamValidator {
    HQUIC Handle;
    StreamEventValidator** ExpectedEvents;
    uint32_t CurrentEvent;
    QUIC_EVENT Complete;
    StreamValidator(StreamEventValidator** expectedEvents) :
        Handle(nullptr), ExpectedEvents(expectedEvents), CurrentEvent(0) {
        QuicEventInitialize(&Complete, TRUE, FALSE);
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
        QuicEventUninitialize(Complete);
    }
    void ValidateEvent(_Inout_ QUIC_STREAM_EVENT* Event) {
        do {
            TEST_NOT_EQUAL(ExpectedEvents[CurrentEvent], nullptr);
            ExpectedEvents[CurrentEvent]->Validate(Handle, Event);
        } while (!ExpectedEvents[CurrentEvent]->Success &&
                 ExpectedEvents[CurrentEvent]->Optional &&
                 ++CurrentEvent);

        if (ExpectedEvents[++CurrentEvent] == nullptr) {
            QuicEventSet(Complete);
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
        Type(type), Actions(actions), Optional(optional), Resumed(resumed) { }
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
    ConnEventValidator** ExpectedEvents;
    uint32_t CurrentEvent;
    QUIC_EVENT Complete;
    ConnValidator() :
        Handle(nullptr), ExpectedEvents(nullptr), CurrentEvent(0) {
        QuicEventInitialize(&Complete, TRUE, FALSE);
    }
    ConnValidator(ConnEventValidator** expectedEvents) :
        Handle(nullptr), ExpectedEvents(expectedEvents), CurrentEvent(0) {
        QuicEventInitialize(&Complete, TRUE, FALSE);
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
        QuicEventUninitialize(Complete);
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
            QuicEventSet(Complete);
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
    Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ListenerEventResumptionCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /*Context*/,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    MsQuic->SetCallbackHandler(
        Event->NEW_CONNECTION.Connection,
        (void *)ConnServerResumptionCallback,
        nullptr);

    Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestValidateConnectionEvents1(
    _In_ HQUIC Session,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    ConnValidator Client(
        new ConnEventValidator* [4] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new ConnEventValidator* [5] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Session,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    uint32_t CertFlags =
        QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(CertFlags),
            &CertFlags));
    uint16_t StreamCount = 0; // Temp Work around.
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
            sizeof(StreamCount),
            &StreamCount));
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(QuicEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(QuicEventWaitWithTimeout(Server.Complete, 1000));
}

void
QuicTestValidateConnectionEvents2(
    _In_ HQUIC Session,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    ConnValidator Client(
        new ConnEventValidator* [5] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new ConnEventValidator* [4] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Session,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    uint32_t CertFlags =
        QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(CertFlags),
            &CertFlags));
    uint16_t StreamCount = 0; // Temp Work around.
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
            sizeof(StreamCount),
            &StreamCount));
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(QuicEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(QuicEventWaitWithTimeout(Server.Complete, 1000));
}

void
QuicTestValidateConnectionEvents3(
    _In_ MsQuicSession& Session,
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    ConnValidator Client(
        new ConnEventValidator* [4] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION, false, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );
    ConnValidator Server(
        new ConnEventValidator* [7] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMED, 0, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_RESUMED, 0, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, 0, false, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        }
    );

    uint32_t CertFlags =
        QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    uint16_t StreamCount = 0; // Temp Work around.
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SERVER_RESUMPTION_LEVEL Level = QUIC_SERVER_RESUME_ONLY;
    QUIC_BUFFER* ResumptionBuffer = (QUIC_BUFFER*) SerializedResumptionStorage;
    ResumptionBuffer->Length = RESUMPTION_BUFFER_LENGTH;
    ResumptionBuffer->Buffer = SerializedResumptionStorage + sizeof(QUIC_BUFFER);

    //
    // Create a connection just to get a resumption ticket.
    //
    MsQuic->SetCallbackHandler(Listener, (void*)ListenerEventResumptionCallback, nullptr);
    Status =
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level),
            &Level);
    TEST_QUIC_SUCCEEDED(Status);

    TestConnection FirstConnection(Session, nullptr);
    FirstConnection.SetCertValidationFlags(CertFlags);
    FirstConnection.SetPeerBidiStreamCount(StreamCount);
    FirstConnection.Start(
        QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
        QUIC_LOCALHOST_FOR_AF(QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
        QuicAddrGetPort(&ServerLocalAddr.SockAddr));
    FirstConnection.WaitForConnectionComplete();
    int i = 0;
    do {
        QuicSleep(100);
        Status =
            FirstConnection.GetResumptionTicket(
                ResumptionBuffer->Buffer,
                &ResumptionBuffer->Length);
    } while (Status != QUIC_STATUS_SUCCESS && i++ < 10);
    TEST_QUIC_SUCCEEDED(Status);
    FirstConnection.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    FirstConnection.WaitForShutdownComplete();

    //
    // Set up the listener for the actual test now.
    //
    MsQuic->SetCallbackHandler(Listener, (void*)ListenerEventValidatorCallback, &Server);

    Level = QUIC_SERVER_NO_RESUME;
    Status =
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level),
            &Level);
    TEST_QUIC_SUCCEEDED(Status);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Session.Handle,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(CertFlags),
            &CertFlags));
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
            sizeof(StreamCount),
            &StreamCount));
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_ADD_RESUMPTION_STATE,
            ResumptionBuffer->Length,
            ResumptionBuffer->Buffer));
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Client.Handle,
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_LOCALHOST_FOR_AF(QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

    TEST_TRUE(QuicEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(QuicEventWaitWithTimeout(Server.Complete, 1000));
}

void QuicTestValidateConnectionEvents()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    Session.SetAutoCleanup();

    { // Listener Scope

    ListenerScope Listener;
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Session.Handle,
            ListenerEventValidatorCallback,
            nullptr,
            &Listener.Handle));
    TEST_QUIC_SUCCEEDED(MsQuic->ListenerStart(Listener.Handle, nullptr));

    QuicAddr ServerLocalAddr;
    uint32_t ServerLocalAddrSize = sizeof(ServerLocalAddr.SockAddr);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LEVEL_LISTENER,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &ServerLocalAddrSize,
            &ServerLocalAddr.SockAddr));

    QuicTestValidateConnectionEvents1(Session.Handle, Listener.Handle, ServerLocalAddr);
    QuicTestValidateConnectionEvents2(Session.Handle, Listener.Handle, ServerLocalAddr);
#ifndef QUIC_DISABLE_0RTT_TESTS
    QuicTestValidateConnectionEvents3(Session, Listener.Handle, ServerLocalAddr);
#endif

    } // Listener Scope
}

void
QuicTestValidateStreamEvents1(
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    Session.SetAutoCleanup();

    { // Connections scope
    ConnValidator Client, Server;

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Session,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    uint32_t CertFlags =
        QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(CertFlags),
            &CertFlags));
    uint16_t StreamCount = 0; // Temp Work around.
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
            sizeof(StreamCount),
            &StreamCount));

    { // Stream scope

    StreamValidator ClientStream(
        new StreamEventValidator* [6] {
            new StreamEventValidator(QUIC_STREAM_EVENT_START_COMPLETE),
            new StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN),
            new StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            nullptr
        });
    StreamValidator ServerStream(
        new StreamEventValidator* [4] {
            new StreamEventValidator(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN, QUIC_EVENT_ACTION_SHUTDOWN_STREAM),
            new StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE),
            new StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });

    Client.SetExpectedEvents(
        new ConnEventValidator* [6] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new ConnEventValidator* [6] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new NewStreamEventValidator(&ServerStream),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
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
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(QuicEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(QuicEventWaitWithTimeout(Server.Complete, 1000));

    } // Stream scope
    } // Connections scope
}

void
QuicTestValidateStreamEvents2(
    _In_ HQUIC Listener,
    _In_ QuicAddr& ServerLocalAddr
    )
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    Session.SetAutoCleanup();

    { // Connections scope
    ConnValidator Client, Server;

    MsQuic->SetContext(Listener, &Server);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionOpen(
            Session.Handle,
            ConnValidatorCallback,
            &Client,
            &Client.Handle));
    uint32_t CertFlags =
        QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(CertFlags),
            &CertFlags));
    uint16_t StreamCount = 0; // Temp Work around.
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Client.Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
            sizeof(StreamCount),
            &StreamCount));

    { // Stream scope

    StreamValidator ClientStream(
        new StreamEventValidator* [5] {
            new StreamEventValidator(QUIC_STREAM_EVENT_START_COMPLETE),
            new StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            new StreamEventValidator(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE),
            new StreamEventValidator(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE, 0, true),
            nullptr
        });

    Client.SetExpectedEvents(
        new ConnEventValidator* [7] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED, QUIC_EVENT_ACTION_SHUTDOWN_CONNECTION),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE, 0, true),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
            nullptr
        });
    Server.SetExpectedEvents(
        new ConnEventValidator* [5] {
            new ConnEventValidator(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_CONNECTED),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER),
            new ConnEventValidator(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE),
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
            QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
            QUIC_LOCALHOST_FOR_AF(
                QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(QuicEventWaitWithTimeout(Client.Complete, 2000));
    TEST_TRUE(QuicEventWaitWithTimeout(Server.Complete, 1000));

    } // Stream scope
    } // Connections scope
}

void QuicTestValidateStreamEvents()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    Session.SetAutoCleanup();

    uint16_t StreamCount = 1;
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT,
            sizeof(StreamCount),
            &StreamCount));

    { // Listener Scope

    ListenerScope Listener;
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Session.Handle,
            ListenerEventValidatorCallback,
            nullptr,
            &Listener.Handle));
    TEST_QUIC_SUCCEEDED(MsQuic->ListenerStart(Listener.Handle, nullptr));

    QuicAddr ServerLocalAddr;
    uint32_t ServerLocalAddrSize = sizeof(ServerLocalAddr.SockAddr);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LEVEL_LISTENER,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &ServerLocalAddrSize,
            &ServerLocalAddr.SockAddr));

    QuicTestValidateStreamEvents1(Listener.Handle, ServerLocalAddr);
    QuicTestValidateStreamEvents2(Listener.Handle, ServerLocalAddr);

    } // Listener Scope
}
