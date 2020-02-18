/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Unittest

--*/

#include "precomp.h"

#pragma warning(disable:6387)  // '_Param_(1)' could be '0':  this does not adhere to the specification for the function

void QuicTestValidateApi()
{
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuicOpenV1(nullptr));

    QUIC_API_V1* BadVersion = nullptr;
    TEST_QUIC_STATUS(
        QUIC_STATUS_NOT_SUPPORTED,
        MsQuicOpen(0, (void**)&BadVersion));

    TEST_QUIC_STATUS(
        QUIC_STATUS_NOT_SUPPORTED,
        MsQuicOpen(QUIC_API_VERSION_1 + 1, (void**)&BadVersion));

    TEST_QUIC_STATUS(
        QUIC_STATUS_NOT_SUPPORTED,
        MsQuicOpen(0xFFFFFFFF, (void**)&BadVersion));

    MsQuicClose(nullptr);
}

void QuicTestValidateRegistration()
{
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->RegistrationOpen(nullptr, nullptr));

    MsQuic->RegistrationClose(nullptr);
}

void QuicTestValidateSession()
{
    MsQuicRegistration TestReg;
    TEST_TRUE(TestReg.IsValid());

    HQUIC Session = nullptr;

    //
    // Test null out param.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            TestReg,
            "alpn",
            nullptr,
            nullptr));

    //
    // Null registration.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            nullptr,
            "alpn",
            nullptr,
            &Session));

    //
    // Null ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            TestReg,
            nullptr,
            nullptr,
            &Session));

    //
    // Empty ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            TestReg,
            "",
            nullptr,
            &Session));

    //
    // 255-byte ALPN.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->SessionOpen(
            TestReg,
            "makethisstringjuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuustright",
            nullptr,
            &Session));

    MsQuic->SessionClose(
        Session);
    Session = nullptr;

    //
    // 256-byte ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            TestReg,
            "makethisextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextrlong",
            nullptr,
            &Session));

    //
    // Can't call SessionClose with invalid values as MsQuic asserts
    // (on purpose).
    //

    TEST_QUIC_SUCCEEDED(
        MsQuic->SessionOpen(
            TestReg,
            "test",
            nullptr,
            &Session));

    uint8_t TicketKey[44] = {0};

    //
    // NULL Ticket.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_TLS_TICKET_KEY,
            0,
            NULL));

    //
    // Invalid length.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_TLS_TICKET_KEY,
            0,
            TicketKey));
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_TLS_TICKET_KEY,
            1,
            TicketKey));
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_TLS_TICKET_KEY,
            sizeof(TicketKey) - 1,
            TicketKey));

#ifndef QUIC_DISABLE_0RTT
    //
    // Valid 0-RTT ticket encryption key.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_TLS_TICKET_KEY,
            sizeof(TicketKey),
            TicketKey));
#endif

    MsQuic->SessionClose(
        Session);
    Session = nullptr;
}

static
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
DummyListenerCallback(
    HQUIC,
    void*,
    QUIC_LISTENER_EVENT*
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

void QuicTestValidateListener()
{
    MsQuicSession TestSession;
    TEST_TRUE(TestSession.IsValid());

    HQUIC Listener = nullptr;

    //
    // Null listener callback handler.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ListenerOpen(
            TestSession,
            nullptr,
            nullptr,
            &Listener));

    //
    // Null session.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ListenerOpen(
            nullptr,
            DummyListenerCallback,
            nullptr,
            &Listener));

    //
    // Null out parameter.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ListenerOpen(
            TestSession,
            DummyListenerCallback,
            nullptr,
            nullptr));

    //
    // Stop before start.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            TestSession,
            DummyListenerCallback,
            nullptr,
            &Listener));

    MsQuic->ListenerStop(Listener);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            nullptr));

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Close before stop.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            TestSession,
            DummyListenerCallback,
            nullptr,
            &Listener));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            nullptr));

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Start twice.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            TestSession,
            DummyListenerCallback,
            nullptr,
            &Listener));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            nullptr));

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_STATE,
        MsQuic->ListenerStart(
            Listener,
            nullptr));

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Stop twice.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            TestSession,
            DummyListenerCallback,
            nullptr,
            &Listener));

    MsQuic->ListenerStop(Listener);

    MsQuic->ListenerStop(Listener);

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Null handle to close.
    //
    MsQuic->ListenerClose(nullptr);
}

static
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
DummyConnectionCallback(
    HQUIC,
    void*,
    QUIC_CONNECTION_EVENT*
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

void QuicTestValidateConnection()
{
    MsQuicSession TestSession;
    TEST_TRUE(TestSession.IsValid());

    //
    // Null out-parameter.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConnectionOpen(
            TestSession,
            DummyConnectionCallback,
            nullptr,
            nullptr));

    //
    // Null Callback-parameter.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionOpen(
                TestSession,
                nullptr,
                nullptr,
                &Connection.Handle));
    }

    //
    // Null session parameter.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionOpen(
                nullptr,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));
    }

    //
    // Null connection parameter.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConnectionStart(
            nullptr,
            AF_INET,
            "localhost",
            4433));

    //
    // Bad address family
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                TestSession,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_MAX,
                "localhost",
                4433));
    }

    //
    // Null server name
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                TestSession,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_INET,
                nullptr,
                4433));
    }

    //
    // Bad port.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                TestSession,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_INET,
                "localhost",
                0));
    }

    //
    // Start connection twice
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                TestSession,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_INET,
                "localhost",
                4433));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_INET,
                "localhost",
                4433));
    }

    //
    // Shutdown connection twice
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                TestSession,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        MsQuic->ConnectionShutdown(
            Connection.Handle,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            QUIC_TEST_NO_ERROR);

        MsQuic->ConnectionShutdown(
            Connection.Handle,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            QUIC_TEST_NO_ERROR);
    }

    //
    // ConnectionShutdown null handle.
    //
    MsQuic->ConnectionShutdown(
        nullptr,
        QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
        QUIC_TEST_NO_ERROR);

    //
    // ConnectionClose null handle.
    //
    MsQuic->ConnectionClose(nullptr);
}

_Function_class_(NEW_STREAM_CALLBACK)
static
void
ConnectionIgnoreStreamCallback(
    _In_ TestConnection* /* Connection */,
    _In_ HQUIC Stream,
    _In_ QUIC_STREAM_OPEN_FLAGS /* Flags */
    )
{
    MsQuic->StreamClose(Stream);
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
void
ListenerAcceptCallback(
    _In_ TestListener*  Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    TestConnection** NewConnection = (TestConnection**)Listener->Context;
    *NewConnection = new TestConnection(ConnectionHandle, ConnectionIgnoreStreamCallback, true);
    if (*NewConnection == nullptr || !(*NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *NewConnection;
        MsQuic->ConnectionClose(ConnectionHandle);
    }
}

_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
DummyStreamCallback(
    _In_ HQUIC /*Stream*/,
    _In_opt_ void* /*Context*/,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {

    case QUIC_STREAM_EVENT_RECEIVE:
        TEST_FAILURE("QUIC_STREAM_EVENT_RECEIVE should never be called!");
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        TEST_FAILURE("QUIC_STREAM_EVENT_SEND_COMPLETE should never be called!");
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void QuicTestValidateStream(bool Connect)
{
    MsQuicSession TestSession;
    TEST_TRUE(TestSession.IsValid());
    TEST_QUIC_SUCCEEDED(TestSession.SetPeerBidiStreamCount(32));

    QUIC_BUFFER Buffers[1] = {};

    //
    // Force the Client, Server, and Listener to clean up before the Session and Registration.
    //
    {
        TestListener MyListener(TestSession, ListenerAcceptCallback);
        TEST_TRUE(MyListener.IsValid());

        UniquePtr<TestConnection> Server;
        MyListener.Context = &Server;

        {
            TestConnection Client(TestSession, ConnectionIgnoreStreamCallback, false);
            TEST_TRUE(Client.IsValid());
            if (Connect) {
                TEST_QUIC_SUCCEEDED(MyListener.Start());
                QuicAddr ServerLocalAddr;
                TEST_QUIC_SUCCEEDED(MyListener.GetLocalAddr(ServerLocalAddr));

                //
                // Start client connection.
                //
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ServerLocalAddr.SockAddr.si_family,
                        QUIC_LOCALHOST_FOR_AF(ServerLocalAddr.SockAddr.si_family),
                        QuicAddrGetPort(&ServerLocalAddr.SockAddr)));

                //
                // Wait for connection.
                //
                TEST_TRUE(Client.WaitForConnectionComplete());
                TEST_TRUE(Client.GetIsConnected());

                TEST_NOT_EQUAL(nullptr, Server);
                TEST_TRUE(Server->WaitForConnectionComplete());
                TEST_TRUE(Server->GetIsConnected());
            }

            //
            // Null connection.
            //
            {
                StreamScope Stream;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->StreamOpen(
                        nullptr,
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));
            }

            //
            // Null handler.
            //
            {
                StreamScope Stream;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        nullptr,
                        nullptr,
                        &Stream.Handle));
            }

            //
            // Null out-parameter.
            //
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->StreamOpen(
                    Client.GetConnection(),
                    QUIC_STREAM_OPEN_FLAG_NONE,
                    DummyStreamCallback,
                    nullptr,
                    nullptr));

            //
            // Fail on blocked.
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));
                if (Connect) {
                    TEST_QUIC_SUCCEEDED(
                        MsQuic->StreamStart(
                            Stream.Handle,
                            QUIC_STREAM_START_FLAG_FAIL_BLOCKED));
                } else {
                    TEST_QUIC_STATUS(
                        QUIC_STATUS_BUFFER_TOO_SMALL,
                        MsQuic->StreamStart(
                            Stream.Handle,
                            QUIC_STREAM_START_FLAG_FAIL_BLOCKED));
                }
            }

            //
            // Null stream handle.
            //
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->StreamSend(
                    nullptr,
                    Buffers,
                    ARRAYSIZE(Buffers),
                    QUIC_SEND_FLAG_NONE,
                    nullptr));

            //
            // Never started (close).
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));
            }

            //
            // Never started (shutdown graceful).
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamShutdown(
                        Stream.Handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                        0));
            }

            //
            // Never started (shutdown abortive).
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamShutdown(
                        Stream.Handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                        0));
            }

            //
            // Null buffer.
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->StreamSend(
                        Stream.Handle,
                        nullptr,
                        ARRAYSIZE(Buffers),
                        QUIC_SEND_FLAG_NONE,
                        nullptr));
            }

            //
            // Zero buffers.
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->StreamSend(
                        Stream.Handle,
                        Buffers,
                        0,
                        QUIC_SEND_FLAG_NONE,
                        nullptr));
            }

            //
            // Send on shutdown stream.
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                // TODO: try this for each flag type
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamShutdown(
                        Stream.Handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                        QUIC_TEST_NO_ERROR));

                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->StreamSend(
                        Stream.Handle,
                        Buffers,
                        ARRAYSIZE(Buffers),
                        QUIC_SEND_FLAG_NONE,
                        nullptr));
            }

            //
            // Double-shutdown stream.
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamShutdown(
                        Stream.Handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                        QUIC_TEST_NO_ERROR));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamShutdown(
                        Stream.Handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                        QUIC_TEST_NO_ERROR));
            }

            //
            // Shutdown null handle.
            //
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->StreamShutdown(
                    nullptr,
                    QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                    QUIC_TEST_NO_ERROR));

            //
            // Shutdown no flags.
            //
            {
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        DummyStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->StreamShutdown(
                        Stream.Handle,
                        QUIC_STREAM_SHUTDOWN_FLAG_NONE,
                        QUIC_TEST_NO_ERROR));
            }

            //
            // Close nullptr.
            //
            MsQuic->StreamClose(nullptr);
        }
    }
}

class SecConfigTestContext {
public:
    QUIC_EVENT Event;
    QUIC_STATUS Expected;
    bool Failed;

    SecConfigTestContext() : Expected(0), Failed(false)
    {
        QuicEventInitialize(&Event, FALSE, FALSE);
    }
    ~SecConfigTestContext()
    {
        QuicEventUninitialize(Event);
    }
};

void static
QuicTestValidateSecConfig(
    _In_ SecConfigTestContext* ctxt,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
{
    TEST_QUIC_STATUS(ctxt->Expected, Status);

    if (ctxt->Expected == QUIC_STATUS_SUCCESS) {
        TEST_TRUE(SecConfig != nullptr);
    }

    ctxt->Failed = false;
}

_Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
void static
QUIC_API
QuicTestSecConfigCreateComplete(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
{
    _Analysis_assume_(Context != NULL);
    SecConfigTestContext* ctxt = (SecConfigTestContext*) Context;

    ctxt->Failed = true;
    QuicTestValidateSecConfig(ctxt, Status, SecConfig);

    //
    // If SecurityConfig is non-null, Delete the security config.
    //
    if (SecurityConfig != nullptr) {
        MsQuic->SecConfigDelete(SecConfig);
    }

    //
    // Finally, signal event in Context to allow test to continue.
    //
    QuicEventSet(ctxt->Event);
}

void QuicTestValidateServerSecConfig(void* CertContext, QUIC_CERTIFICATE_HASH_STORE* CertHashStore, char* Principal)
{
    MsQuicRegistration TestReg;
    TEST_TRUE(TestReg.IsValid());

    SecConfigTestContext TestContext;

    //
    // Test null inputs.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SecConfigCreate(
            TestReg,
            QUIC_SEC_CONFIG_FLAG_NONE,
            nullptr,    // Certificate
            nullptr,    // Principal
            &TestContext,
            QuicTestSecConfigCreateComplete));

    if (CertContext != nullptr) {
        //
        // Test certificate context.
        //
        TestContext.Expected = QUIC_STATUS_SUCCESS;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SecConfigCreate(
                TestReg,
                QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT,
                CertContext,                // Certificate
                nullptr,                    // Principal
                &TestContext,
                QuicTestSecConfigCreateComplete));

        TEST_TRUE(QuicEventWaitWithTimeout(TestContext.Event, TestWaitTimeout));
        TEST_FALSE(TestContext.Failed);
    }

    if (Principal != nullptr) {
        //
        // Test certificate principal.
        //
        TestContext.Expected = QUIC_STATUS_SUCCESS;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SecConfigCreate(
                TestReg,
                QUIC_SEC_CONFIG_FLAG_NONE,
                nullptr,                    // Certificate
                Principal,                  // Principal
                &TestContext,
                QuicTestSecConfigCreateComplete));

        TEST_TRUE(QuicEventWaitWithTimeout(TestContext.Event, TestWaitTimeout));
        TEST_FALSE(TestContext.Failed);
    }

    if (CertHashStore != nullptr) {
        //
        // Test certificate hash.
        //
        TEST_QUIC_SUCCEEDED(
            MsQuic->SecConfigCreate(
                TestReg,
                QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
                &CertHashStore->ShaHash,        // Certificate
                nullptr,                        // Principal
                &TestContext,
                QuicTestSecConfigCreateComplete));

        TEST_TRUE(QuicEventWaitWithTimeout(TestContext.Event, TestWaitTimeout));
        TEST_FALSE(TestContext.Failed);

        //
        // Test certificate hash + store.
        //
        TEST_QUIC_SUCCEEDED(
            MsQuic->SecConfigCreate(
                TestReg,
                QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE,
                CertHashStore,                          // Certificate
                nullptr,                                // Principal
                &TestContext,
                QuicTestSecConfigCreateComplete));

        TEST_TRUE(QuicEventWaitWithTimeout(TestContext.Event, TestWaitTimeout));
        TEST_FALSE(TestContext.Failed);
    }
}
