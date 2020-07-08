/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Unittest

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "ApiTest.cpp.clog.h"
#endif

#pragma warning(disable:6387)  // '_Param_(1)' could be '0':  this does not adhere to the specification for the function

void QuicTestValidateApi()
{
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuicOpen(nullptr));

    MsQuicClose(nullptr);

    TEST_FAILURE("Forcing test failure to test CLOG"); // TODO - Remove before merging feature/clog to master
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

    const char RawGoodAlpn[]    = "Alpn";
    const char RawEmptyAlpn[]   = "";
    const char RawLongAlpn[]    = "makethisstringjuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuustright";
    const char RawTooLongAlpn[] = "makethisextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextraextrlong";

    const QUIC_BUFFER GoodAlpn = { sizeof(RawGoodAlpn) - 1, (uint8_t*)RawGoodAlpn };
    const QUIC_BUFFER EmptyAlpn = { sizeof(RawEmptyAlpn) - 1, (uint8_t*)RawEmptyAlpn };
    const QUIC_BUFFER LongAlpn = { sizeof(RawLongAlpn) - 1, (uint8_t*)RawLongAlpn };
    const QUIC_BUFFER TooLongAlpn = { sizeof(RawTooLongAlpn) - 1, (uint8_t*)RawTooLongAlpn };

    //
    // Test null out param.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            TestReg,
            &GoodAlpn,
            1,
            nullptr,
            nullptr));

    //
    // Null registration.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            nullptr,
            &GoodAlpn,
            1,
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
            0,
            nullptr,
            &Session));

    //
    // Empty ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SessionOpen(
            TestReg,
            &EmptyAlpn,
            1,
            nullptr,
            &Session));

    //
    // 255-byte ALPN.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->SessionOpen(
            TestReg,
            &LongAlpn,
            1,
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
            &TooLongAlpn,
            1,
            nullptr,
            &Session));

    //
    // Multiple ALPNs
    //
    const QUIC_BUFFER TwoAlpns[] = {
        { sizeof("alpn1") - 1, (uint8_t*)"alpn1" },
        { sizeof("alpn2") - 1, (uint8_t*)"alpn2" }
    };
    TEST_QUIC_SUCCEEDED(
        MsQuic->SessionOpen(
            TestReg,
            TwoAlpns,
            2,
            nullptr,
            &Session));

    MsQuic->SessionClose(
        Session);
    Session = nullptr;

    //
    // Can't call SessionClose with invalid values as MsQuic asserts
    // (on purpose).
    //

    TEST_QUIC_SUCCEEDED(
        MsQuic->SessionOpen(
            TestReg,
            &GoodAlpn,
            1,
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

#ifndef QUIC_DISABLE_0RTT_TESTS
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

    //
    // Server resumption level - invalid level
    //
    QUIC_SERVER_RESUMPTION_LEVEL Level = (QUIC_SERVER_RESUMPTION_LEVEL) 0xff;
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level),
            nullptr));

    //
    // Server resumption level - Invalid length
    //
    Level = QUIC_SERVER_RESUME_ONLY;
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            0,
            &Level));

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level) - 1,
            &Level));

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level) + 1,
            &Level));

    //
    // Server resumption level - NULL level
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level),
            nullptr));

    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(Level),
            &Level));

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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    HQUIC Listener = nullptr;

    //
    // Null listener callback handler.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ListenerOpen(
            Session,
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
            Session,
            DummyListenerCallback,
            nullptr,
            nullptr));

    //
    // Stop before start.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Session,
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
            Session,
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
            Session,
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
            Session,
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

#ifndef QUIC_DISABLE_0RTT_TESTS
static
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
AutoShutdownConnectionCallback(
    HQUIC Connection,
    void* Context,
    QUIC_CONNECTION_EVENT* Event
    )
{
    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
        if (Context != nullptr) {
            if (!QuicEventWaitWithTimeout(*(QUIC_EVENT*)Context, 1000)) {
                TEST_FAILURE("Peer never signaled connected event");
            }
        }
        MsQuic->ConnectionShutdown(
            Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            0);
    }
    return QUIC_STATUS_SUCCESS;
}

static
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ResumptionFailConnectionCallback(
    HQUIC Connection,
    void* Context,
    QUIC_CONNECTION_EVENT* Event
    )
{
    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
        QUIC_STATUS Status =
            MsQuic->ConnectionSendResumptionTicket(
                Connection,
                QUIC_SEND_RESUMPTION_FLAG_NONE,
                0,
                nullptr);
        if (Status != QUIC_STATUS_INVALID_STATE) {
            TEST_FAILURE(
                "ConnectionSendResumptionTicket has unexpected error! Expected 0x%x, actual 0x%x",
                QUIC_STATUS_INVALID_STATE,
                Status);
        }
        QuicEventSet(*(QUIC_EVENT*)Context);
        return QUIC_STATUS_SUCCESS;
    } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
        MsQuic->ConnectionClose(Connection);
        return QUIC_STATUS_SUCCESS;
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
void
ListenerFailSendResumeCallback(
    _In_ TestListener*  Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    //
    // Validate sending the resumption ticket fails
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_STATE,
        MsQuic->ConnectionSendResumptionTicket(
            ConnectionHandle,
            QUIC_SEND_RESUMPTION_FLAG_NONE,
            0,
            nullptr));
    MsQuic->SetCallbackHandler(ConnectionHandle, (void*)ResumptionFailConnectionCallback, Listener->Context);
    QuicEventSet(*(QUIC_EVENT*)Listener->Context);
}
#endif

void QuicTestValidateConnection()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    //
    // Null out-parameter.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConnectionOpen(
            Session,
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
                Session,
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
                Session,
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
                Session,
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
                Session,
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
                Session,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_INET,
                "localhost",
                4433));

        //
        // If ConnectionStart is called immediately for a second time, it will
        // likely succeed because the previous one was queued up. It would
        // instead eventually fail asynchronously. Instead, this test case
        // waits a bit to allow for the previous command to be processed so
        // that the second call will fail inline.
        //
        QuicSleep(100);

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            MsQuic->ConnectionStart(
                Connection.Handle,
                AF_INET,
                "localhost",
                4433));
    }

    //
    // Shutdown connection and then start. Make sure there is no crash.
    // Depending on the timing it's possible for the ConnectionStart call to
    // either fail or succeed. This test case doesn't care about the result,
    // just that no crash results because of this.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Session,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        MsQuic->ConnectionShutdown(
            Connection.Handle,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            QUIC_TEST_NO_ERROR);

        MsQuic->ConnectionStart(
            Connection.Handle,
            AF_INET,
            "localhost",
            4433);
    }

    //
    // Shutdown connection twice
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Session,
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

    //
    // Invalid datagram send calls.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Session,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        uint8_t RawBuffer[] = "datagram";
        QUIC_BUFFER DatagramBuffer = { sizeof(RawBuffer), RawBuffer };

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->DatagramSend(
                Connection.Handle,
                nullptr,
                1,
                QUIC_SEND_FLAG_NONE,
                nullptr));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->DatagramSend(
                Connection.Handle,
                &DatagramBuffer,
                0,
                QUIC_SEND_FLAG_NONE,
                nullptr));
    }

    //
    // Successful send datagram calls.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Session,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        uint8_t RawBuffer[] = "datagram";
        QUIC_BUFFER DatagramBuffer = { sizeof(RawBuffer), RawBuffer };

        TEST_QUIC_SUCCEEDED(
            MsQuic->DatagramSend(
                Connection.Handle,
                &DatagramBuffer,
                1,
                QUIC_SEND_FLAG_NONE,
                nullptr));
    }

    //
    // Successful set datagram receive parameter.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Session,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        BOOLEAN ReceiveDatagrams = TRUE;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Connection.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                sizeof(ReceiveDatagrams),
                &ReceiveDatagrams));

        ReceiveDatagrams = FALSE;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Connection.Handle,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                sizeof(ReceiveDatagrams),
                &ReceiveDatagrams));
    }

    //
    // Invalid send resumption.
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Session,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        //
        // NULL connection handle.
        //
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionSendResumptionTicket(
                nullptr,
                QUIC_SEND_RESUMPTION_FLAG_NONE,
                0,
                nullptr));

        //
        // Can only be called on server Connections.
        //
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionSendResumptionTicket(
                Connection.Handle,
                QUIC_SEND_RESUMPTION_FLAG_NONE,
                0,
                nullptr));

        //
        // Validate flags are within range.
        //
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionSendResumptionTicket(
                Connection.Handle,
                (QUIC_SEND_RESUMPTION_FLAGS)4,
                0,
                nullptr));
    }

    //
    // Invalid send resumption, server-side
    // Some of these cases require an actual connection to succeed, so
    // they won't work on Schannel in AZP.
    // Currently disabling these test cases for TLS platforms without 0-RTT.
    //
#ifndef QUIC_DISABLE_0RTT_TESTS
    {
        TestListener MyListener(Session, ListenerFailSendResumeCallback);
        TEST_TRUE(MyListener.IsValid());

        TEST_QUIC_SUCCEEDED(MyListener.Start());
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(MyListener.GetLocalAddr(ServerLocalAddr));

        QUIC_EVENT Event;
        QuicEventInitialize(&Event, FALSE, FALSE);
        MyListener.Context = &Event;

        {
            //
            // Validate that the resumption ticket call fails in the listener.
            //
            ConnectionScope Connection;
            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionOpen(
                    Session,
                    AutoShutdownConnectionCallback,
                    nullptr,
                    &Connection.Handle));

            const uint64_t IdleTimeout = 1000;
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection.Handle,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_IDLE_TIMEOUT,
                    sizeof(IdleTimeout),
                    &IdleTimeout));

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_LOCALHOST_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            TEST_TRUE(QuicEventWaitWithTimeout(Event, 1000));

            MsQuic->ConnectionClose(Connection.Handle);

            //
            // Ensure sending a resumption ticket fails even when connected
            // because resumption is not enabled.
            //
            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionOpen(
                    Session,
                    AutoShutdownConnectionCallback,
                    &Event,
                    &Connection.Handle));

            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection.Handle,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_IDLE_TIMEOUT,
                    sizeof(IdleTimeout),
                    &IdleTimeout));

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_LOCALHOST_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            TEST_TRUE(QuicEventWaitWithTimeout(Event, 1000));

            MsQuic->ConnectionClose(Connection.Handle);

            //
            // Enable resumption but ensure failure because the connection 
            // isn't in connected state yet.
            //

            QUIC_SERVER_RESUMPTION_LEVEL Level = QUIC_SERVER_RESUME_ONLY;
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Session.Handle,
                    QUIC_PARAM_LEVEL_SESSION,
                    QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
                    sizeof(Level),
                    &Level));

            //
            // Give time for the parameter to get set.
            //
            QuicSleep(100);

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionOpen(
                    Session,
                    AutoShutdownConnectionCallback,
                    nullptr,
                    &Connection.Handle));

            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection.Handle,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_IDLE_TIMEOUT,
                    sizeof(IdleTimeout),
                    &IdleTimeout));

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_LOCALHOST_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            TEST_TRUE(QuicEventWaitWithTimeout(Event, 1000));

            //
            // TODO: add test case to validate ConnectionSendResumptionTicket:
            // * succeeds when resumption is enabled and once connected.
            //
        }

        QuicEventUninitialize(Event);
    }
#endif
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
    *NewConnection = new TestConnection(ConnectionHandle);
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
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    TEST_QUIC_SUCCEEDED(Session.SetPeerBidiStreamCount(32));

    QUIC_BUFFER Buffers[1] = {};

    //
    // Force the Client, Server, and Listener to clean up before the Session and Registration.
    //
    {
        TestListener MyListener(Session, ListenerAcceptCallback);
        TEST_TRUE(MyListener.IsValid());

        UniquePtr<TestConnection> Server;
        MyListener.Context = &Server;

        {
            TestConnection Client(Session);
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
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                        QUIC_LOCALHOST_FOR_AF(
                            QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                        ServerLocalAddr.GetPort()));

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
                QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
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
