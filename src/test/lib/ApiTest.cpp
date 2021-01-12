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
}

void QuicTestValidateRegistration()
{
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->RegistrationOpen(nullptr, nullptr));

    MsQuic->RegistrationClose(nullptr);
}

void QuicTestValidateConfiguration()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    HQUIC LocalConfiguration = nullptr;

    QUIC_SETTINGS EmptySettings{0};

    QUIC_SETTINGS GoodSettings{0};
    GoodSettings.IdleTimeoutMs = 30000;
    GoodSettings.IsSet.IdleTimeoutMs = TRUE;

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
        MsQuic->ConfigurationOpen(
            Registration,
            &GoodAlpn,
            1,
            nullptr,
            0,
            nullptr,
            nullptr));

    //
    // Null registration.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConfigurationOpen(
            nullptr,
            &GoodAlpn,
            1,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    //
    // Null settings.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConfigurationOpen(
            Registration,
            &GoodAlpn,
            1,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    MsQuic->ConfigurationClose(
        LocalConfiguration);
    LocalConfiguration = nullptr;

    //
    // Empty settings.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConfigurationOpen(
            Registration,
            &GoodAlpn,
            1,
            &EmptySettings,
            sizeof(EmptySettings),
            nullptr,
            &LocalConfiguration));

    MsQuic->ConfigurationClose(
        LocalConfiguration);
    LocalConfiguration = nullptr;

    //
    // Good settings.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConfigurationOpen(
            Registration,
            &GoodAlpn,
            1,
            &GoodSettings,
            sizeof(GoodSettings),
            nullptr,
            &LocalConfiguration));

    MsQuic->ConfigurationClose(
        LocalConfiguration);
    LocalConfiguration = nullptr;

    //
    // Invalid settings - TODO
    //

    //
    // Null ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConfigurationOpen(
            Registration,
            nullptr,
            0,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    //
    // Empty ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConfigurationOpen(
            Registration,
            &EmptyAlpn,
            1,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    //
    // 255-byte ALPN.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConfigurationOpen(
            Registration,
            &LongAlpn,
            1,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    MsQuic->ConfigurationClose(
        LocalConfiguration);
    LocalConfiguration = nullptr;

    //
    // 256-byte ALPN.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConfigurationOpen(
            Registration,
            &TooLongAlpn,
            1,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    //
    // Multiple ALPNs
    //
    const QUIC_BUFFER TwoAlpns[] = {
        { sizeof("alpn1") - 1, (uint8_t*)"alpn1" },
        { sizeof("alpn2") - 1, (uint8_t*)"alpn2" }
    };
    TEST_QUIC_SUCCEEDED(
        MsQuic->ConfigurationOpen(
            Registration,
            TwoAlpns,
            2,
            nullptr,
            0,
            nullptr,
            &LocalConfiguration));

    MsQuic->ConfigurationClose(
        LocalConfiguration);
    LocalConfiguration = nullptr;

    //
    // TODO - ConfigurationLoad?
    //
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
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration LocalConfiguration(Registration, Alpn);
    TEST_TRUE(LocalConfiguration.IsValid());

    HQUIC Listener = nullptr;

    //
    // Null listener callback handler.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ListenerOpen(
            Registration,
            nullptr,
            nullptr,
            &Listener));

    //
    // Null registration.
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
            Registration,
            DummyListenerCallback,
            nullptr,
            nullptr));

    //
    // Stop before start.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback,
            nullptr,
            &Listener));

    MsQuic->ListenerStop(Listener);

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Close before stop.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback,
            nullptr,
            &Listener));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Start twice.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback,
            nullptr,
            &Listener));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_STATE,
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    MsQuic->ListenerClose(Listener);
    Listener = nullptr;

    //
    // Stop twice.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
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
            if (!CxPlatEventWaitWithTimeout(*(CXPLAT_EVENT*)Context, 1000)) {
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
        CxPlatEventSet(*(CXPLAT_EVENT*)Context);
        return QUIC_STATUS_SUCCESS;
    } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
        MsQuic->ConnectionClose(Connection);
        return QUIC_STATUS_SUCCESS;
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerFailSendResumeCallback(
    _In_ TestListener*  Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    //
    // Validate sending the resumption ticket fails
    //
    QUIC_STATUS Status =
        MsQuic->ConnectionSendResumptionTicket(
            ConnectionHandle,
            QUIC_SEND_RESUMPTION_FLAG_NONE,
            0,
            nullptr);
    if (Status != QUIC_STATUS_INVALID_STATE) {
        TEST_FAILURE(
            "ConnectionSendResumptionTicket has unexpected error! Expected 0x%x, actual 0x%x",
            QUIC_STATUS_INVALID_STATE,
            Status);
        return false;
    }
    MsQuic->SetCallbackHandler(ConnectionHandle, (void*)ResumptionFailConnectionCallback, Listener->Context);
    CxPlatEventSet(*(CXPLAT_EVENT*)Listener->Context);
    return true;
}
#endif

void QuicTestValidateConnection()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY);
    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    Settings.SetIdleTimeoutMs(1000);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    //
    // Null out-parameter.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ConnectionOpen(
            Registration,
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
                Registration,
                nullptr,
                nullptr,
                &Connection.Handle));
    }

    //
    // Null registration parameter.
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
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "localhost",
            4433));

    //
    // Bad address family
    //
    {
        ConnectionScope Connection;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionOpen(
                Registration,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                Connection.Handle,
                ClientConfiguration,
                127,
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
                Registration,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                Connection.Handle,
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
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
                Registration,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                Connection.Handle,
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
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
                Registration,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionStart(
                Connection.Handle,
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
                "localhost",
                4433));

        //
        // If ConnectionStart is called immediately for a second time, it will
        // likely succeed because the previous one was queued up. It would
        // instead eventually fail asynchronously. Instead, this test case
        // waits a bit to allow for the previous command to be processed so
        // that the second call will fail inline.
        //
        CxPlatSleep(500);

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            MsQuic->ConnectionStart(
                Connection.Handle,
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
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
                Registration,
                DummyConnectionCallback,
                nullptr,
                &Connection.Handle));

        MsQuic->ConnectionShutdown(
            Connection.Handle,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            QUIC_TEST_NO_ERROR);

        MsQuic->ConnectionStart(
            Connection.Handle,
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
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
                Registration,
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
                Registration,
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
                Registration,
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
                Registration,
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
                Registration,
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
        TestListener MyListener(Registration, ListenerFailSendResumeCallback, ServerConfiguration);
        TEST_TRUE(MyListener.IsValid());

        TEST_QUIC_SUCCEEDED(MyListener.Start(Alpn, Alpn.Length()));
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(MyListener.GetLocalAddr(ServerLocalAddr));

        CXPLAT_EVENT Event;
        CxPlatEventInitialize(&Event, FALSE, FALSE);
        MyListener.Context = &Event;

        {
            //
            // Validate that the resumption ticket call fails in the listener.
            //
            ConnectionScope Connection;
            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionOpen(
                    Registration,
                    AutoShutdownConnectionCallback,
                    nullptr,
                    &Connection.Handle));

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    ClientConfiguration,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_LOCALHOST_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            TEST_TRUE(CxPlatEventWaitWithTimeout(Event, 1000));

            MsQuic->ConnectionClose(Connection.Handle);

            //
            // Ensure sending a resumption ticket fails even when connected
            // because resumption is not enabled.
            //
            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionOpen(
                    Registration,
                    AutoShutdownConnectionCallback,
                    &Event,
                    &Connection.Handle));

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    ClientConfiguration,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_LOCALHOST_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            TEST_TRUE(CxPlatEventWaitWithTimeout(Event, 1000));

            MsQuic->ConnectionClose(Connection.Handle);

            //
            // Enable resumption but ensure failure because the connection
            // isn't in connected state yet.
            //

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionOpen(
                    Registration,
                    AutoShutdownConnectionCallback,
                    nullptr,
                    &Connection.Handle));

            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    ClientConfiguration,
                    QuicAddrGetFamily(&ServerLocalAddr.SockAddr),
                    QUIC_LOCALHOST_FOR_AF(
                        QuicAddrGetFamily(&ServerLocalAddr.SockAddr)),
                    ServerLocalAddr.GetPort()));

            TEST_TRUE(CxPlatEventWaitWithTimeout(Event, 1000));

            //
            // TODO: add test case to validate ConnectionSendResumptionTicket:
            // * succeeds when resumption is enabled and once connected.
            //
        }

        CxPlatEventUninitialize(Event);
    }
#endif
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerAcceptCallback(
    _In_ TestListener*  Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    TestConnection** NewConnection = (TestConnection**)Listener->Context;
    *NewConnection = new(std::nothrow) TestConnection(ConnectionHandle);
    if (*NewConnection == nullptr || !(*NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *NewConnection;
        return false;
    }
    return true;
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
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(32);
    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, SelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_BUFFER Buffers[1] = {};

    //
    // Force the Client, Server, and Listener to clean up before the Registration.
    //
    {
        TestListener MyListener(Registration, ListenerAcceptCallback, ServerConfiguration);
        TEST_TRUE(MyListener.IsValid());

        UniquePtr<TestConnection> Server;
        MyListener.Context = &Server;

        {
            TestConnection Client(Registration);
            TEST_TRUE(Client.IsValid());
            if (Connect) {
                TEST_QUIC_SUCCEEDED(MyListener.Start(Alpn, Alpn.Length()));
                QuicAddr ServerLocalAddr;
                TEST_QUIC_SUCCEEDED(MyListener.GetLocalAddr(ServerLocalAddr));

                //
                // Start client connection.
                //
                TEST_QUIC_SUCCEEDED(
                    Client.Start(
                        ClientConfiguration,
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
    CXPLAT_EVENT Event;
    QUIC_STATUS Expected;
    bool Failed;

    SecConfigTestContext() : Expected(0), Failed(false)
    {
        CxPlatEventInitialize(&Event, FALSE, FALSE);
    }
    ~SecConfigTestContext()
    {
        CxPlatEventUninitialize(Event);
    }
};

void
QuicTestGetPerfCounters()
{
    //
    // Test getting the correct size.
    //
    uint32_t BufferLength = 0;
    TEST_EQUAL(
        MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_PERF_COUNTERS,
            &BufferLength,
            nullptr),
        QUIC_STATUS_BUFFER_TOO_SMALL);

    TEST_EQUAL(BufferLength, sizeof(uint64_t) * QUIC_PERF_COUNTER_MAX);

    //
    // Test getting the full array of counters.
    //
    uint64_t Counters[QUIC_PERF_COUNTER_MAX];
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_PERF_COUNTERS,
            &BufferLength,
            Counters));

    //
    // Test a smaller buffer will be rounded to the nearest counter and filled.
    //
    BufferLength = (sizeof(uint64_t) * (QUIC_PERF_COUNTER_MAX - 4)) + 1;
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_PERF_COUNTERS,
            &BufferLength,
            Counters));

    TEST_EQUAL(BufferLength, (sizeof(uint64_t) * (QUIC_PERF_COUNTER_MAX - 4)));
}
