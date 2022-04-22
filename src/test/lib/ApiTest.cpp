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
        MsQuicOpen2(nullptr));

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
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConfigurationOpen(
                nullptr,
                &GoodAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // Null settings.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &GoodAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // Empty settings.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &GoodAlpn,
                1,
                &EmptySettings,
                sizeof(EmptySettings),
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // Good settings.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &GoodAlpn,
                1,
                &GoodSettings,
                sizeof(GoodSettings),
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // Invalid settings - TODO
    //

    //
    // Null ALPN.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConfigurationOpen(
                Registration,
                nullptr,
                0,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // Empty ALPN.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConfigurationOpen(
                Registration,
                &EmptyAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // 255-byte ALPN.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &LongAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // 256-byte ALPN.
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConfigurationOpen(
                Registration,
                &TooLongAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));
    }

    //
    // Multiple ALPNs
    //
    {
        ConfigurationScope LocalConfiguration;
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
                &LocalConfiguration.Handle));
    }

    //
    // ConfigurationLoad
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &GoodAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationLoadCredential(
                LocalConfiguration,
                &ServerSelfSignedCredConfig));
    }

#ifndef QUIC_DISABLE_TICKET_KEY_TESTS
    //
    // Set Ticket Key (single)
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &GoodAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationLoadCredential(
                LocalConfiguration,
                &ServerSelfSignedCredConfig));

        QUIC_TICKET_KEY_CONFIG KeyConfig;
        CxPlatZeroMemory(&KeyConfig, sizeof(KeyConfig));
        KeyConfig.MaterialLength = 64;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                LocalConfiguration,
                QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                sizeof(KeyConfig),
                &KeyConfig));
    }

    //
    // Set Ticket Key (multiple)
    //
    {
        ConfigurationScope LocalConfiguration;
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                &GoodAlpn,
                1,
                nullptr,
                0,
                nullptr,
                &LocalConfiguration.Handle));

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationLoadCredential(
                LocalConfiguration,
                &ServerSelfSignedCredConfig));

        QUIC_TICKET_KEY_CONFIG KeyConfigs[2];
        CxPlatZeroMemory(KeyConfigs, sizeof(KeyConfigs));
        KeyConfigs[0].MaterialLength = 64;
        KeyConfigs[1].MaterialLength = 64;
        KeyConfigs[1].Id[0] = 1;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                LocalConfiguration,
                QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                sizeof(KeyConfigs),
                KeyConfigs));
    }
#endif // QUIC_DISABLE_TICKET_KEY_TESTS
}

static
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
DummyListenerCallback(
    HQUIC,
    void* Context,
    QUIC_LISTENER_EVENT* Event
    )
{
    CxPlatEvent* StopCompleteEvent = (CxPlatEvent*)Context;
    if (StopCompleteEvent &&
        Event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE) {
        StopCompleteEvent->Set();
        return QUIC_STATUS_SUCCESS;
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

static
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
AutoCloseListenerCallback(
    HQUIC Listener,
    void* Context,
    QUIC_LISTENER_EVENT* Event
    )
{
    CxPlatEvent* StopCompleteEvent = (CxPlatEvent*)Context;
    if (StopCompleteEvent &&
        Event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE) {
        StopCompleteEvent->Set();
        MsQuic->ListenerClose(Listener);
        return QUIC_STATUS_SUCCESS;
    }
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
    CxPlatEvent StopCompleteEvent;

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
            &StopCompleteEvent,
            &Listener));

    MsQuic->ListenerStop(Listener);
    TEST_FALSE(StopCompleteEvent.WaitTimeout(100)); // Event not should have been set

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    MsQuic->ListenerClose(Listener);
    TEST_TRUE(StopCompleteEvent.WaitTimeout(100)); // Event should have been set
    Listener = nullptr;

    //
    // Close before stop.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback,
            &StopCompleteEvent,
            &Listener));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    MsQuic->ListenerClose(Listener);
    TEST_TRUE(StopCompleteEvent.WaitTimeout(100)); // Event should have been set
    Listener = nullptr;

    //
    // Start twice.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback,
            &StopCompleteEvent,
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
    TEST_TRUE(StopCompleteEvent.WaitTimeout(100)); // Event should have been set

    MsQuic->ListenerStop(Listener);
    TEST_FALSE(StopCompleteEvent.WaitTimeout(100)); // Event not should have been set (again)

    MsQuic->ListenerClose(Listener);
    TEST_FALSE(StopCompleteEvent.WaitTimeout(100)); // Event not should have been set (again)
    Listener = nullptr;

    //
    // Null handle to close.
    //
    MsQuic->ListenerClose(nullptr);

    //
    // Close in callback
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            AutoCloseListenerCallback,
            &StopCompleteEvent,
            &Listener));

    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerStart(
            Listener,
            Alpn,
            Alpn.Length(),
            nullptr));

    MsQuic->ListenerStop(Listener);
    TEST_TRUE(StopCompleteEvent.WaitTimeout(100)); // Event should have been set
    Listener = nullptr;
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
struct QuicServerSendResumeState {
    CxPlatEvent ListenerAcceptEvent;
    CxPlatEvent HandshakeCompleteEvent;
};

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
        ((QuicServerSendResumeState*)Context)->HandshakeCompleteEvent.Set();
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
    _In_ TestListener* Listener,
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
    ((QuicServerSendResumeState*)Listener->Context)->ListenerAcceptEvent.Set();
    return true;
}
#endif

void QuicTestValidateConnection()
{
#ifndef QUIC_DISABLE_0RTT_TESTS
    QuicServerSendResumeState ListenerContext;
#endif
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfigurationNoResumption(Registration, Alpn, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfigurationNoResumption.IsValid());

    MsQuicSettings Settings;
    Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY);
    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    Settings.SetIdleTimeoutMs(1000);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    //
    // Null out-parameter.
    //
    {
        TestScopeLogger logScope("Null out-parameter");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionOpen(
                Registration,
                DummyConnectionCallback,
                nullptr,
                nullptr));
    }

    //
    // Null Callback-parameter.
    //
    {
        TestScopeLogger logScope("Null Callback-parameter");
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
        TestScopeLogger logScope("Null registration parameter");
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
    {
        TestScopeLogger logScope("Null connection parameter");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionStart(
                nullptr,
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
                "localhost",
                4433));
    }

    //
    // Bad address family
    //
    {
        TestScopeLogger logScope("Bad address family");
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
        TestScopeLogger logScope("Null server name");
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
    // Bad port
    //
    {
        TestScopeLogger logScope("Bad port");
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
        TestScopeLogger logScope("Start connection twice");
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
        TestScopeLogger logScope("Shutdown connection and then start");
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
        TestScopeLogger logScope("Shutdown connection twice");
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
    // ConnectionShutdown null handle
    //
    {
        TestScopeLogger logScope("ConnectionShutdown null handle");
        MsQuic->ConnectionShutdown(
            nullptr,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            QUIC_TEST_NO_ERROR);
    }

    //
    // ConnectionClose null handle
    //
    {
        TestScopeLogger logScope("ConnectionClose null handle");
        MsQuic->ConnectionClose(nullptr);
    }

    //
    // Invalid datagram send calls
    //
    {
        TestScopeLogger logScope("Invalid datagram send calls");
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
    // Successful send datagram calls
    //
    {
        TestScopeLogger logScope("Successful send datagram calls");
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
    // Successful set datagram receive parameter
    //
    {
        TestScopeLogger logScope("Successful set datagram receive parameter");
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
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                sizeof(ReceiveDatagrams),
                &ReceiveDatagrams));

        ReceiveDatagrams = FALSE;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Connection.Handle,
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                sizeof(ReceiveDatagrams),
                &ReceiveDatagrams));
    }

    //
    // Invalid send resumption
    //
    {
        TestScopeLogger logScope("Invalid send resumption");
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
        TestScopeLogger logScopeouter("Invalid send resumption, server-side");
        TestListener MyListener(Registration, ListenerFailSendResumeCallback, ServerConfigurationNoResumption);
        TEST_TRUE(MyListener.IsValid());

        TEST_QUIC_SUCCEEDED(MyListener.Start(Alpn, Alpn.Length()));
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(MyListener.GetLocalAddr(ServerLocalAddr));

        MyListener.Context = &ListenerContext;

        {
            //
            // Validate that the resumption ticket call fails in the listener.
            //
            {
            TestScopeLogger logScope("SendResumption in Listener callback");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
            TEST_TRUE(ListenerContext.ListenerAcceptEvent.WaitTimeout(2000));
            }

            //
            // Ensure sending a resumption ticket fails even when connected
            // because resumption is not enabled.
            //
            {
            TestScopeLogger logScope("SendResumption with resumption disabled");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
            TEST_TRUE(ListenerContext.ListenerAcceptEvent.WaitTimeout(2000));
            TEST_TRUE(ListenerContext.HandshakeCompleteEvent.WaitTimeout(2000)); // Wait for server to get connected
            }

            //
            // Enable resumption but ensure failure because the connection
            // isn't in connected state yet.
            //
            {
            TestScopeLogger logScope("SendResumption handshake not complete");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
            TEST_TRUE(ListenerContext.ListenerAcceptEvent.WaitTimeout(2000));
            TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(2000)); // Wait for client to get connected

            //
            // TODO: add test case to validate ConnectionSendResumptionTicket:
            // * succeeds when resumption is enabled and once connected.
            //
            }
        }
    }
#endif
}

_Function_class_(STREAM_SHUTDOWN_CALLBACK)
static
void
ServerApiTestStreamShutdown(
    _In_ TestStream* Stream
    )
{
    delete Stream;
}

_Function_class_(NEW_STREAM_CALLBACK)
static
void
ServerApiTestNewStream(
    _In_ TestConnection* /* Connection */,
    _In_ HQUIC StreamHandle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags
    )
{
    auto Stream = TestStream::FromStreamHandle(StreamHandle, ServerApiTestStreamShutdown, Flags);
    if (Stream == nullptr || !Stream->IsValid()) {
        delete Stream;
        TEST_FAILURE("Failed to accept new TestStream.");
    }
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
    *NewConnection = new(std::nothrow) TestConnection(ConnectionHandle, ServerApiTestNewStream);
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
        if (Event->RECEIVE.TotalBufferLength != 0) {
            TEST_FAILURE("QUIC_STREAM_EVENT_RECEIVE with data should never be called!");
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        TEST_FAILURE("QUIC_STREAM_EVENT_SEND_COMPLETE should never be called!");
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

struct ShutdownStreamContext {
    QUIC_STATUS StartCompleteStatus { QUIC_STATUS_SUCCESS };
    bool ShutdownComplete { false };
    CxPlatEvent StartCompleteEvent;
    CxPlatEvent ShutdownCompleteEvent;
    ShutdownStreamContext() { }
};

_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
ShutdownStreamCallback(
    _In_ HQUIC /*Stream*/,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    ShutdownStreamContext* ShutdownContext = (ShutdownStreamContext*)Context;
    switch (Event->Type) {

    case QUIC_STREAM_EVENT_START_COMPLETE:
        ShutdownContext->StartCompleteStatus = Event->START_COMPLETE.Status;
        ShutdownContext->StartCompleteEvent.Set();
        break;

    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.TotalBufferLength != 0) {
            TEST_FAILURE("QUIC_STREAM_EVENT_RECEIVE with data should never be called!");
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        TEST_FAILURE("QUIC_STREAM_EVENT_SEND_COMPLETE should never be called!");
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        ShutdownContext->ShutdownComplete = true;
        ShutdownContext->ShutdownCompleteEvent.Set();
        break;

    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
AllowSendCompleteStreamCallback(
    _In_ HQUIC /*Stream*/,
    _In_opt_ void* /*Context*/,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {

    case QUIC_STREAM_EVENT_RECEIVE:
        TEST_FAILURE("QUIC_STREAM_EVENT_RECEIVE should never be called!");
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
    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
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
                        QUIC_TEST_LOOPBACK_FOR_AF(
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
                TestScopeLogger logScope("Null connection");
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
                TestScopeLogger logScope("Null handler");
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
                TestScopeLogger logScope("Fail on blocked");
                ShutdownStreamContext Context;
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        ShutdownStreamCallback,
                        &Context,
                        &Stream.Handle));
                if (Connect) {
                    TEST_QUIC_SUCCEEDED(
                        MsQuic->StreamStart(
                            Stream.Handle,
                            QUIC_STREAM_START_FLAG_FAIL_BLOCKED));
                } else {
                    TEST_QUIC_STATUS(
                        QUIC_STATUS_PENDING,
                        MsQuic->StreamStart(
                            Stream.Handle,
                            QUIC_STREAM_START_FLAG_FAIL_BLOCKED));
                    Context.StartCompleteEvent.WaitTimeout(2000);
                    TEST_EQUAL(Context.StartCompleteStatus, QUIC_STATUS_STREAM_LIMIT_REACHED);
                }
                TEST_FALSE(Context.ShutdownComplete);
            }

            //
            // Shutdown on fail.
            //
            if (!Connect) {
                TestScopeLogger logScope("Shutdown on fail");
                ShutdownStreamContext Context;
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE,
                        ShutdownStreamCallback,
                        &Context,
                        &Stream.Handle));
                TEST_QUIC_STATUS(
                    QUIC_STATUS_PENDING,
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_FAIL_BLOCKED | QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL));
                Context.StartCompleteEvent.WaitTimeout(2000);
                TEST_EQUAL(Context.StartCompleteStatus, QUIC_STATUS_STREAM_LIMIT_REACHED);
                Context.ShutdownCompleteEvent.WaitTimeout(2000);
                TEST_TRUE(Context.ShutdownComplete);
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
                TestScopeLogger logScope("Never started (close)");
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
                TestScopeLogger logScope("Never started (shutdown graceful)");
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
                TestScopeLogger logScope("Never started (shutdown abortive)");
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
                TestScopeLogger logScope("Null buffer");
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
                TestScopeLogger logScope("Zero buffers");
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE | QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                        AllowSendCompleteStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamSend(
                        Stream.Handle,
                        Buffers,
                        0,
                        QUIC_SEND_FLAG_NONE,
                        nullptr));
            }

            //
            // Zero-length buffers.
            //
            {
                TestScopeLogger logScope("Zero-length buffers");
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE | QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                        AllowSendCompleteStreamCallback,
                        nullptr,
                        &Stream.Handle));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        Stream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamSend(
                        Stream.Handle,
                        Buffers,
                        ARRAYSIZE(Buffers),
                        QUIC_SEND_FLAG_NONE,
                        nullptr));
            }

            //
            // Send on shutdown stream.
            //
            {
                TestScopeLogger logScope("Send on shutdown stream");
                StreamScope Stream;
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE | QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
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

                CxPlatSleep(100); // TODO - Ideally wait for shutdown event instead

                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
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
                TestScopeLogger logScope("Double-shutdown stream");
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
                TestScopeLogger logScope("Shutdown no flags");
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

            if (Connect) {
                StreamScope PrevOpenStream; // Opened before shutdown
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE | QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                        AllowSendCompleteStreamCallback,
                        nullptr,
                        &PrevOpenStream.Handle));

                StreamScope PrevOpenAndStartedStream; // Started before shutdown
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamOpen(
                        Client.GetConnection(),
                        QUIC_STREAM_OPEN_FLAG_NONE | QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                        AllowSendCompleteStreamCallback,
                        nullptr,
                        &PrevOpenAndStartedStream.Handle));
                TEST_QUIC_SUCCEEDED(
                    MsQuic->StreamStart(
                        PrevOpenAndStartedStream.Handle,
                        QUIC_STREAM_START_FLAG_NONE));

                //
                // Test after connection has been shutdown.
                //
                Server->Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

                CxPlatSleep(100); // TODO - Ideally wait for completion event instead

                //
                // Open After Connection Shutdown
                //
                {
                    TestScopeLogger logScope("Open After Connection Shutdown");
                    StreamScope Stream;
                    TEST_QUIC_STATUS(
                        QUIC_STATUS_ABORTED,
                        MsQuic->StreamOpen(
                            Client.GetConnection(),
                            QUIC_STREAM_OPEN_FLAG_NONE | QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                            AllowSendCompleteStreamCallback,
                            nullptr,
                            &Stream.Handle));
                }

                //
                // Start After Connection Shutdown
                //
                {
                    TestScopeLogger logScope("Start After Connection Shutdown");
                    TEST_QUIC_STATUS(
                        QUIC_STATUS_ABORTED,
                        MsQuic->StreamStart(
                            PrevOpenStream.Handle,
                            QUIC_STREAM_START_FLAG_NONE));
                }

                //
                // Send+Start After Connection Shutdown
                //
                {
                    TestScopeLogger logScope("Send+Start After Connection Shutdown");
                    TEST_QUIC_STATUS(
                        QUIC_STATUS_ABORTED,
                        MsQuic->StreamSend(
                            PrevOpenStream.Handle,
                            Buffers,
                            ARRAYSIZE(Buffers),
                            QUIC_SEND_FLAG_START,
                            nullptr));
                }

                //
                // Send After Connection Shutdown
                //
                {
                    TestScopeLogger logScope("Send After Connection Shutdown");
                    TEST_QUIC_STATUS(
                        QUIC_STATUS_ABORTED,
                        MsQuic->StreamSend(
                            PrevOpenAndStartedStream.Handle,
                            Buffers,
                            ARRAYSIZE(Buffers),
                            QUIC_SEND_FLAG_START,
                            nullptr));
                }
            }
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
            QUIC_PARAM_GLOBAL_PERF_COUNTERS,
            &BufferLength,
            Counters));

    TEST_EQUAL(BufferLength, (sizeof(uint64_t) * (QUIC_PERF_COUNTER_MAX - 4)));
}

void
ValidateVersionSettings(
    _In_ const QUIC_VERSION_SETTINGS* const OutputVersionSettings,
    _In_reads_bytes_(ValidVersionsLength * sizeof(uint32_t))
        const uint32_t* const ValidVersions,
    _In_ const size_t ValidVersionsLength
    )
{
    TEST_EQUAL(OutputVersionSettings->AcceptableVersionsLength, ValidVersionsLength);
    TEST_EQUAL(OutputVersionSettings->OfferedVersionsLength, ValidVersionsLength);
    TEST_EQUAL(OutputVersionSettings->FullyDeployedVersionsLength, ValidVersionsLength);
    //
    // Test to make sure the version lists are correct.
    //
    for (unsigned i = 0; i < OutputVersionSettings->AcceptableVersionsLength; ++i) {
        TEST_EQUAL(OutputVersionSettings->AcceptableVersions[i], CxPlatByteSwapUint32(ValidVersions[i]));
    }
    for (unsigned i = 0; i < OutputVersionSettings->OfferedVersionsLength; ++i) {
        TEST_EQUAL(OutputVersionSettings->OfferedVersions[i], CxPlatByteSwapUint32(ValidVersions[i]));
    }
    for (unsigned i = 0; i < OutputVersionSettings->FullyDeployedVersionsLength; ++i) {
        TEST_EQUAL(OutputVersionSettings->FullyDeployedVersions[i], CxPlatByteSwapUint32(ValidVersions[i]));
    }
}

void
QuicTestVersionSettings()
{
    const uint32_t ValidVersions[] = {0x00000001, 0xabcd0000, 0xff00001d, 0x0a0a0a0a};
    const uint32_t InvalidVersions[] = {0x00000001, 0x00000002};
    const uint32_t ZeroVersion[] = { 0 };
    uint8_t OutputVersionBuffer[sizeof(QUIC_VERSION_SETTINGS) + (3 * sizeof(ValidVersions))];
    uint32_t BufferLength = sizeof(OutputVersionBuffer);
    QUIC_VERSION_SETTINGS* OutputVersionSettings = (QUIC_VERSION_SETTINGS*)OutputVersionBuffer;

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicVersionSettings InputSettings;

    //
    // Test setting and getting the desired versions on Connection
    //
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

        //
        // Test invalid versions are failed on Connection
        //
        InputSettings.SetAllVersionLists(InvalidVersions, ARRAYSIZE(InvalidVersions));
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        InputSettings.SetAllVersionLists(ZeroVersion, ARRAYSIZE(ZeroVersion));
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        //
        // Test setting/getting valid versions list on Connection
        //
        InputSettings.SetAllVersionLists(ValidVersions, ARRAYSIZE(ValidVersions));

        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(
                QUIC_PARAM_CONN_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        TEST_QUIC_SUCCEEDED(
            Connection.GetParam(
                QUIC_PARAM_CONN_VERSION_SETTINGS,
                &BufferLength,
                OutputVersionBuffer));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));
        ValidateVersionSettings(OutputVersionSettings, ValidVersions, ARRAYSIZE(ValidVersions));

        BufferLength = 0;
        CxPlatZeroMemory(OutputVersionBuffer, sizeof(OutputVersionBuffer));

        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            Connection.GetParam(
                QUIC_PARAM_CONN_VERSION_SETTINGS,
                &BufferLength,
                NULL));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));

        TEST_QUIC_SUCCEEDED(
            Connection.GetParam(
                QUIC_PARAM_CONN_VERSION_SETTINGS,
                &BufferLength,
                OutputVersionBuffer));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));
        ValidateVersionSettings(OutputVersionSettings, ValidVersions, ARRAYSIZE(ValidVersions));
    }

    //
    // Test setting/getting versions on Configuration
    //
    {
        MsQuicAlpn Alpn("MsQuicTest");
        ConfigurationScope Configuration;

        TEST_QUIC_SUCCEEDED(
            MsQuic->ConfigurationOpen(
                Registration,
                Alpn,
                Alpn.Length(),
                nullptr,
                0,
                nullptr,
                &Configuration.Handle));

        InputSettings.SetAllVersionLists(InvalidVersions, ARRAYSIZE(InvalidVersions));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Configuration.Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        InputSettings.SetAllVersionLists(ZeroVersion, ARRAYSIZE(ZeroVersion));
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Configuration.Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        InputSettings.SetAllVersionLists(ValidVersions, ARRAYSIZE(ValidVersions));

        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Configuration.Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        BufferLength = sizeof(OutputVersionBuffer);

        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Configuration.Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                &BufferLength,
                OutputVersionBuffer));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));
        ValidateVersionSettings(OutputVersionSettings, ValidVersions, ARRAYSIZE(ValidVersions));

        BufferLength = 0;
        CxPlatZeroMemory(OutputVersionBuffer, sizeof(OutputVersionBuffer));

        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            MsQuic->GetParam(
                Configuration.Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                &BufferLength,
                NULL));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));

        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Configuration.Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                &BufferLength,
                OutputVersionBuffer));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));

        ValidateVersionSettings(OutputVersionSettings, ValidVersions, ARRAYSIZE(ValidVersions));
    }

    {
        //
        // Test invalid versions are failed on Global
        //
        InputSettings.SetAllVersionLists(InvalidVersions, ARRAYSIZE(InvalidVersions));
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        InputSettings.SetAllVersionLists(ZeroVersion, ARRAYSIZE(ZeroVersion));
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));

        //
        // Test setting/getting valid desired versions on global
        //
        BufferLength = sizeof(InputSettings);
        InputSettings.SetAllVersionLists(ValidVersions, ARRAYSIZE(ValidVersions));

        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                sizeof(InputSettings),
                &InputSettings));
        ClearGlobalVersionListScope ClearVersionListScope;

        BufferLength = 0;
        CxPlatZeroMemory(OutputVersionBuffer, sizeof(OutputVersionBuffer));

        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            MsQuic->GetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                &BufferLength,
                NULL));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));

        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                &BufferLength,
                OutputVersionBuffer));

        TEST_EQUAL(BufferLength, sizeof(OutputVersionBuffer));

        ValidateVersionSettings(OutputVersionSettings, ValidVersions, ARRAYSIZE(ValidVersions));
    }
}

void
QuicTestValidateParamApi()
{
    //
    // Test backwards compatibility.
    //
    uint16_t LoadBalancingMode;
    uint32_t BufferSize = sizeof(LoadBalancingMode);

    BufferSize = sizeof(LoadBalancingMode);
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->GetParam(
            nullptr,
            2,              // No longer backwards compatible with v1.*
            &BufferSize,
            (void*)&LoadBalancingMode));

    BufferSize = sizeof(LoadBalancingMode);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
            &BufferSize,
            (void*)&LoadBalancingMode));
}

static
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
RejectListenerCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
) noexcept {
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        auto ShutdownEvent = (CxPlatEvent*)Context;
        if (ShutdownEvent) {
            MsQuic->ConnectionClose(Event->NEW_CONNECTION.Connection);
            ShutdownEvent->Set();
            return QUIC_STATUS_SUCCESS;
        } else {
            return QUIC_STATUS_ABORTED;
        }
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestConnectionRejection(
    bool RejectByClosing
    )
{
    CxPlatEvent ShutdownEvent;
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicListener Listener(Registration, RejectListenerCallback, RejectByClosing ? &ShutdownEvent : nullptr);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = QUIC_ADDRESS_FAMILY_INET;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

    if (RejectByClosing) {
        TEST_TRUE(ShutdownEvent.WaitTimeout(TestWaitTimeout));
    } else {
        TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        TEST_FALSE(Connection.HandshakeComplete);
        TEST_EQUAL(Connection.TransportShutdownStatus, QUIC_STATUS_CONNECTION_REFUSED);
    }
}

void
QuicTestCredentialLoad(const QUIC_CREDENTIAL_CONFIG* Config)
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration Configuration(Registration, "MsQuicTest");
    TEST_TRUE(Configuration.IsValid());

    TEST_QUIC_SUCCEEDED(Configuration.LoadCredential(Config));
}

void
QuicTestStorage()
{
    const uint32_t SpecialInitialRtt = 55;

#ifdef _KERNEL_MODE
    DECLARE_CONST_UNICODE_STRING(GlobalStoragePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\");
    DECLARE_CONST_UNICODE_STRING(AppStoragePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest\\");
    DECLARE_CONST_UNICODE_STRING(ValueName, L"InitialRttMs");
    HANDLE GlobalKey, AppKey;
    OBJECT_ATTRIBUTES GlobalAttributes, AppAttributes;
    InitializeObjectAttributes(
        &GlobalAttributes,
        (PUNICODE_STRING)&GlobalStoragePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    InitializeObjectAttributes(
        &AppAttributes,
        (PUNICODE_STRING)&AppStoragePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    TEST_QUIC_SUCCEEDED(
        ZwOpenKey(
            &GlobalKey,
            KEY_READ | KEY_NOTIFY,
            &GlobalAttributes));
    ZwDeleteValueKey(
        GlobalKey,
        (PUNICODE_STRING)&ValueName);
    if (QUIC_SUCCEEDED(
        ZwOpenKey(
            &AppKey,
            KEY_READ | KEY_NOTIFY,
            &AppAttributes))) {
        ZwDeleteKey(AppKey);
        ZwClose(AppKey);
    }
    TEST_QUIC_SUCCEEDED(
        ZwCreateKey(
            &AppKey,
            KEY_READ | KEY_NOTIFY,
            &AppAttributes,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            NULL));
#elif _WIN32
    RegDeleteKeyValueA(
        HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\MsQuic\\Parameters",
        "InitialRttMs");
    RegDeleteKeyA(
        HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest");
    HKEY Key;
    RegCreateKeyA(
        HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest",
        &Key);
    RegCloseKey(Key);
#else
    TEST_FAILURE("Storage tests not supported on this platform");
#endif

    MsQuicSettings Settings;

    //
    // Global settings
    //

    TEST_QUIC_SUCCEEDED(Settings.GetGlobal());
    TEST_NOT_EQUAL(Settings.InitialRttMs, SpecialInitialRtt);

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            GlobalKey,
            (PUNICODE_STRING)&ValueName,
            0,
            REG_DWORD,
            (PVOID)&SpecialInitialRtt,
            sizeof(SpecialInitialRtt)));
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\MsQuic\\Parameters",
            "InitialRttMs",
            REG_DWORD,
            &SpecialInitialRtt,
            sizeof(SpecialInitialRtt)));
#else
    TEST_FAILURE("Storage tests not supported on this platform");
#endif

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(Settings.GetGlobal());
    TEST_EQUAL(Settings.InitialRttMs, SpecialInitialRtt);

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            GlobalKey,
            (PUNICODE_STRING)&ValueName));
    ZwClose(GlobalKey);
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\MsQuic\\Parameters",
            "InitialRttMs"));
#else
    TEST_FAILURE("Storage tests not supported on this platform");
#endif

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(Settings.GetGlobal());
    TEST_NOT_EQUAL(Settings.InitialRttMs, SpecialInitialRtt);

    //
    // App settings
    //

    MsQuicRegistration Registration("StorageTest");
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration Configuration(Registration, "MsQuicTest");
    TEST_TRUE(Configuration.IsValid());

    TEST_QUIC_SUCCEEDED(Configuration.GetSettings(Settings));
    TEST_NOT_EQUAL(Settings.InitialRttMs, SpecialInitialRtt);

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            AppKey,
            (PUNICODE_STRING)&ValueName,
            0,
            REG_DWORD,
            (PVOID)&SpecialInitialRtt,
            sizeof(SpecialInitialRtt)));
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest",
            "InitialRttMs",
            REG_DWORD,
            &SpecialInitialRtt,
            sizeof(SpecialInitialRtt)));
#else
    TEST_FAILURE("Storage tests not supported on this platform");
#endif

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(Configuration.GetSettings(Settings));
    TEST_EQUAL(Settings.InitialRttMs, SpecialInitialRtt);

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            AppKey,
            (PUNICODE_STRING)&ValueName));
    ZwClose(AppKey);
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest",
            "InitialRttMs"));
#else
    TEST_FAILURE("Storage tests not supported on this platform");
#endif

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(Configuration.GetSettings(Settings));
    TEST_NOT_EQUAL(Settings.InitialRttMs, SpecialInitialRtt);
}
