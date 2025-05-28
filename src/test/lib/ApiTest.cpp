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

#if defined(_KERNEL_MODE)
static bool UseQTIP = false;
#elif defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
extern bool UseQTIP;
#endif

void QuicTestValidateApi()
{
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuicOpen2(nullptr));

    MsQuicClose(nullptr);

    // TODO - Move these into GetParam/SetParam tests
    QUIC_TLS_PROVIDER TlsProvider;
    uint32_t BufferLength = sizeof(TlsProvider);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_TLS_PROVIDER,
            &BufferLength,
            &TlsProvider));

    TEST_EQUAL(
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_TLS_PROVIDER,
            BufferLength,
            &TlsProvider),
        QUIC_STATUS_INVALID_PARAMETER);
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

namespace
{
    _Function_class_(QUIC_LISTENER_CALLBACK)
    template<typename T>
    QUIC_STATUS
    QUIC_API
    DummyListenerCallback(
        T,
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
            DummyListenerCallback<HQUIC>,
            nullptr,
            &Listener));

    //
    // Null out parameter.
    //
    TEST_QUIC_STATUS(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback<HQUIC>,
            nullptr,
            nullptr));

    //
    // Stop before start.
    //
    TEST_QUIC_SUCCEEDED(
        MsQuic->ListenerOpen(
            Registration,
            DummyListenerCallback<HQUIC>,
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
            DummyListenerCallback<HQUIC>,
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
            DummyListenerCallback<HQUIC>,
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
            DummyListenerCallback<HQUIC>,
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
QUIC_API
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
    // Invalid partition index.
    //
    {
        TestScopeLogger logScope("Invalid partition index");
        ConnectionScope Connection;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionOpenInPartition(
                Registration,
                UINT16_MAX,
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
QUIC_API
ServerApiTestStreamShutdown(
    _In_ TestStream* Stream
    )
{
    delete Stream;
}

_Function_class_(NEW_STREAM_CALLBACK)
static
void
QUIC_API
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
QUIC_API
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

struct CloseFromCallbackContext {
    short CloseCount;
    volatile short CurrentCount;
    uint8_t RawBuffer[100];
    QUIC_BUFFER BufferToSend { sizeof(RawBuffer), RawBuffer };

    static QUIC_STATUS StreamCallback(_In_ MsQuicStream*, _In_opt_ void*, _Inout_ QUIC_STREAM_EVENT*) {
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS Callback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event, bool IsServer) {
        auto Ctx = (CloseFromCallbackContext*)Context;

        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, Context);
        }

        if (IsServer) {
            if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
                (void)Conn->SendResumptionTicket();

                QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
                auto Stream = new(std::nothrow) MsQuicStream(*Conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, CleanUpAutoDelete, StreamCallback, Context);
                if (QUIC_FAILED(Stream->GetInitStatus()) || QUIC_FAILED(Status = Stream->Start(QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL))) {
                    delete Stream;
                } else {
                    (void)Stream->Send(&Ctx->BufferToSend, 1, QUIC_SEND_FLAG_FIN);
                }
            }
        }

        if (Ctx->CloseCount == InterlockedIncrement16(&Ctx->CurrentCount) - 1) {
            Conn->Close();
        }

        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS CallbackC(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        return Callback(Conn, Context, Event, false);
    }

    static QUIC_STATUS CallbackS(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        return Callback(Conn, Context, Event, true);
    }
};

void
QuicTestConnectionCloseFromCallback() {
    for (uint16_t i = 0; i < 20; i++) {
        CxPlatWatchdog Watchdog(2000);

        CloseFromCallbackContext Context {(short)i, 0};

        MsQuicRegistration Registration(true);
        TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

        MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest",
            MsQuicSettings()
                .SetPeerUnidiStreamCount(10)
                .SetPeerBidiStreamCount(10)
                .SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT),
            ServerSelfSignedCredConfig);
        TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

        MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest",
            MsQuicSettings()
                .SetPeerUnidiStreamCount(10)
                .SetPeerBidiStreamCount(10),
            MsQuicCredentialConfig());
        TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, CloseFromCallbackContext::CallbackS, &Context);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
        QuicAddr ServerLocalAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        MsQuicConnection Connection(Registration,  CleanUpManual, CloseFromCallbackContext::CallbackC, &Context);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

        //
        // Start the stream **before** starting the connection so not to race with connection closure.
        // Don't create it on the stack so we can leverage the "AutoDelete" clean up behavior on shutdown complete.
        //
        auto Stream = new(std::nothrow) MsQuicStream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, CleanUpAutoDelete, CloseFromCallbackContext::StreamCallback, &Context);
        TEST_QUIC_SUCCEEDED(Stream->GetInitStatus());
        TEST_QUIC_SUCCEEDED(Stream->Start(QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL));
        TEST_QUIC_SUCCEEDED(Stream->Send(&Context.BufferToSend, 1, QUIC_SEND_FLAG_FIN));

        TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

        CxPlatSleep(50);
    }
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

uint8_t RawNoopBuffer[100];
QUIC_BUFFER NoopBuffer { sizeof(RawNoopBuffer), RawNoopBuffer };

void QuicTestCloseConnBeforeStreamFlush()
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest",
        MsQuicSettings()
            .SetPeerUnidiStreamCount(1),
        ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest",
        MsQuicSettings(),
        MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    struct TestContext {
        static QUIC_STATUS ServerCallback(_In_ MsQuicConnection*, _In_opt_ void*, _Inout_ QUIC_CONNECTION_EVENT* Event) {
            if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
                new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete);
            }
            return QUIC_STATUS_SUCCESS;
        }
        static QUIC_STATUS ClientCallback(_In_ MsQuicConnection* Conn, _In_opt_ void*, _Inout_ QUIC_CONNECTION_EVENT* Event) {
            if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
                auto Stream = new(std::nothrow) MsQuicStream(*Conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, CleanUpAutoDelete);
                (void)Stream->Send(&NoopBuffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN);
                Conn->Close();
            }
            return QUIC_STATUS_SUCCESS;
        }
    };

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, TestContext::ServerCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerLocalAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration,  CleanUpManual, TestContext::ClientCallback);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));

    CxPlatSleep(50);
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

void SettingApplyTests(HQUIC Handle, uint32_t Param, bool AllowMtuEcnChanges = true) {
    struct TestSpec {
        uint64_t Value;
        QUIC_STATUS Status;
    };

    {
        struct TestSpec Spec[] = {{UINT32_MAX, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_TP_MAX_ACK_DELAY_MAX,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.MaxAckDelayMs = TRUE;
        for (auto &Data: Spec) {
            Settings.MaxAckDelayMs = (uint32_t)Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    {
        struct TestSpec Spec[] = {{UINT32_MAX, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_MAX_DISCONNECT_TIMEOUT,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.DisconnectTimeoutMs = TRUE;
        for (auto &Data: Spec) {
            Settings.DisconnectTimeoutMs = (uint32_t)Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    {
        struct TestSpec Spec[] = {{UINT64_MAX, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_VAR_INT_MAX,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.IdleTimeoutMs = TRUE;
        for (auto &Data: Spec) {
            Settings.IdleTimeoutMs = Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    {
        struct TestSpec Spec[] = {{UINT64_MAX, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_VAR_INT_MAX,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
        for (auto &Data: Spec) {
            Settings.HandshakeIdleTimeoutMs = Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    {
        struct TestSpec Spec[] = {{0, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.StreamRecvBufferDefault = TRUE;
        for (auto &Data: Spec) {
            Settings.StreamRecvBufferDefault = (uint32_t)Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    {
        struct TestSpec Spec[] = {{UINT64_MAX, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_DEFAULT_MAX_BYTES_PER_KEY,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.MaxBytesPerKey = TRUE;
        for (auto &Data: Spec) {
            Settings.MaxBytesPerKey = Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    {
        struct TestSpec Spec[] = {{3, QUIC_STATUS_INVALID_PARAMETER},
                                  {QUIC_SERVER_RESUME_AND_ZERORTT,  QUIC_STATUS_SUCCESS}};
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.ServerResumptionLevel = TRUE;
        for (auto &Data: Spec) {
            Settings.ServerResumptionLevel = Data.Value;
            TEST_QUIC_STATUS(
                Data.Status,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    //
    // MinimumMtu is bigger than MaximumMtu
    //
    {
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.MinimumMtu = TRUE;
        Settings.IsSet.MaximumMtu = TRUE;
        Settings.MinimumMtu = 1400;
        Settings.MaximumMtu = 1300;

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(QUIC_SETTINGS),
                &Settings));

        Settings.MinimumMtu = 1300;
        Settings.MaximumMtu = 1400;

        QUIC_STATUS Status = MsQuic->SetParam(
                Handle,
                Param,
                sizeof(QUIC_SETTINGS),
                &Settings);

        TEST_TRUE((AllowMtuEcnChanges && Status == QUIC_STATUS_SUCCESS) ||
                    (!AllowMtuEcnChanges && Status == QUIC_STATUS_INVALID_PARAMETER));
    }

    {
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.EcnEnabled = TRUE;
        Settings.EcnEnabled = TRUE;
        QUIC_STATUS Status =
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(QUIC_SETTINGS),
                &Settings);
        TEST_TRUE((AllowMtuEcnChanges && Status == QUIC_STATUS_SUCCESS) ||
                    (!AllowMtuEcnChanges && Status == QUIC_STATUS_INVALID_PARAMETER));
    }

    //
    // Good
    //
    {
        QUIC_SETTINGS Settings{0};

        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(QUIC_SETTINGS),
                &Settings));
    }

    //
    // MaxOperationsPerDrain
    //
    {
        QUIC_SETTINGS Settings{0};
        Settings.IsSet.MaxOperationsPerDrain = TRUE;

        Settings.MaxOperationsPerDrain = 0; // Not allowed
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(QUIC_SETTINGS),
                &Settings));

        Settings.MaxOperationsPerDrain = 255; // Max allowed
        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(QUIC_SETTINGS),
                &Settings));
    }
}

void QuicTestStatefulGlobalSetParam()
{
    TestScopeLogger LogScope0("QuicTestStatefulGlobalSetParam");
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    //
    // Set QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE after connection start (MsQuicLib.InUse)
    //
    {
        TestScopeLogger LogScope1("Set QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE after connection start (MsQuicLib.InUse)");
        GlobalSettingScope ParamScope(QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE);
        MsQuicAlpn Alpn("MsQuicTest");
        MsQuicCredentialConfig ClientCredConfig;
        MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCertCredConfig);
        TEST_TRUE(ClientConfiguration.IsValid());
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
            MsQuic->ConnectionStart(
                Connection.Handle,
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
                "localhost",
                4433));
        TEST_TRUE(WaitForMsQuicInUse()); // Waiting for to set MsQuicLib.InUse = TRUE

        uint16_t Mode = QUIC_LOAD_BALANCING_SERVER_ID_IP;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
                sizeof(Mode),
                &Mode));
    }

    {
        TestScopeLogger LogScope1("Get QUIC_PARAM_GLOBAL_DATAPATH_FEATURES after Datapath is made (MsQuicLib.Datapath)");
        uint32_t Length = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_DATAPATH_FEATURES,
                &Length,
                nullptr));
        TEST_EQUAL(Length, sizeof(uint32_t));

        uint32_t ActualFeatures = 0;
        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_DATAPATH_FEATURES,
                &Length,
                &ActualFeatures));
        TEST_NOT_EQUAL(ActualFeatures, 0);
    }
}

void QuicTestGlobalParam()
{
    //
    // QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT");
        GlobalSettingScope ParamScope(QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT);
        uint16_t Percent = 26;
        {
            TestScopeLogger LogScope1("SetParam");
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                    sizeof(Percent),
                    &Percent));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT, sizeof(Percent), &Percent);
        }
    }

    //
    // QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS
    //
    {
        TestScopeLogger LogScope("QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS is get only");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS,
                0,
                nullptr));

        // in src/core/packet.h QUIC_VERSION_INFO and QuicSupportedVersionList are defined
        // but dependency issue happen when including it.
        // sizeof(QUIC_VERSION_INFO[4]) is 88 * 4
        SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS, 88 * 4, nullptr, true);
    }

    //
    // QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE");
        GlobalSettingScope ParamScope(QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE);
        uint16_t Mode = QUIC_LOAD_BALANCING_SERVER_ID_IP;
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // Invalid mode
            //
            {
                TestScopeLogger LogScope2("Invalid mode");
                uint16_t InvalidMode = (QUIC_LOAD_BALANCING_MODE)128;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
                        sizeof(InvalidMode),
                        &InvalidMode));
            }

            //
            // Good setting
            //
            {
                TEST_QUIC_SUCCEEDED(
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
                        sizeof(Mode),
                        &Mode));
            }
        }

        {
            TestScopeLogger LogScope1("GetParam");
            SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE, sizeof(Mode), &Mode);
        }
    }

    //
    // QUIC_PARAM_GLOBAL_PERF_COUNTERS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_PERF_COUNTERS");
        {
            TestScopeLogger LogScope1("SetParam");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_PERF_COUNTERS,
                    0,
                    nullptr));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            {
#if DEBUG
                //
                // Only test this in debug mode, because release tests may be run on
                // the installed binary that is actively being used, and the counters
                // can be non-zero.
                //
                int64_t Buffer[QUIC_PERF_COUNTER_MAX] = {};
                int64_t* ExpectedData = Buffer;
#else
                int64_t* ExpectedData = nullptr;
#endif
                SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_PERF_COUNTERS, QUIC_PERF_COUNTER_MAX * sizeof(int64_t), ExpectedData, true);
            }

            //
            // Truncate length case
            //
            {
                TestScopeLogger LogScope2("Truncate length case");
                int64_t ActualBuffer[QUIC_PERF_COUNTER_MAX/2] = {1,2,3}; // 15
                uint32_t Length = sizeof(int64_t) * (QUIC_PERF_COUNTER_MAX/2) + 4; // truncated 124 -> 120

                TEST_QUIC_SUCCEEDED(
                    MsQuic->GetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_PERF_COUNTERS,
                        &Length,
                        ActualBuffer));
                TEST_EQUAL(Length, sizeof(int64_t) * (QUIC_PERF_COUNTER_MAX / 2));
#if DEBUG
                int64_t ExpectedBuffer[QUIC_PERF_COUNTER_MAX/2] = {}; // 15
                //
                // Only test this in debug mode, because release tests may be run on
                // the installed binary that is actively being used, and the counters
                // can be non-zero.
                //
                TEST_EQUAL(memcmp(ActualBuffer, ExpectedBuffer, Length), 0);
#endif
            }
        }
    }

    //
    // QUIC_PARAM_GLOBAL_LIBRARY_VERSION
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_LIBRARY_VERSION");
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_LIBRARY_VERSION,
                    0,
                    nullptr));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_LIBRARY_VERSION,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(uint32_t[4]));

            uint32_t ActualVersion[4];
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_LIBRARY_VERSION,
                    &Length,
                    &ActualVersion));
            TEST_EQUAL(ActualVersion[0], 2);
            // value of idx 2 and 3 are decided at build time.
            // it is hard to verify the values at runtime.
        }
    }

    //
    // QUIC_PARAM_GLOBAL_SETTINGS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_SETTINGS");
        GlobalSettingScope ParamScope(QUIC_PARAM_GLOBAL_SETTINGS);
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // QuicSettingsSettingsToInternal fail
            //
            {
                TestScopeLogger LogScope2("QuicSettingsSettingsToInternal fail");
                uint32_t MinimumSettingsSize =
                    FIELD_OFFSET(QUIC_SETTINGS, MtuDiscoveryMissingProbeCount) + sizeof(((QUIC_SETTINGS*)0)->MtuDiscoveryMissingProbeCount);
                QUIC_SETTINGS Settings{0};
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_SETTINGS,
                        MinimumSettingsSize-8,
                        &Settings));
            }

            //
            // QuicSettingApply fail
            //
            {
                TestScopeLogger LogScope2("QuicSettingApply fail");
                // TODO: this test set affects other tests' behavior and hangs in Kernel mode test.
                //       temporally disable
                // SettingApplyTests(nullptr, QUIC_PARAM_GLOBAL_SETTINGS);
            }
        }

        {
            TestScopeLogger LogScope1("GetParam");
            SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_SETTINGS, sizeof(QUIC_SETTINGS), nullptr, true);
        }
    }

    //
    // QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS");
        GlobalSettingScope ParamScope(QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS);
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // QuicSettingsGlobalSettingsToInternal fail
            //
            {
                TestScopeLogger LogScope2("QuicSettingsSettingsToInternal fail");
                QUIC_GLOBAL_SETTINGS Settings{0};
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS,
                        sizeof(QUIC_GLOBAL_SETTINGS) - 8,
                        &Settings));
            }

            //
            // QuicSettingApply fail
            //
            {
                TestScopeLogger LogScope2("QuicSettingApply fail");
                QUIC_GLOBAL_SETTINGS Settings{0};
                Settings.LoadBalancingMode = QUIC_LOAD_BALANCING_SERVER_ID_IP + 10;
                Settings.IsSet.LoadBalancingMode = TRUE;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS,
                        sizeof(QUIC_GLOBAL_SETTINGS),
                        &Settings));
            }
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(QUIC_GLOBAL_SETTINGS));

            QUIC_GLOBAL_SETTINGS Settings{0};
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS,
                    &Length,
                    &Settings));
            TEST_EQUAL(Settings.LoadBalancingMode, QUIC_DEFAULT_LOAD_BALANCING_MODE);
            TEST_EQUAL(Settings.RetryMemoryLimit, QUIC_DEFAULT_RETRY_MEMORY_FRACTION);
        }
    }

    //
    // QUIC_PARAM_GLOBAL_VERSION_SETTINGS
    //
    {
        TestScopeLogger LogScope("QUIC_PARAM_GLOBAL_VERSION_SETTINGS is covered by QuicTestVersionSettings");
    }

    //
    // QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH");
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH,
                    0,
                    nullptr));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            // Hash length is 40 http://git-scm.com/book/en/v2/Git-Tools-Revision-Selection#Short-SHA-1
            // Test might not have simple way to fetch git hash at runtime
            // or use VER_GIT_HASH_STR, but need to resolve include dependency
            SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH, 41, nullptr);
        }
    }

#ifndef _KERNEL_MODE
    //
    // QUIC_PARAM_GLOBAL_DATAPATH_FEATURES
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_DATAPATH_FEATURES");
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // Invalid features
            //
            {
                TestScopeLogger LogScope2("SetParam is not allowed");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_DATAPATH_FEATURES,
                        0,
                        nullptr));
            }
        }

        {
            TestScopeLogger LogScope2("GetParam. Failed by missing MsQuicLib.Datapath");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_DATAPATH_FEATURES,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(uint32_t));

            uint32_t ActualFeatures = 0;
            TEST_QUIC_STATUS(QUIC_STATUS_INVALID_STATE,
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_DATAPATH_FEATURES,
                    &Length,
                    &ActualFeatures));
        }
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // QUIC_PARAM_GLOBAL_EXECUTION_CONFIG
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_EXECUTION_CONFIG");
        {
            GlobalSettingScope ParamScope1(QUIC_PARAM_GLOBAL_EXECUTION_CONFIG);

            //
            // Good without data
            //
            {
                TestScopeLogger LogScope2("Good without data");
                TEST_QUIC_SUCCEEDED(
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
                        0,
                        nullptr));
            }

            uint8_t Data[QUIC_GLOBAL_EXECUTION_CONFIG_MIN_SIZE + sizeof(uint16_t) * 4] = {};
            uint32_t DataLength = sizeof(Data);
            QUIC_GLOBAL_EXECUTION_CONFIG* Config = (QUIC_GLOBAL_EXECUTION_CONFIG*)Data;
            Config->ProcessorCount = 4;
            if (CxPlatProcCount() < Config->ProcessorCount) {
                Config->ProcessorCount = CxPlatProcCount();
                DataLength = QUIC_GLOBAL_EXECUTION_CONFIG_MIN_SIZE + sizeof(uint16_t) * Config->ProcessorCount;
            }
            for (uint16_t i = 0; i < (uint16_t)Config->ProcessorCount; ++i) {
                Config->ProcessorList[i] = i;
            }

            //
            // Good with data
            //
            {
                TestScopeLogger LogScope2("Good with data");
                TEST_QUIC_SUCCEEDED(
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
                        DataLength,
                        &Data));
            }

            //
            // Good GetParam with data
            //
            SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_EXECUTION_CONFIG, DataLength, Data);
        }

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
        if (!UseQTIP && !UseDuoNic)
#endif
        {
            //
            // Good GetParam with length == 0
            //
            uint32_t BufferLength = 0;
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
                    &BufferLength,
                    nullptr));
        }
    }
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
#endif // !_KERNEL_MODE

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    //
    // QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS
    //
    {
        TestScopeLogger LogScope("QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS");
        QUIC_TEST_DATAPATH_HOOKS Hooks[2] = {};
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS,
                sizeof(&Hooks),
                &Hooks));
    }
#endif

    //
    // QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR
    // QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE
    // These two cause hang test with `./test.ps1 -IsolationMode Batch`
    // Remove tests as these doesn't have GetParam and are for local debugging purpose
    //

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED");
        GlobalSettingScope ParamScope(QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED);
        BOOLEAN Flag = TRUE;
        {
            TestScopeLogger LogScope1("SetParam");
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED,
                    sizeof(Flag),
                    &Flag));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            SimpleGetParamTest(nullptr, QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED, sizeof(Flag), &Flag);
        }
    }
#endif

    //
    // QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY");
        {
            TestScopeLogger LogScope1("SetParam");
            uint8_t StatelessResetkey[QUIC_STATELESS_RESET_KEY_LENGTH - 1];
            CxPlatRandom(sizeof(StatelessResetkey), StatelessResetkey);
            {
                TestScopeLogger LogScope2("StatelessResetkey fail with invalid state");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY,
                        sizeof(StatelessResetkey),
                        StatelessResetkey));
            }
            {
                TestScopeLogger LogScope2("StatelessResetkey fail with invalid parameter");
                MsQuicRegistration Registration;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY,
                        sizeof(StatelessResetkey),
                        StatelessResetkey));
            }
        }
    }

#if DEBUG
    //
    // QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL");
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // Invalid features
            //
            {
                TestScopeLogger LogScope2("SetParam is not allowed");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL,
                        0,
                        nullptr));
            }
        }

        {
            TestScopeLogger LogScope2("GetParam. Failed by missing MsQuicLib.WorkerPool");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(CXPLAT_WORKER_POOL*));

            CXPLAT_WORKER_POOL* WorkerPool = 0;
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL,
                    &Length,
                    &WorkerPool));
        }
    }
#endif

    //
    // Invalid parameter
    //
    {
        TestScopeLogger LogScope("Invalid parameter for Global SetParam");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_PREFIX_GLOBAL | 0x00234567,
                0,
                nullptr));
    }

    //
    // QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES");
        const uint32_t Expected[] = {
            QUIC_STATISTICS_V2_SIZE_1,
            QUIC_STATISTICS_V2_SIZE_2,
            QUIC_STATISTICS_V2_SIZE_3,
            QUIC_STATISTICS_V2_SIZE_4
        };

        //
        // Expect buffer too small
        //
        uint32_t Length = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
                &Length,
                nullptr));
        TEST_TRUE(Length >= sizeof(Expected));

        //
        // NULL pointer output error case
        //
        Length = sizeof(uint32_t);
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
                &Length,
                nullptr));

        //
        // Retrieve the sizes
        //
        uint32_t Sizes[8] = {0};
        Length = sizeof(Sizes);
        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
                &Length,
                Sizes));
        TEST_TRUE(Length % sizeof(uint32_t) == 0);
        TEST_TRUE(Length >= sizeof(Expected));
        for (uint32_t i = 0; i < ARRAYSIZE(Expected); ++i) {
            TEST_EQUAL(Sizes[i], Expected[i]);
        }

        //
        // Partial retrieve
        //
        uint32_t SingleSize = 0;
        Length = sizeof(SingleSize);
        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
                &Length,
                &SingleSize));
        TEST_EQUAL(Length, sizeof(uint32_t));
        TEST_EQUAL(SingleSize, QUIC_STATISTICS_V2_SIZE_1);

        //
        // Non-multiple of sizeof(uin32_t)
        //
        Length = sizeof(uint32_t) + 1;
        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
                &Length,
                Sizes));
        TEST_EQUAL(Length, sizeof(uint32_t));
        TEST_EQUAL(Sizes[0], QUIC_STATISTICS_V2_SIZE_1);

        //
        // Too Small Receive
        //
        uint8_t SmallSingleSize = 0;
        Length = sizeof(SmallSingleSize);
        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
                &Length,
                &SmallSingleSize));
        TEST_TRUE(Length >= sizeof(Expected));
    }

    QuicTestStatefulGlobalSetParam();
}

void QuicTestCommonParam()
{
    //
    // Null hundle
    //
    {
        TestScopeLogger LogScope("Null handle with non-global param");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                nullptr,
                0, // Any param other than GLOBAL
                0,
                nullptr));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->GetParam(
                nullptr,
                0,
                nullptr,
                nullptr));
    }

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    //
    // Global param with handle
    //
    {
        TestScopeLogger LogScope("Global param with handle");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Registration.Handle,
                QUIC_PARAM_PREFIX_GLOBAL,
                0,
                nullptr));

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->GetParam(
                Registration.Handle,
                QUIC_PARAM_PREFIX_GLOBAL,
                nullptr,
                nullptr));
    }

    //
    // Invalid handle type
    //
    {
        TestScopeLogger LogScope("Invalid handle type");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        auto OriginalType = ((uint8_t*)Connection.Handle)[0];
        ((uint8_t*)Connection.Handle)[0] = 128; // Invalid

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Connection.Handle,
                0,
                0,
                nullptr));

        uint32_t DummyLength = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->GetParam(
                Connection.Handle,
                0,
                &DummyLength,
                nullptr));

        ((uint8_t*)Connection.Handle)[0] = OriginalType;
    }
}

void QuicTestRegistrationParam()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    //
    // No parameter for Registration
    //
    {
        uint32_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                Registration.Handle,
                QUIC_PARAM_PREFIX_REGISTRATION,
                sizeof(Dummy),
                &Dummy));
    }

    {
        uint32_t Length = 65535;
        uint32_t Buffer = 65535;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->GetParam(
                Registration.Handle,
                QUIC_PARAM_PREFIX_REGISTRATION,
                &Length,
                &Buffer));
        TEST_EQUAL(Length, 65535);
        TEST_EQUAL(Buffer, 65535);
    }
}

#define SETTINGS_SIZE_THRU_FIELD(SettingsType, Field) \
    (FIELD_OFFSET(SettingsType, Field) + sizeof(((SettingsType*)0)->Field))

void QuicTestConfigurationParam()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");

    //
    // QUIC_PARAM_CONFIGURATION_SETTINGS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_CONFIGURATION_SETTINGS");
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // QuicSettingsSettingsToInternal fail
            //
            {
                TestScopeLogger LogScope2("QuicSettingsSettingsToInternal fail");
                MsQuicConfiguration Configuration(Registration, Alpn);
                QUIC_SETTINGS Settings{0};
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_CONFIGURATION_SETTINGS,
                        sizeof(QUIC_SETTINGS)-8,
                        &Settings));
            }

            //
            // QuicSettingApply fail
            //
            {
                TestScopeLogger LogScope2("QuicSettingApply fail");
                MsQuicConfiguration Configuration(Registration, Alpn);
                SettingApplyTests(Configuration.Handle, QUIC_PARAM_CONFIGURATION_SETTINGS);
            }
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            MsQuicConfiguration Configuration(Registration, Alpn);
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Configuration.Handle,
                    QUIC_PARAM_CONFIGURATION_SETTINGS,
                    &Length,
                    nullptr));
            TEST_TRUE(Length >= sizeof(QUIC_SETTINGS));

            Length = 1;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Configuration.Handle,
                    QUIC_PARAM_CONFIGURATION_SETTINGS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, SETTINGS_SIZE_THRU_FIELD(QUIC_SETTINGS, MtuDiscoveryMissingProbeCount));

            QUIC_SETTINGS Settings{0};
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Configuration.Handle,
                    QUIC_PARAM_CONFIGURATION_SETTINGS,
                    &Length,
                    &Settings));
            // TODO: how to compare with default?
            //       QuicSettingsSetDefault is not accessible from test
        }
    }

    //
    // QUIC_PARAM_CONFIGURATION_TICKET_KEYS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_CONFIGURATION_TICKET_KEYS");
        {
            TestScopeLogger LogScope1("SetParam");
            //
            // Set before MsQuic->ConfigurationLoadCredential which is Configuration->SecurityConfig == NULL
            //
            {
                TestScopeLogger LogScope2("Set before MsQuic->ConfigurationLoadCredential which is Configuration->SecurityConfig == NULL");
                MsQuicConfiguration Configuration(Registration, Alpn);
                QUIC_TICKET_KEY_CONFIG Config{0};
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    MsQuic->SetParam(
                        Configuration,
                        QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                        sizeof(Config),
                        &Config));
            }

            //
            // SetParam for client is not supported
            //
            {
                TestScopeLogger LogScope2("SetParam for client is not supported");
                MsQuicConfiguration Configuration(Registration, Alpn);
                QUIC_CREDENTIAL_CONFIG CredConfig = {};
                CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
                Configuration.LoadCredential(&CredConfig);
                QUIC_TICKET_KEY_CONFIG Config = {};
                TEST_QUIC_STATUS(
                    QUIC_STATUS_NOT_SUPPORTED,
                    MsQuic->SetParam(
                        Configuration,
                        QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                        sizeof(Config),
                        &Config));
            }

            //
            // Good with self-signed key
            //
            {
                TestScopeLogger LogScope2("Good tests are covered by QuicTestValidateConfiguration");
            }
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam is not allowed");
            MsQuicConfiguration Configuration(Registration, Alpn);
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->GetParam(
                    Configuration,
                    QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                    nullptr,
                    nullptr));
        }
    }

    //
    // QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS
    //
    {
        TestScopeLogger LogScope("QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS is covered by QuicTestVersionSettings");
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED
    //
    {

        TestScopeLogger LogScope0("QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED");
        MsQuicConfiguration Configuration(Registration, Alpn);
        BOOLEAN ExpectedFlag = TRUE;
        //
        // SetParam
        //
        {
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Configuration,
                    QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED,
                    sizeof(ExpectedFlag),
                    &ExpectedFlag));
        }

        //
        // GetParam
        //
        {
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Configuration,
                    QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(BOOLEAN));

            BOOLEAN Flag = FALSE;
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Configuration,
                    QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED,
                    &Length,
                    &Flag));
            TEST_EQUAL(Flag, ExpectedFlag);
        }
    }
#endif
}

// Used by Listener and Connection
void CibirIDTests(HQUIC Handle, uint32_t Param) {
    //
    // buffer length test
    //
    {
        TestScopeLogger LogScope0("Buffer length test");
        //
        // Buffer is bigger than QUIC_MAX_CIBIR_LENGTH + 1
        //
        {
            TestScopeLogger LogScope1("Buffer is bigger than QUIC_MAX_CIBIR_LENGTH + 1");
            uint8_t Cibir[128] = {0};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(Cibir),
                    &Cibir));
        }

        //
        // BufferLength == 1
        //
        {
            TestScopeLogger LogScope1("BufferLength == 1");
            uint8_t Cibir[1] = {0};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(Cibir),
                    &Cibir));
        }

        //
        // Good without value, length 0
        //
        {
            TestScopeLogger LogScope1("no value, Bufferlength == 0");
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Handle,
                    Param,
                    0,
                    nullptr));
        }
    }

    //
    // Buffer starts from non-zero is not supported
    // NOTE: This can be removed once this case is supported
    //
    {
        TestScopeLogger LogScope0("Buffer starts from non-zero is not supported");
        uint8_t Cibir[6] = {128};
        TEST_QUIC_STATUS(
            QUIC_STATUS_NOT_SUPPORTED,
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(Cibir),
                &Cibir));
    }

    //
    // Good setting
    //
    {
        uint8_t Cibir[6] = {0};
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(Cibir),
                &Cibir));
    }
}


// Used by Listener
void DosMitigationTests(HQUIC Handle, uint32_t Param) {
    //
    // buffer length test
    //
    {
        TestScopeLogger LogScope0("DoS param Buffer length test");
        //
        // Buffer is bigger than 1 byte
        //
        {
            TestScopeLogger LogScope1("DoS param Buffer is bigger than 1 byte");
            uint8_t buffer[2] = {0};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(buffer),
                    &buffer));
        }

        //
        // BufferLength == 1
        //
        {
            TestScopeLogger LogScope1("DoS param BufferLength == 1");
            uint8_t buffer[1] = {0};

            TEST_QUIC_STATUS(
                QUIC_STATUS_SUCCESS,
                MsQuic->SetParam(
                    Handle,
                    Param,
                    sizeof(buffer),
                    &buffer));
        }
    }

    //
    // Test with value of 1
    //
    {
        TestScopeLogger LogScope0("DoS param Buffer starts from non-zero is not supported");
        uint8_t buffer[1] = {1};
        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(buffer),
                &buffer));
    }

    //
    // Test with value of 0
    //
    {
        uint8_t buffer[1] = {0};
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Handle,
                Param,
                sizeof(buffer),
                &buffer));
    }
}

void QuicTestListenerParam()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    QUIC_ADDR ExpectedAddress;
    QuicAddrFromString("123.45.67.89", 4433, &ExpectedAddress);

    //
    // QUIC_PARAM_LISTENER_LOCAL_ADDRESS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_LISTENER_LOCAL_ADDRESS");
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*>, nullptr);
            TEST_TRUE(Listener.IsValid());
            QUIC_ADDR Dummy = {0};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                Listener.SetParam(
                    QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*>, nullptr);
            TEST_TRUE(Listener.IsValid());

            TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ExpectedAddress));

            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Listener.GetParam(
                    QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(QUIC_ADDR))

            QUIC_ADDR Address = {0};
            TEST_QUIC_SUCCEEDED(
                Listener.GetParam(
                    QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                    &Length,
                    &Address));
            TEST_EQUAL(memcmp((void*)&Address, (void*)&ExpectedAddress, sizeof(QUIC_ADDR)), 0);
        }
    }

    //
    // QUIC_PARAM_LISTENER_STATS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_LISTENER_STATS");
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*>, nullptr);
            TEST_TRUE(Listener.IsValid());
            QUIC_LISTENER_STATISTICS Dummy = {0};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                Listener.SetParam(
                    QUIC_PARAM_LISTENER_STATS,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*>, nullptr);
            TEST_TRUE(Listener.IsValid());

            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Listener.GetParam(
                    QUIC_PARAM_LISTENER_STATS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(QUIC_LISTENER_STATISTICS))

            QUIC_LISTENER_STATISTICS Stats = {65535, 65535, 65535};
            TEST_QUIC_SUCCEEDED(
                Listener.GetParam(
                    QUIC_PARAM_LISTENER_STATS,
                    &Length,
                    &Stats));
            TEST_EQUAL(Stats.TotalAcceptedConnections, 0);
            TEST_EQUAL(Stats.TotalRejectedConnections, 0);
            TEST_EQUAL(Stats.BindingRecvDroppedPackets, 0);
            // TODO: Stateful test after accept/rejecting connection
        }
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // QUIC_PARAM_LISTENER_CIBIR_ID
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_LISTENER_CIBIR_ID");
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*> , nullptr);
            TEST_TRUE(Listener.IsValid());
            CibirIDTests(Listener.Handle, QUIC_PARAM_LISTENER_CIBIR_ID);
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*>, nullptr);
            TEST_TRUE(Listener.IsValid());
            uint32_t Length = 65535;
            TEST_QUIC_SUCCEEDED(
                Listener.GetParam(
                    QUIC_PARAM_LISTENER_CIBIR_ID,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, 0);
            // TODO: Stateful test once Listener->CibrId is filled
        }
    }

    //
    // QUIC_PARAM_DOS_MODE_EVENTS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_DOS_MODE_EVENTS");
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*> , nullptr);
            TEST_TRUE(Listener.IsValid());
            DosMitigationTests(Listener.Handle, QUIC_PARAM_DOS_MODE_EVENTS);
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            MsQuicListener Listener(Registration, CleanUpManual, DummyListenerCallback<MsQuicListener*>, nullptr);
            TEST_TRUE(Listener.IsValid());
            uint32_t Length = 65535;
            uint8_t buffer[1] = {0};
            TEST_QUIC_SUCCEEDED(
                Listener.GetParam(
                    QUIC_PARAM_DOS_MODE_EVENTS,
                    &Length,
                    &buffer));
            TEST_EQUAL(Length, sizeof(BOOLEAN)); //sizeof (((QUIC_LISTENER *)0)->DosModeEventsEnabled)
        }
    }
#endif

}

void QuicTest_QUIC_PARAM_CONN_QUIC_VERSION(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_QUIC_VERSION");
    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    //
    // SetParam
    //
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        uint32_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_QUIC_VERSION,
                sizeof(Dummy),
                &Dummy));
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        uint32_t Length = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            Connection.GetParam(
                QUIC_PARAM_CONN_QUIC_VERSION,
                &Length,
                nullptr));
        TEST_EQUAL(Length, sizeof(uint32_t));

        uint32_t Version = 65535;
        {
            TestScopeLogger LogScope2("Version == 0 before start");
            TEST_QUIC_SUCCEEDED(
                Connection.GetParam(
                    QUIC_PARAM_CONN_QUIC_VERSION,
                    &Length,
                    &Version));
            TEST_EQUAL(Version, 0);
        }

        {
            TestScopeLogger LogScope2("Version == 1 after start");
            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    ClientConfiguration,
                    QUIC_ADDRESS_FAMILY_INET,
                    "localhost",
                    4433));
            TEST_QUIC_SUCCEEDED(
                Connection.GetParam(
                    QUIC_PARAM_CONN_QUIC_VERSION,
                    &Length,
                    &Version));
            TEST_EQUAL(Version, 1);
        }
    }
}

void QuicTest_QUIC_PARAM_CONN_LOCAL_ADDRESS(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_LOCAL_ADDRESS");
    //
    // SetParam
    //
    {
        TestScopeLogger LogScope1("SetParam");
        //
        // Connection ClosedLocally
        //
        {
            TestScopeLogger LogScope2("Connection is closed locally");
            TEST_TRUE(ClientConfiguration.IsValid());
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            SimulateConnBadStartState(Connection, ClientConfiguration);

            QUIC_ADDR Dummy = {};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                Connection.SetParam(
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // Connection is started, but not handshake confirmed
        //
        {
            TestScopeLogger LogScope2("Connection is started, but not handshake confirmed");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            TEST_QUIC_SUCCEEDED(
                MsQuic->ConnectionStart(
                    Connection.Handle,
                    ClientConfiguration,
                    QUIC_ADDRESS_FAMILY_INET,
                    "localhost",
                    4433));

            QUIC_ADDR Dummy = {};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                Connection.SetParam(
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // Good before ConnectioStart
        //
        {
            TestScopeLogger LogScope2("Good before ConnectionStart");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            QUIC_ADDR Dummy = {};
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(Dummy),
                    &Dummy));
        }

        {// TODO: good after start, need to set Connection->State.HandshakeConfirmed
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        {
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Connection.GetParam(
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(QUIC_ADDR));

            QUIC_ADDR Addr = {};
            //
            // !Connection->Stae.LocalAddressSet
            //
            {
                TestScopeLogger LogScope2("!Connection->Stae.LocalAddressSet");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    Connection.GetParam(
                        QUIC_PARAM_CONN_LOCAL_ADDRESS,
                        &Length,
                        &Addr));
            }

            //
            // Good
            //
            {
                TEST_QUIC_SUCCEEDED(
                    MsQuic->ConnectionStart(
                        Connection.Handle,
                        ClientConfiguration,
                        QUIC_ADDRESS_FAMILY_INET,
                        "127.0.0.1",
                        4433));
                TEST_QUIC_SUCCEEDED(
                    Connection.GetParam(
                        QUIC_PARAM_CONN_LOCAL_ADDRESS,
                        &Length,
                        &Addr));
                QUIC_ADDR Expected = {0};
                QuicAddrFromString("127.0.0.1", 4433, &Expected);
                TEST_EQUAL(memcmp((void*)&Addr.Ipv4.sin_addr, (void*)&Expected.Ipv4.sin_addr, sizeof(struct in_addr)), 0);
                TEST_NOT_EQUAL(Addr.Ipv4.sin_port, Expected.Ipv4.sin_port);
            }
        }
    }
}

void QuicTest_QUIC_PARAM_CONN_REMOTE_ADDRESS(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_REMOTE_ADDRESS");
    {
        TestScopeLogger LogScope1("SetParam");
        {
            //
            // QUIC_STATUS_INVALID_STATE (connection failed to started)
            //
            {
                TestScopeLogger LogScope2("QUIC_CONN_BAD_START_STATE");
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                SimulateConnBadStartState(Connection, ClientConfiguration);

                QUIC_ADDR Dummy = {};
                TEST_TRUE(QuicAddrFromString("127.0.0.1", 0, &Dummy));
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    Connection.SetParam(
                        QUIC_PARAM_CONN_REMOTE_ADDRESS,
                        sizeof(Dummy),
                        &Dummy));
            }

            //
            // QUIC_STATUS_INVALID_PARAMETER (0.0.0.0)
            //
            {
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                const QUIC_ADDR ZeroAddr = {0};
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    Connection.SetParam(
                        QUIC_PARAM_CONN_REMOTE_ADDRESS,
                        sizeof(ZeroAddr),
                        &ZeroAddr));
            }

            //
            // QUIC_STATUS_INVALID_PARAMETER (too small)
            //
            {
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                QUIC_ADDR Dummy = {};
                TEST_TRUE(QuicAddrFromString("127.0.0.1", 0, &Dummy));
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    Connection.SetParam(
                        QUIC_PARAM_CONN_REMOTE_ADDRESS,
                        sizeof(Dummy)-1,
                        &Dummy));
            }

            //
            // Good
            //
            {
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                QUIC_ADDR Dummy = {};
                TEST_TRUE(QuicAddrFromString("127.0.0.1", 0, &Dummy));
                TEST_QUIC_SUCCEEDED(
                    Connection.SetParam(
                        QUIC_PARAM_CONN_REMOTE_ADDRESS,
                        sizeof(Dummy),
                        &Dummy));
            }
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        {
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Connection.GetParam(
                    QUIC_PARAM_CONN_REMOTE_ADDRESS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(QUIC_ADDR));

            //
            // !Connection->State.RemoteAddressSet
            //
            QUIC_ADDR Addr = {};
            {
                TestScopeLogger LogScope2("!Connection->State.RemoteAddressSet");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    Connection.GetParam(
                        QUIC_PARAM_CONN_REMOTE_ADDRESS,
                        &Length,
                        &Addr));
            }

            //
            // Good
            //
            {
                TEST_QUIC_SUCCEEDED(
                    MsQuic->ConnectionStart(
                        Connection.Handle,
                        ClientConfiguration,
                        QUIC_ADDRESS_FAMILY_INET,
                        "127.0.0.1",
                        4433));
                TEST_QUIC_SUCCEEDED(
                    Connection.GetParam(
                        QUIC_PARAM_CONN_REMOTE_ADDRESS,
                        &Length,
                        &Addr));
                QUIC_ADDR Expected = {0};
                QuicAddrFromString("127.0.0.1", 4433, &Expected);
                TEST_EQUAL(memcmp((void*)&Addr, (void*)&Expected, sizeof(QUIC_ADDR)), 0);
            }
        }
    }
}

void QuicTest_QUIC_PARAM_CONN_IDEAL_PROCESSOR(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_IDEAL_PROCESSOR");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint16_t Dummy = 8;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_IDEAL_PROCESSOR,
                sizeof(Dummy),
                &Dummy));
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_IDEAL_PROCESSOR, sizeof(uint16_t), nullptr);
    }
}

void QuicTest_QUIC_PARAM_CONN_SETTINGS(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_SETTINGS");
    {
        TestScopeLogger LogScope1("SetParam");
        //
        // QuicConnApplyNewSettings
        //
        {
            TestScopeLogger LogScope2("QuicConnApplyNewSettings");
            //
            // Before ConnectionStart
            //
            {
                TestScopeLogger LogScope3("Before ConnectionStart");
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                SettingApplyTests(Connection.Handle, QUIC_PARAM_CONN_SETTINGS);
            }

            //
            // After ConnectionStart
            //
            {
                TestScopeLogger LogScope3("After ConnectionStart");
                // Internally AllowMtuEcnChanges become FALSE
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                TEST_QUIC_SUCCEEDED(
                    MsQuic->ConnectionStart(
                        Connection.Handle,
                        ClientConfiguration,
                        QUIC_ADDRESS_FAMILY_INET,
                        "localhost",
                        4433));
                CxPlatSleep(100);

                SettingApplyTests(Connection.Handle, QUIC_PARAM_CONN_SETTINGS, FALSE);
            }
        }

        //
        // Good
        //
        {
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            QUIC_SETTINGS Settings{0};

            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection.Handle,
                    QUIC_PARAM_CONN_SETTINGS,
                    sizeof(QUIC_SETTINGS),
                    &Settings));
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_SETTINGS, sizeof(QUIC_SETTINGS), nullptr, true);
    }
}

void QuicTest_QUIC_PARAM_CONN_STATISTICS(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_STATISTICS");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        QUIC_STATISTICS Dummy = {};
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_STATISTICS,
                sizeof(Dummy),
                &Dummy));
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_STATISTICS, sizeof(QUIC_STATISTICS), nullptr, true);
    }
}

void QuicTest_QUIC_PARAM_CONN_STATISTICS_PLAT(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_STATISTICS_PLAT is get only");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        QUIC_STATISTICS Dummy = {};
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_STATISTICS_PLAT,
                sizeof(Dummy),
                &Dummy));
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_STATISTICS_PLAT, sizeof(QUIC_STATISTICS), nullptr, true);
    }
}

void QuicTest_QUIC_PARAM_CONN_SHARE_UDP_BINDING(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_SHARE_UDP_BINDING");
    BOOLEAN Data = TRUE;
    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    //
    // SetParam
    //
    {
        TestScopeLogger LogScope1("SetParam");
        //
        // QUIC_CONN_BAD_START_STATE
        //
        {
            TestScopeLogger LogScope2("QUIC_CONN_BAD_START_STATE");
            MsQuicConnection ConnInval(Registration);
            SimulateConnBadStartState(ConnInval, ClientConfiguration);

            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                ConnInval.SetParam(
                    QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                    sizeof(Data),
                    &Data));
        }


        //
        // Good
        //
        {
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                    sizeof(Data),
                    &Data));
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope2("GetParam");
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_SHARE_UDP_BINDING, sizeof(BOOLEAN), &Data);
    }
}

void QuicTest_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint16_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT,
                sizeof(Dummy),
                &Dummy));
    }

    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        // There is no stream yet
        uint16_t Count = 0;
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT, sizeof(uint16_t), &Count);
    }
}

void QuicTest_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint16_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT,
                sizeof(Dummy),
                &Dummy));
    }

    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        // There is no stream yet
        uint16_t Count = 0;
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT, sizeof(uint16_t), &Count);
    }
}

void QuicTest_QUIC_PARAM_CONN_MAX_STREAM_IDS(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_MAX_STREAM_IDS");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint16_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_MAX_STREAM_IDS,
                sizeof(Dummy),
                &Dummy));
    }

    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        // There is no stream yet
        // 4 is defined in stream.h as NUMBER_OF_STREAM_TYPES
        uint8_t NumberOfStreamTypes = 4;
        uint64_t IDs[4] = {0, 1, 2, 3}; // Refer quicStreamSetGetMaxStreamIDs()
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_MAX_STREAM_IDS, sizeof(uint64_t) * NumberOfStreamTypes, IDs);
    }
}

void QuicTest_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_CLOSE_REASON_PHRASE");
    MsQuicConnection Connection(Registration); // shared with Set/GetParam
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    char MainReason[] = "This is main reason";
    {
        TestScopeLogger LogScope1("SetParam");
        // //
        // // BufferLength is longer than QUIC_MAX_CONN_CLOSE_REASON_LENGTH
        // //
        // {
        //     TestScopeLogger LogScope2("BufferLength is longer than QUIC_MAX_CONN_CLOSE_REASON_LENGTH");
        //     MsQuicConnection ConnInval(Registration);
        //     TEST_QUIC_SUCCEEDED(ConnInval.GetInitStatus());
        //     char Reason[2048] = {};
        //     TEST_QUIC_STATUS(
        //         QUIC_STATUS_INVALID_PARAMETER,
        //         ConnInval.SetParam(
        //             QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,
        //             sizeof(Reason),
        //             &Reason));
        // }

    //     //
    //     // Non null termination
    //     //
    //     {
    //         TestScopeLogger LogScope2("Non null termination");
    //         MsQuicConnection ConnInval(Registration);
    //         TEST_QUIC_SUCCEEDED(ConnInval.GetInitStatus());
    //         char Reason[] = "This is reason";
    //         Reason[sizeof(Reason)-1] = 'X';
    //         TEST_QUIC_STATUS(
    //             QUIC_STATUS_INVALID_PARAMETER,
    //             ConnInval.SetParam(
    //                 QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,
    //                 sizeof(Reason),
    //                 &Reason));
    //     }

        //
        // Good, set twice to call update part
        //
        {
            TestScopeLogger LogScope2("Good, set twice to call update part");
            // char ReasonDummy[] = "This is reason";
            // TEST_QUIC_SUCCEEDED(
            //     Connection.SetParam(
            //         QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,
            //         sizeof(ReasonDummy),
            //         &ReasonDummy));

            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,
                    sizeof(MainReason),
                    &MainReason));
        }
    // }

    // //
    // // GetParam
    // //
    // {
    //     //
    //     // if (Connection->CloseReasonPhrase == NULL)
    //     //
    //     {
    //         TestScopeLogger LogScope2("if (Connection->CloseReasonPhrase == NULL)");
    //         MsQuicConnection ConnInval(Registration);
    //         TEST_QUIC_SUCCEEDED(ConnInval.GetInitStatus());
    //         uint32_t Length = 0;
    //         TEST_QUIC_STATUS(
    //             QUIC_STATUS_NOT_FOUND,
    //             ConnInval.GetParam(
    //                 QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,
    //                 &Length,
    //                 nullptr));
    //     }

    //     //
    //     // Good
    //     //
    //     {
    //         SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_CLOSE_REASON_PHRASE, 0, nullptr);
    //         //SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_CLOSE_REASON_PHRASE, sizeof(MainReason), MainReason);
    //     }
    }
}

void QuicTest_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME");
    {
        TestScopeLogger LogScope1("SetParam");
        {
            //
            // Invalid scheme
            //
            {
                TestScopeLogger LogScope2("Invalid scheme");
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                QUIC_STREAM_SCHEDULING_SCHEME Scheme = QUIC_STREAM_SCHEDULING_SCHEME_COUNT;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                        Connection.SetParam(
                        QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME,
                        sizeof(Scheme),
                        &Scheme));
            }

            //
            // Good
            //
            for (uint32_t Scheme = 0; Scheme < QUIC_STREAM_SCHEDULING_SCHEME_COUNT; Scheme++) {
                MsQuicConnection Connection(Registration);
                TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
                TEST_QUIC_SUCCEEDED(
                    Connection.SetParam(
                        QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME,
                        sizeof(Scheme),
                        &Scheme));
            }
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint32_t Scheme = QUIC_STREAM_SCHEDULING_SCHEME_FIFO;
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME, sizeof(QUIC_STREAM_SCHEDULING_SCHEME), &Scheme);
    }
}

void QuicTest_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED");
    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    BOOLEAN Flag = TRUE;
    {
        TestScopeLogger LogScope1("SetParam");
        //
        // QUIC_CONN_BAD_START_STATE
        //
        {
            TestScopeLogger LogScope2("QUIC_CONN_BAD_START_STATE");
            MsQuicConnection ConnInval(Registration);
            TEST_QUIC_SUCCEEDED(ConnInval.GetInitStatus());
            SimulateConnBadStartState(ConnInval, ClientConfiguration);

            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                ConnInval.SetParam(
                    QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                    sizeof(Flag),
                    &Flag));
        }

        //
        // Good
        //
        {
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                    sizeof(Flag),
                    &Flag));
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED, sizeof(BOOLEAN), &Flag);
    }
}

void QuicTest_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED");
    {
        TestScopeLogger LogScope1("SetParam is not allowed");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint8_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED,
                sizeof(Dummy),
                &Dummy));
    }

    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        BOOLEAN Enabled = TRUE;
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED, sizeof(BOOLEAN), &Enabled);
    }
}

void QuicTest_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
#ifdef QUIC_API_ENABLE_INSECURE_FEATURES
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION");
    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    BOOLEAN Flag = TRUE;
    //
    // The peer didn't negotiate the feature
    //
    {
        {
            MsQuicConnection ConnInval(Registration);
            TEST_QUIC_SUCCEEDED(ConnInval.GetInitStatus());
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                ConnInval.SetParam(
                    QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                    sizeof(Flag),
                    &Flag));
        }

        //
        // Good
        //
        {
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                    sizeof(Flag),
                    &Flag));
        }
    }

    //
    // GetParam
    //
    {
        TestScopeLogger LogScope1("GetParam");
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION, sizeof(BOOLEAN), &Flag);
    }
#else
    UNREFERENCED_PARAMETER(Registration);
    UNREFERENCED_PARAMETER(ClientConfiguration);
#endif
}

void QuicTest_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID");
    {
        TestScopeLogger LogScope1("SetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

        //
        // Good with True/False
        //
        for (uint8_t i = 0; i < 2; i++) {
            BOOLEAN Result = FALSE + i;
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID,
                    sizeof(Result),
                    &Result));
        }
    }

    {
        TestScopeLogger LogScope1("GetParam is not allowed");
    }
}

void QuicTest_QUIC_PARAM_CONN_LOCAL_INTERFACE(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_LOCAL_INTERFACE");

    uint32_t Index = 0;
    //
    // QUIC_CONN_BAD_START_STATE
    //
    {
        TestScopeLogger LogScope1("QUIC_CONN_BAD_START_STATE");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimulateConnBadStartState(Connection, ClientConfiguration);

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Connection.SetParam(
                QUIC_PARAM_CONN_LOCAL_INTERFACE,
                sizeof(Index),
                &Index));
    }

    //
    // Good
    //
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(
                QUIC_PARAM_CONN_LOCAL_INTERFACE,
                sizeof(Index),
                &Index));
    }

    {
        TestScopeLogger LogScope1("GetParam is not allowed");
    }
}

void QuicTest_QUIC_PARAM_CONN_TLS_SECRETS(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_TLS_SECRETS");
    {
        TestScopeLogger LogScope1("SetParam");
        QUIC_TLS_SECRETS Secrets = {};
        //
        // QUIC_CONN_BAD_START_STATE
        //
        {
            TestScopeLogger LogScope2("QUIC_CONN_BAD_START_STATE");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            SimulateConnBadStartState(Connection, ClientConfiguration);

            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                Connection.SetParam(
                    QUIC_PARAM_CONN_TLS_SECRETS,
                    sizeof(Secrets),
                    &Secrets));
        }

        //
        // Good
        //
        {
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_TLS_SECRETS,
                    sizeof(Secrets),
                    &Secrets));
        }
    }

    {
        TestScopeLogger LogScope1("GetParam is not allowed");
    }
}

void QuicTest_QUIC_PARAM_CONN_CIBIR_ID(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration)
{
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_CIBIR_ID");
    {
        TestScopeLogger LogScope1("SetParam");
        //
        // QUIC_CONN_BAD_START_STATE
        //
        {
            TestScopeLogger LogScope2("QUIC_CONN_BAD_START_STATE");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            SimulateConnBadStartState(Connection, ClientConfiguration);

            uint8_t Id[5] = {};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                Connection.SetParam(
                    QUIC_PARAM_CONN_CIBIR_ID,
                    sizeof(Id),
                    &Id));
        }

        //
        // !Connection->State.ShareBinding
        //
        {
            TestScopeLogger LogScope2("SharedBinding is disabled");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            uint8_t Id[4] = {};
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                Connection.SetParam(
                    QUIC_PARAM_CONN_CIBIR_ID,
                    sizeof(Id),
                    &Id));
        }


        //
        // CIBIR_ID common
        //
        {
            TestScopeLogger LogScope2("SharedBinding is enabled");
            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            BOOLEAN Flag = TRUE;
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                    sizeof(Flag),
                    &Flag));

            // Will be enabled once Listener test is merged
            // CibirIDTests(Connection.Handle, QUIC_PARAM_CONN_CIBIR_ID);
        }
    }

    {
        TestScopeLogger LogScope1("GetParam is not allowed");
    }
#else
    UNREFERENCED_PARAMETER(Registration);
    UNREFERENCED_PARAMETER(ClientConfiguration);
#endif
}

void QuicTest_QUIC_PARAM_CONN_STATISTICS_V2(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_STATISTICS_V2 is get only");
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint16_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_STATISTICS_V2,
                sizeof(Dummy),
                &Dummy));
    }

    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_STATISTICS_V2, sizeof(QUIC_STATISTICS_V2), nullptr, true);
    }
}

void QuicTest_QUIC_PARAM_CONN_STATISTICS_V2_PLAT(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_STATISTICS_V2_PLAT");
    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint16_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
                sizeof(Dummy),
                &Dummy));
    }

    {
        TestScopeLogger LogScope1("GetParam");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_STATISTICS_V2_PLAT, sizeof(QUIC_STATISTICS_V2), nullptr, true);
    }
}


void QuicTest_QUIC_PARAM_CONN_ORIG_DEST_CID(MsQuicRegistration& Registration, MsQuicConfiguration& ClientConfiguration) {
    //
    // This is the unit test for checking to see if a server has the correct original dest CID.
    //
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_ORIG_DEST_CID");
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
          Connection.Start(
              ClientConfiguration,
              QUIC_ADDRESS_FAMILY_INET,
              "localhost",
              4433));
        MsQuic->ConnectionSetConfiguration(Connection.Handle, ClientConfiguration);
        //
        // 8 bytes is the expected minimum size of the CID.
        //
        uint32_t SizeOfBuffer = 8;
        uint8_t Buffer[8] = {0};
        uint8_t ZeroBuffer[8] = {0};
        TestScopeLogger LogScope1("GetParam test success case");
        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            Connection.GetParam(
                QUIC_PARAM_CONN_ORIG_DEST_CID,
                &SizeOfBuffer,
                Buffer
            )
        )
        TEST_NOT_EQUAL(memcmp(Buffer, ZeroBuffer, sizeof(Buffer)), 0);
    }
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
          Connection.Start(
              ClientConfiguration,
              QUIC_ADDRESS_FAMILY_INET,
              "localhost",
              4433));
        uint32_t SizeOfBuffer = 8;
        TestScopeLogger LogScope1("GetParam null buffer check");
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.GetParam(
                QUIC_PARAM_CONN_ORIG_DEST_CID,
                &SizeOfBuffer,
                nullptr
            )
        )
    }
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
          Connection.Start(
              ClientConfiguration,
              QUIC_ADDRESS_FAMILY_INET,
              "localhost",
              4433));
        uint32_t SizeOfBuffer = 1;
        TestScopeLogger LogScope1("GetParam buffer too small check");
        uint8_t Buffer[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            Connection.GetParam(
                QUIC_PARAM_CONN_ORIG_DEST_CID,
                &SizeOfBuffer,
                Buffer
            )
        )
    }
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
          Connection.Start(
              ClientConfiguration,
              QUIC_ADDRESS_FAMILY_INET,
              "localhost",
              4433));
        uint32_t SizeOfBuffer = 100;
        uint8_t Buffer[100] = {0};
        uint8_t ZeroBuffer[100] = {0};
        TestScopeLogger LogScope1("GetParam size of buffer bigger than needed");
        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            Connection.GetParam(
                QUIC_PARAM_CONN_ORIG_DEST_CID,
                &SizeOfBuffer,
                Buffer
            )
        )
        TEST_NOT_EQUAL(memcmp(Buffer, ZeroBuffer, sizeof(Buffer)), 0);
        //
        // There is no way the CID written should be 100 bytes according to the RFC.
        //
        TEST_TRUE(SizeOfBuffer < 100);
    }
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(
          Connection.Start(
              ClientConfiguration,
              QUIC_ADDRESS_FAMILY_INET,
              "localhost",
              4433));
        uint32_t SizeOfBuffer = 0;
        TestScopeLogger LogScope1("GetParam check OrigDestCID size with nullptr");
        TEST_QUIC_STATUS(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            Connection.GetParam(
                QUIC_PARAM_CONN_ORIG_DEST_CID,
                &SizeOfBuffer,
                nullptr
            )
        )
        TEST_TRUE(SizeOfBuffer >= 8);
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.GetParam(
                QUIC_PARAM_CONN_ORIG_DEST_CID,
                &SizeOfBuffer,
                nullptr
            )
        )
    }
}

void QuicTest_QUIC_PARAM_CONN_SEND_DSCP(MsQuicRegistration& Registration)
{
    TestScopeLogger LogScope0("QUIC_PARAM_CONN_SEND_DSCP");
    {
        TestScopeLogger LogScope1("SetParam null buffer");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint8_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_SEND_DSCP,
                sizeof(Dummy),
                nullptr));
    }
    {
        TestScopeLogger LogScope1("SetParam zero length");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint8_t Dummy = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_SEND_DSCP,
                0,
                &Dummy));
    }
    {
        TestScopeLogger LogScope1("SetParam non-DSCP number");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint8_t Dummy = 64;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_SEND_DSCP,
                sizeof(Dummy),
                &Dummy));
        Dummy = 255;
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(
                QUIC_PARAM_CONN_SEND_DSCP,
                sizeof(Dummy),
                &Dummy));
    }
    {
        TestScopeLogger LogScope1("GetParam Default");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint8_t Dscp = 0;
        SimpleGetParamTest(Connection.Handle, QUIC_PARAM_CONN_SEND_DSCP, sizeof(Dscp), &Dscp);
    }
    {
        TestScopeLogger LogScope1("SetParam/GetParam Valid DSCP");
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        uint8_t Dscp = CXPLAT_DSCP_LE;
        uint8_t GetValue = 0;
        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            Connection.SetParam(
                QUIC_PARAM_CONN_SEND_DSCP,
                sizeof(Dscp),
                &Dscp));
        uint32_t BufferSize = sizeof(GetValue);
        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            Connection.GetParam(
                QUIC_PARAM_CONN_SEND_DSCP,
                &BufferSize,
                &GetValue));
        TEST_EQUAL(BufferSize, sizeof(GetValue));
        TEST_EQUAL(GetValue, Dscp);
    }
}

void QuicTestConnectionParam()
{
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCertCredConfig);

    QuicTest_QUIC_PARAM_CONN_QUIC_VERSION(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_LOCAL_ADDRESS(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_REMOTE_ADDRESS(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_IDEAL_PROCESSOR(Registration);
    QuicTest_QUIC_PARAM_CONN_SETTINGS(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_STATISTICS(Registration);
    QuicTest_QUIC_PARAM_CONN_STATISTICS_PLAT(Registration);
    QuicTest_QUIC_PARAM_CONN_SHARE_UDP_BINDING(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT(Registration);
    QuicTest_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT(Registration);
    QuicTest_QUIC_PARAM_CONN_MAX_STREAM_IDS(Registration);
    QuicTest_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE(Registration);
    QuicTest_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME(Registration);
    QuicTest_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED(Registration);
    QuicTest_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION(Registration, ClientConfiguration);
    // QUIC_PARAM_CONN_RESUMPTION_TICKET is covered by TestConnection.cpp and EventTest.cpp
    QuicTest_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID(Registration);
    QuicTest_QUIC_PARAM_CONN_LOCAL_INTERFACE(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_TLS_SECRETS(Registration, ClientConfiguration);
    // QUIC_PARAM_CONN_VERSION_SETTINGS is covered by QuicTestVersionSettings
    QuicTest_QUIC_PARAM_CONN_CIBIR_ID(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_STATISTICS_V2(Registration);
    QuicTest_QUIC_PARAM_CONN_STATISTICS_V2_PLAT(Registration);
    QuicTest_QUIC_PARAM_CONN_ORIG_DEST_CID(Registration, ClientConfiguration);
    QuicTest_QUIC_PARAM_CONN_SEND_DSCP(Registration);
}

//
// This test uses TEST_NOT_EQUAL(XXX, QUIC_STATUS_SUCCESS) to cover both
// OpenSSL and Schannel which return different error code.
// This need to be fixed in the future.
// see src/platform/tsl_schannel.c about the TODO
//
void QuicTestTlsParam()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCertCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());
    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(
        MsQuic->ConnectionStart(
            Connection.Handle,
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "localhost",
            4433));

    //
    // QUIC_PARAM_TLS_HANDSHAKE_INFO
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_TLS_HANDSHAKE_INFO");
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            QUIC_HANDSHAKE_INFO Dummy = {};
            TEST_QUIC_STATUS(
                QUIC_STATUS_NOT_SUPPORTED,
                Connection.SetParam(
                    QUIC_PARAM_TLS_HANDSHAKE_INFO,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                Connection.GetParam(
                    QUIC_PARAM_TLS_HANDSHAKE_INFO,
                    nullptr,
                    nullptr));

            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Connection.GetParam(
                    QUIC_PARAM_TLS_HANDSHAKE_INFO,
                    &Length,
                    nullptr));
            TEST_TRUE(Length >= sizeof(QUIC_HANDSHAKE_INFO));

            //
            // Before handshake
            //
            {
                TestScopeLogger LogScope2("Before handshake");
                QUIC_HANDSHAKE_INFO Info = {};

                TEST_NOT_EQUAL(
                    Connection.GetParam(
                        QUIC_PARAM_TLS_HANDSHAKE_INFO,
                        &Length,
                        &Info
                ), QUIC_STATUS_SUCCESS);
            }

            {
                TestScopeLogger LogScope2("Successful case is covered by TlsTest.HandshakeParamInfo*");
            }
        }
    }

    //
    // QUIC_PARAM_TLS_NEGOTIATED_ALPN
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_TLS_NEGOTIATED_ALPN is get only");
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            uint8_t Dummy[] = "MsQuicTest";
            TEST_QUIC_STATUS(
                QUIC_STATUS_NOT_SUPPORTED,
                Connection.SetParam(
                    QUIC_PARAM_TLS_NEGOTIATED_ALPN,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            {
                TestScopeLogger LogScope2("Before handshake");
                uint32_t Length = 0;
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_PARAMETER,
                    Connection.GetParam(
                        QUIC_PARAM_TLS_NEGOTIATED_ALPN,
                        &Length,
                        nullptr));

                uint8_t Dummy[] = "MsQuicTest";
                TEST_NOT_EQUAL(
                    Connection.GetParam(
                        QUIC_PARAM_TLS_NEGOTIATED_ALPN,
                        &Length,
                        &Dummy),
                    QUIC_STATUS_SUCCESS);
            }

            {
                TestScopeLogger LogScope2("Successful case is covered by TlsTest.HandshakeParamNegotiatedAlpn");
            }
        }
    }

#ifdef QUIC_TEST_SCHANNEL_FLAGS
    {
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W Data;
            TEST_QUIC_STATUS(
                QUIC_STATUS_NOT_SUPPORTED,
                Connection.SetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,
                    sizeof(Data),
                    &Data));
        }

        {
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Connection.GetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,
                    &Length,
                    nullptr));

            QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W Data;
            TEST_NOT_EQUAL(
                Connection.GetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,
                    &Length,
                    &Data),
                QUIC_STATUS_SUCCESS);
        }
    }

    {
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W Data;
            TEST_QUIC_STATUS(
                QUIC_STATUS_NOT_SUPPORTED,
                Connection.SetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W,
                    sizeof(Data),
                    &Data));
        }

        {
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Connection.GetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W,
                    &Length,
                    nullptr));

            QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W Data;
            TEST_NOT_EQUAL(
                Connection.GetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W,
                    &Length,
                    &Data),
                QUIC_STATUS_SUCCESS);
        }
    }

    {
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            HANDLE DummyHandle;
            TEST_QUIC_STATUS(
                QUIC_STATUS_NOT_SUPPORTED,
                Connection.SetParam(
                    QUIC_PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN,
                    sizeof(DummyHandle),
                    &DummyHandle));
        }

        {
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                Connection.GetParam(
                    QUIC_PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN,
                    &Length,
                    nullptr));

            HANDLE Handle;
            TEST_NOT_EQUAL(
                Connection.GetParam(
                    QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W,
                    &Length,
                    &Handle),
                QUIC_STATUS_SUCCESS);
        }
    }
#endif
}

struct TestTlsHandshakeInfoServerContext {
    MsQuicConnection** Server;
    MsQuicConfiguration* ServerConfiguration;
    QUIC_STATUS GetParamStatus;
};

QUIC_STATUS
TestTlsHandshakeInfoListenerCallback(
    _In_ MsQuicListener* /*Listener*/,
    _In_opt_ void* ListenerContext,
    _Inout_ QUIC_LISTENER_EVENT* Event)
{
    TestTlsHandshakeInfoServerContext* Context = (TestTlsHandshakeInfoServerContext*)ListenerContext;
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        *Context->Server = new(std::nothrow) MsQuicConnection(
            Event->NEW_CONNECTION.Connection,
            CleanUpManual,
            [](MsQuicConnection* Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
                if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
                    QUIC_HANDSHAKE_INFO Info = {};
                    uint32_t Length = sizeof(Info);
                    ((TestTlsHandshakeInfoServerContext*)Context)->GetParamStatus =
                        MsQuic->GetParam(
                            *Connection,
                            QUIC_PARAM_TLS_HANDSHAKE_INFO,
                            &Length,
                            &Info);
                }
                return QUIC_STATUS_SUCCESS;
            },
            Context);
        (*Context->Server)->SetConfiguration(*Context->ServerConfiguration);
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestTlsHandshakeInfo(
    _In_ bool EnableResumption
    )
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCertCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicSettings Settings;
    if (EnableResumption) {
        Settings.SetServerResumptionLevel(QUIC_SERVER_RESUME_ONLY);
    }

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    TestTlsHandshakeInfoServerContext ServerContext = { nullptr, &ServerConfiguration, QUIC_STATUS_SUCCESS };

    MsQuicListener Listener(
        Registration,
        CleanUpManual,
        TestTlsHandshakeInfoListenerCallback,
        &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    UniquePtr<MsQuicConnection> Server;
    ServerContext.Server = (MsQuicConnection**)&Server;
    Listener.Context = &ServerContext;

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, ServerLocalAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Client(Registration);
    TEST_QUIC_SUCCEEDED(Client.GetInitStatus());

    if (UseDuoNic) {
        QuicAddr RemoteAddr{QuicAddrGetFamily(ServerLocalAddr), ServerLocalAddr.GetPort()};
        QuicAddrSetToDuoNic(&RemoteAddr.SockAddr);
        TEST_QUIC_SUCCEEDED(Client.SetRemoteAddr(RemoteAddr));
    }

    TEST_QUIC_SUCCEEDED(
        Client.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_LOCALHOST_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));

    Client.HandshakeCompleteEvent.WaitForever();
    TEST_TRUE(Client.HandshakeComplete);
    TEST_TRUE(Server);
    Server->HandshakeCompleteEvent.WaitForever();
    TEST_TRUE(Server->HandshakeComplete);

    //
    // Validate the GetParam succeeded in the CONNECTED callback.
    //
    TEST_QUIC_SUCCEEDED(ServerContext.GetParamStatus);

    QUIC_HANDSHAKE_INFO Info = {};
    uint32_t Length = sizeof(Info);
    TEST_QUIC_SUCCEEDED(
        Client.GetParam(
            QUIC_PARAM_TLS_HANDSHAKE_INFO,
            &Length,
            &Info
    ));

    if (EnableResumption) {
        //
        // The server should NOT have freed the TLS state, so this
        // should succeed.
        //
        TEST_QUIC_SUCCEEDED(
            Server->GetParam(
                QUIC_PARAM_TLS_HANDSHAKE_INFO,
                &Length,
                &Info));
    } else {
        //
        // The server should have freed the TLS state by now, so this
        // should fail.
        //
        TEST_EQUAL(
            Server->GetParam(
                QUIC_PARAM_TLS_HANDSHAKE_INFO,
                &Length,
                &Info),
            QUIC_STATUS_INVALID_STATE);
    }
}

void QuicTestStreamParam()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    //
    // QUIC_PARAM_STREAM_ID
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_STREAM_ID");
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
        QUIC_UINT62 Dummy = 123;
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_ID,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_ID,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(Dummy));

            QUIC_UINT62 StreamId = 65535;
            //
            // Before Stream.Start()
            //
            {
                TestScopeLogger LogScope2("Before Stream.Start()");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    MsQuic->GetParam(
                        Stream.Handle,
                        QUIC_PARAM_STREAM_ID,
                        &Length,
                        &StreamId));
                TEST_EQUAL(StreamId, 65535);
            }

            //
            // Good
            //
            {
                Stream.Start();
                TEST_QUIC_SUCCEEDED(
                    MsQuic->GetParam(
                        Stream.Handle,
                        QUIC_PARAM_STREAM_ID,
                        &Length,
                        &StreamId));
                TEST_EQUAL(StreamId, 0); // (client) streamId start from 0
            }
        }
    }

    //
    // QUIC_PARAM_STREAM_0RTT_LENGTH
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_STREAM_0RTT_LENGTH");
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
        uint64_t Dummy = 123;
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_0RTT_LENGTH,
                    sizeof(Dummy),
                    &Dummy));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_0RTT_LENGTH,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(uint64_t));

            uint64_t ZeroRTTLength = 65535;
            //
            // Before Stream.Shutdown()
            //
            {
                TestScopeLogger LogScope2("Before Stream.Shutdown()");
                TEST_QUIC_STATUS(
                    QUIC_STATUS_INVALID_STATE,
                    MsQuic->GetParam(
                        Stream.Handle,
                        QUIC_PARAM_STREAM_0RTT_LENGTH,
                        &Length,
                        &ZeroRTTLength));
                TEST_EQUAL(ZeroRTTLength, 65535);
            }

            //
            // Good
            //
            {
                Stream.Start();

                Stream.Shutdown(0,
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                    (QUIC_STREAM_SHUTDOWN_FLAGS) 0x8000); // QUIC_STREAM_SHUTDOWN_SILENT
                TEST_QUIC_SUCCEEDED(
                    MsQuic->GetParam(
                        Stream.Handle,
                        QUIC_PARAM_STREAM_0RTT_LENGTH,
                        &Length,
                        &ZeroRTTLength));
                TEST_EQUAL(ZeroRTTLength, 0);
            }
        }
    }

    //
    // QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE");
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
        uint64_t Dummy = 123;
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,
                    sizeof(Dummy),
                    &Dummy));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(uint64_t));

            uint64_t IdealSendBufferSize = 65535;
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,
                    &Length,
                    &IdealSendBufferSize));
            TEST_EQUAL(IdealSendBufferSize, QUIC_DEFAULT_IDEAL_SEND_BUFFER_SIZE);
        }
    }

    //
    // QUIC_PARAM_STREAM_PRIORITY
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_STREAM_PRIORITY");
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
        Stream.Start(QUIC_STREAM_START_FLAG_IMMEDIATE); // IMMEDIATE to set Stream->SendFlags != 0
        uint16_t Expected = 123;
        //
        // SetParam
        //
        {
            TestScopeLogger LogScope1("SetParam");
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_PRIORITY,
                    sizeof(Expected),
                    &Expected));
        }

        //
        // GetParam
        //
        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_PRIORITY,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(uint16_t));

            uint16_t Priority = 256;
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_PRIORITY,
                    &Length,
                    &Priority));
            TEST_EQUAL(Priority, Expected);
        }
    }

    //
    // QUIC_PARAM_STREAM_STATISTICS
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_STREAM_STATISTICS");
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
        uint64_t Dummy = 123;
        {
            TestScopeLogger LogScope1("SetParam is not allowed");
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->SetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_STATISTICS,
                    sizeof(Dummy),
                    &Dummy));
        }

        {
            TestScopeLogger LogScope1("GetParam");
            uint32_t Length = 0;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_STATISTICS,
                    &Length,
                    nullptr));
            TEST_EQUAL(Length, sizeof(QUIC_STREAM_STATISTICS));

            QUIC_STREAM_STATISTICS Stats = {0};
            TEST_QUIC_STATUS(
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_STATISTICS,
                    &Length,
                    &Stats),
                    QUIC_STATUS_INVALID_STATE);

            Stream.Start();
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_STATISTICS,
                    &Length,
                    &Stats));
            TEST_EQUAL(Length, sizeof(QUIC_STREAM_STATISTICS));
        }
    }

#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
    //
    // QUIC_PARAM_STREAM_RELIABLE_OFFSET
    // QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV
    //
    {
        TestScopeLogger LogScope0("QUIC_PARAM_STREAM_RELIABLE_OFFSET");
        MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_NONE);
        uint32_t BufferSize = 1;

        //
        // GetParam Test Invalid States.
        //
        {
            TestScopeLogger LogScope1("GetParam for invalid states");
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_RELIABLE_OFFSET,
                    &BufferSize,
                    NULL));
            BufferSize = 1;
            TEST_QUIC_STATUS(
                QUIC_STATUS_BUFFER_TOO_SMALL,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV,
                    &BufferSize,
                    NULL));

            BufferSize = 64;

            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV,
                    &BufferSize,
                    NULL));
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV,
                    &BufferSize,
                    NULL));

            //
            // Should return invalid state since we haven't set it yet.
            //
            uint64_t Buffer = 10000;
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_RELIABLE_OFFSET,
                    &BufferSize,
                    &Buffer));
            Buffer = 10000;
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_STATE,
                MsQuic->GetParam(
                    Stream.Handle,
                    QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV,
                    &BufferSize,
                    &Buffer));
        }
    }
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET
}

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

    if (BufferLength < sizeof(uint64_t) * QUIC_PERF_COUNTER_MAX) {
        TEST_FAILURE("Perf counters length too small");
        return;
    }

    //
    // Test getting the full array of counters.
    //
    uint64_t Counters[QUIC_PERF_COUNTER_MAX];
    BufferLength = sizeof(Counters);
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

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
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
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

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
    _In_ MsQuicListener* /* Listener */,
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

    MsQuicListener Listener(Registration, CleanUpManual, RejectListenerCallback, RejectByClosing ? &ShutdownEvent : nullptr);
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

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
void
QuicTestVersionStorage()
{
    const uint32_t VersionList[] = {QUIC_VERSION_2_H, QUIC_VERSION_1_H};
    const uint32_t VersionListLength = ARRAYSIZE(VersionList);

#ifdef _KERNEL_MODE
#define __WIDEN(quote) L##quote
#define WIDEN(quote) __WIDEN(quote)
    DECLARE_CONST_UNICODE_STRING(GlobalStoragePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\");
    DECLARE_CONST_UNICODE_STRING(AppStoragePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest\\");
    DECLARE_CONST_UNICODE_STRING(AcceptableVersionsValueName, WIDEN(QUIC_SETTING_ACCEPTABLE_VERSIONS));
    DECLARE_CONST_UNICODE_STRING(OfferedVersionsValueName, WIDEN(QUIC_SETTING_OFFERED_VERSIONS));
    DECLARE_CONST_UNICODE_STRING(FullyDeployedVersionsValueName, WIDEN(QUIC_SETTING_FULLY_DEPLOYED_VERSIONS));
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
        (PUNICODE_STRING)&AcceptableVersionsValueName);
    ZwDeleteValueKey(
        GlobalKey,
        (PUNICODE_STRING)&OfferedVersionsValueName);
    ZwDeleteValueKey(
        GlobalKey,
        (PUNICODE_STRING)&FullyDeployedVersionsValueName);
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
#define MSQUIC_GLOBAL_PARAMETERS_PATH   "System\\CurrentControlSet\\Services\\MsQuic\\Parameters"
#define MSQUIC_APP_PARAMETERS_PATH      "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest"
    RegDeleteKeyValueA(
        HKEY_LOCAL_MACHINE,
        MSQUIC_GLOBAL_PARAMETERS_PATH,
        QUIC_SETTING_ACCEPTABLE_VERSIONS);
    RegDeleteKeyValueA(
        HKEY_LOCAL_MACHINE,
        MSQUIC_GLOBAL_PARAMETERS_PATH,
        QUIC_SETTING_OFFERED_VERSIONS);
    RegDeleteKeyValueA(
        HKEY_LOCAL_MACHINE,
        MSQUIC_GLOBAL_PARAMETERS_PATH,
        QUIC_SETTING_FULLY_DEPLOYED_VERSIONS);
    RegDeleteKeyA(
        HKEY_LOCAL_MACHINE,
        MSQUIC_APP_PARAMETERS_PATH);
    HKEY Key;
    RegCreateKeyA(
        HKEY_LOCAL_MACHINE,
        MSQUIC_APP_PARAMETERS_PATH,
        &Key);
    RegCloseKey(Key);
#else
    TEST_FAILURE("Storage tests not supported on this platform");
#endif

    MsQuicVersionSettings Settings{};

    //
    // Global settings
    //

    TEST_QUIC_SUCCEEDED(Settings.GetGlobal());
    TEST_EQUAL(Settings.AcceptableVersionsLength, 0);
    TEST_EQUAL(Settings.OfferedVersionsLength, 0);
    TEST_EQUAL(Settings.FullyDeployedVersionsLength, 0);
    TEST_EQUAL(Settings.AcceptableVersions, nullptr);
    TEST_EQUAL(Settings.OfferedVersions, nullptr);
    TEST_EQUAL(Settings.FullyDeployedVersions, nullptr);

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            GlobalKey,
            (PUNICODE_STRING)&AcceptableVersionsValueName,
            0,
            REG_BINARY,
            (PVOID)&VersionList,
            sizeof(VersionList)));
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            GlobalKey,
            (PUNICODE_STRING)&OfferedVersionsValueName,
            0,
            REG_BINARY,
            (PVOID)&VersionList,
            sizeof(VersionList)));
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            GlobalKey,
            (PUNICODE_STRING)&FullyDeployedVersionsValueName,
            0,
            REG_BINARY,
            (PVOID)&VersionList,
            sizeof(VersionList)));
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_GLOBAL_PARAMETERS_PATH,
            QUIC_SETTING_ACCEPTABLE_VERSIONS,
            REG_BINARY,
            &VersionList,
            sizeof(VersionList)));
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_GLOBAL_PARAMETERS_PATH,
            QUIC_SETTING_OFFERED_VERSIONS,
            REG_BINARY,
            &VersionList,
            sizeof(VersionList)));
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_GLOBAL_PARAMETERS_PATH,
            QUIC_SETTING_FULLY_DEPLOYED_VERSIONS,
            REG_BINARY,
            &VersionList,
            sizeof(VersionList)));
#endif

    CxPlatSleep(100);
    uint8_t Scratch[sizeof(QUIC_VERSION_SETTINGS) + (3 * sizeof(VersionList))];
    MsQuicVersionSettings* ReadSettings = (MsQuicVersionSettings*)Scratch;
    uint32_t ReadSize = sizeof(Scratch);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
            &ReadSize,
            ReadSettings));
    TEST_EQUAL(ReadSettings->AcceptableVersionsLength, VersionListLength);
    TEST_EQUAL(ReadSettings->OfferedVersionsLength, VersionListLength);
    TEST_EQUAL(ReadSettings->FullyDeployedVersionsLength, VersionListLength);
    for (uint32_t i = 0; i < ReadSettings->AcceptableVersionsLength; i++) {
        TEST_EQUAL(CxPlatByteSwapUint32(ReadSettings->AcceptableVersions[i]), VersionList[i]);
    }
    for (uint32_t i = 0; i < ReadSettings->OfferedVersionsLength; i++) {
        TEST_EQUAL(CxPlatByteSwapUint32(ReadSettings->OfferedVersions[i]), VersionList[i]);
    }
    for (uint32_t i = 0; i < ReadSettings->FullyDeployedVersionsLength; i++) {
        TEST_EQUAL(CxPlatByteSwapUint32(ReadSettings->FullyDeployedVersions[i]), VersionList[i]);
    }

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            GlobalKey,
            (PUNICODE_STRING)&AcceptableVersionsValueName));
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            GlobalKey,
            (PUNICODE_STRING)&OfferedVersionsValueName));
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            GlobalKey,
            (PUNICODE_STRING)&FullyDeployedVersionsValueName));
    ZwClose(GlobalKey);
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_GLOBAL_PARAMETERS_PATH,
            QUIC_SETTING_ACCEPTABLE_VERSIONS));
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_GLOBAL_PARAMETERS_PATH,
            QUIC_SETTING_OFFERED_VERSIONS));
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_GLOBAL_PARAMETERS_PATH,
            QUIC_SETTING_FULLY_DEPLOYED_VERSIONS));
#endif

    CxPlatSleep(100);
    TEST_QUIC_SUCCEEDED(Settings.GetGlobal());
    TEST_EQUAL(Settings.AcceptableVersionsLength, 0);
    TEST_EQUAL(Settings.OfferedVersionsLength, 0);
    TEST_EQUAL(Settings.FullyDeployedVersionsLength, 0);
    TEST_EQUAL(Settings.AcceptableVersions, nullptr);
    TEST_EQUAL(Settings.OfferedVersions, nullptr);
    TEST_EQUAL(Settings.FullyDeployedVersions, nullptr);

    //
    // App settings
    //

    MsQuicRegistration Registration("StorageTest");
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration Configuration(Registration, "MsQuicTest");
    TEST_TRUE(Configuration.IsValid());

    ReadSize = sizeof(Settings);
    TEST_QUIC_SUCCEEDED(Configuration.GetVersionSettings(Settings, &ReadSize));
    TEST_EQUAL(Settings.AcceptableVersionsLength, 0);
    TEST_EQUAL(Settings.OfferedVersionsLength, 0);
    TEST_EQUAL(Settings.FullyDeployedVersionsLength, 0);
    TEST_EQUAL(Settings.AcceptableVersions, nullptr);
    TEST_EQUAL(Settings.OfferedVersions, nullptr);
    TEST_EQUAL(Settings.FullyDeployedVersions, nullptr);

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            AppKey,
            (PUNICODE_STRING)&AcceptableVersionsValueName,
            0,
            REG_BINARY,
            (PVOID)&VersionList,
            sizeof(VersionList)));
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            AppKey,
            (PUNICODE_STRING)&OfferedVersionsValueName,
            0,
            REG_BINARY,
            (PVOID)&VersionList,
            sizeof(VersionList)));
    TEST_QUIC_SUCCEEDED(
        ZwSetValueKey(
            AppKey,
            (PUNICODE_STRING)&FullyDeployedVersionsValueName,
            0,
            REG_BINARY,
            (PVOID)&VersionList,
            sizeof(VersionList)));
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_APP_PARAMETERS_PATH,
            QUIC_SETTING_ACCEPTABLE_VERSIONS,
            REG_BINARY,
            &VersionList,
            sizeof(VersionList)));
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_APP_PARAMETERS_PATH,
            QUIC_SETTING_OFFERED_VERSIONS,
            REG_BINARY,
            &VersionList,
            sizeof(VersionList)));
    TEST_EQUAL(
        NO_ERROR,
        RegSetKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_APP_PARAMETERS_PATH,
            QUIC_SETTING_FULLY_DEPLOYED_VERSIONS,
            REG_BINARY,
            &VersionList,
            sizeof(VersionList)));
#endif

    CxPlatSleep(100);
    ReadSize = sizeof(Scratch);
    TEST_QUIC_SUCCEEDED(Configuration.GetVersionSettings(*ReadSettings, &ReadSize));
    TEST_EQUAL(ReadSettings->AcceptableVersionsLength, VersionListLength);
    TEST_EQUAL(ReadSettings->OfferedVersionsLength, VersionListLength);
    TEST_EQUAL(ReadSettings->FullyDeployedVersionsLength, VersionListLength);
    for (uint32_t i = 0; i < ReadSettings->AcceptableVersionsLength; i++) {
        TEST_EQUAL(CxPlatByteSwapUint32(ReadSettings->AcceptableVersions[i]), VersionList[i]);
    }
    for (uint32_t i = 0; i < ReadSettings->OfferedVersionsLength; i++) {
        TEST_EQUAL(CxPlatByteSwapUint32(ReadSettings->OfferedVersions[i]), VersionList[i]);
    }
    for (uint32_t i = 0; i < ReadSettings->FullyDeployedVersionsLength; i++) {
        TEST_EQUAL(CxPlatByteSwapUint32(ReadSettings->FullyDeployedVersions[i]), VersionList[i]);
    }

#ifdef _KERNEL_MODE
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            AppKey,
            (PUNICODE_STRING)&AcceptableVersionsValueName));
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            AppKey,
            (PUNICODE_STRING)&OfferedVersionsValueName));
    TEST_QUIC_SUCCEEDED(
        ZwDeleteValueKey(
            AppKey,
            (PUNICODE_STRING)&FullyDeployedVersionsValueName));
    ZwClose(AppKey);
#elif _WIN32
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_APP_PARAMETERS_PATH,
            QUIC_SETTING_ACCEPTABLE_VERSIONS));
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_APP_PARAMETERS_PATH,
            QUIC_SETTING_OFFERED_VERSIONS));
    TEST_EQUAL(
        NO_ERROR,
        RegDeleteKeyValueA(
            HKEY_LOCAL_MACHINE,
            MSQUIC_APP_PARAMETERS_PATH,
            QUIC_SETTING_FULLY_DEPLOYED_VERSIONS));
#endif

    CxPlatSleep(100);
    ReadSize = sizeof(Settings);
    TEST_QUIC_SUCCEEDED(Configuration.GetVersionSettings(Settings, &ReadSize));
    TEST_EQUAL(Settings.AcceptableVersionsLength, 0);
    TEST_EQUAL(Settings.OfferedVersionsLength, 0);
    TEST_EQUAL(Settings.FullyDeployedVersionsLength, 0);
    TEST_EQUAL(Settings.AcceptableVersions, nullptr);
    TEST_EQUAL(Settings.OfferedVersions, nullptr);
    TEST_EQUAL(Settings.FullyDeployedVersions, nullptr);
}

void
QuicTestValidateConnectionPoolCreate()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration Configuration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_TRUE(Configuration.IsValid());

    {
        TestScopeLogger logScope("All parameters NULL");
        TEST_QUIC_STATUS(QUIC_STATUS_INVALID_PARAMETER, MsQuic->ConnectionPoolCreate(NULL, NULL));
    }

    {
        TestScopeLogger logScope("Config NULL");
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                nullptr,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("ConnectionPool NULL");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                nullptr));
    }

    {
        TestScopeLogger logScope("No Registration");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = nullptr;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 443;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 1;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("No Configuration");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = nullptr;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 443;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 1;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("Zero Connections");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 443;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 0;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("Missing Connection Callback");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = nullptr;
        Config.ServerPort = 443;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 1;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("Invalid Address Family");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 443;
        Config.Family = (QUIC_ADDRESS_FAMILY)3;
        Config.NumberOfConnections = 1;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("Invalid Server port");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 0;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 1;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("Non-Null CIBIR, zero count");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 443;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 1;
        Config.CibirIds = (uint8_t**)0x1;
        Config.CibirIdLength = 0;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }

    {
        TestScopeLogger logScope("Null CIBIR, non-zero count");
        QUIC_CONNECTION_POOL_CONFIG Config{};
        Config.Registration = Registration;
        Config.Configuration = Configuration;
        Config.ServerName = "localhost";
        Config.Handler = (QUIC_CONNECTION_CALLBACK_HANDLER)0x1;
        Config.ServerPort = 443;
        Config.Family = QUIC_ADDRESS_FAMILY_UNSPEC;
        Config.NumberOfConnections = 1;
        Config.CibirIds = nullptr;
        Config.CibirIdLength = 1;
        HQUIC ConnectionPool[1];
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->ConnectionPoolCreate(
                &Config,
                ConnectionPool));
    }
}
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
