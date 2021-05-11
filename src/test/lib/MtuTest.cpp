/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic MTU Unittest

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "MtuTest.cpp.clog.h"
#endif

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

void
QuicTestMtuSettings()
{
    {
        //
        // Test setting on library works
        //
        MsQuicSettings CurrentSettings;
        uint32_t SettingsSize = sizeof(CurrentSettings);
        TEST_QUIC_SUCCEEDED(
            MsQuic->GetParam(
                NULL,
                QUIC_PARAM_LEVEL_GLOBAL,
                QUIC_PARAM_GLOBAL_SETTINGS,
                &SettingsSize,
                &CurrentSettings));

        MsQuicSettings NewSettings;
        NewSettings.SetMinimumMtu(1400).SetMaximumMtu(1400);
        QUIC_STATUS SetSuccess =
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_LEVEL_GLOBAL,
                QUIC_PARAM_GLOBAL_SETTINGS,
                sizeof(NewSettings),
                &NewSettings);

        MsQuicSettings UpdatedSettings;
        SettingsSize = sizeof(UpdatedSettings);
        QUIC_STATUS GetSuccess =
            MsQuic->GetParam(
                NULL,
                QUIC_PARAM_LEVEL_GLOBAL,
                QUIC_PARAM_GLOBAL_SETTINGS,
                &SettingsSize,
                &UpdatedSettings);

        CurrentSettings.IsSetFlags = 0;
        CurrentSettings.IsSet.MaximumMtu = TRUE;
        CurrentSettings.IsSet.MinimumMtu = TRUE;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_LEVEL_GLOBAL,
                QUIC_PARAM_GLOBAL_SETTINGS,
                sizeof(CurrentSettings),
                &CurrentSettings));

        TEST_QUIC_SUCCEEDED(SetSuccess);
        TEST_QUIC_SUCCEEDED(GetSuccess);

        TEST_EQUAL(NewSettings.MinimumMtu, UpdatedSettings.MinimumMtu);
        TEST_EQUAL(NewSettings.MaximumMtu, UpdatedSettings.MaximumMtu);
    }

    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    {
        MsQuicCredentialConfig ClientCredConfig;
        MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
        TEST_TRUE(ClientConfiguration.IsValid());

        MsQuicSettings Settings;

        //
        // Set out of range, correct order. This should just corce our boundaries.
        //
        Settings.SetMaximumMtu(0xFFFF).SetMinimumMtu(1);

        TEST_QUIC_STATUS(
            QUIC_STATUS_SUCCESS,
            MsQuic->SetParam(
                ClientConfiguration,
                QUIC_PARAM_LEVEL_CONFIGURATION,
                QUIC_PARAM_CONFIGURATION_SETTINGS,
                sizeof(Settings),
                &Settings));

        //
        // Set Inverse Order
        //
        Settings.SetMaximumMtu(1300).SetMinimumMtu(1400);

        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            MsQuic->SetParam(
                ClientConfiguration,
                QUIC_PARAM_LEVEL_CONFIGURATION,
                QUIC_PARAM_CONFIGURATION_SETTINGS,
                sizeof(Settings),
                &Settings));

        MsQuicSettings ServerSettings;
        MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
        TEST_TRUE(ServerConfiguration.IsValid());

        TestListener MyListener(Registration, ListenerAcceptCallback, ServerConfiguration);
        TEST_TRUE(MyListener.IsValid());

        UniquePtr<TestConnection> Server;
        MyListener.Context = &Server;

        {
            TestConnection Client(Registration);
            TEST_TRUE(Client.IsValid());
                TEST_QUIC_SUCCEEDED(MyListener.Start(Alpn, Alpn.Length()));
                QuicAddr ServerLocalAddr;
                TEST_QUIC_SUCCEEDED(MyListener.GetLocalAddr(ServerLocalAddr));

            //
            // Set connection settings before open
            //
            Settings.SetMaximumMtu(1450).SetMinimumMtu(1280);
            TEST_QUIC_SUCCEEDED(Client.SetSettings(Settings));

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

            //
            // Set connection settings after open
            //
            Settings.SetMaximumMtu(1400).SetMinimumMtu(1300);
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                Client.SetSettings(Settings));

            QUIC_SETTINGS CheckSettings = Client.GetSettings();
            TEST_EQUAL(1450, CheckSettings.MaximumMtu);
            TEST_EQUAL(1280, CheckSettings.MinimumMtu);
        }
    }
}
