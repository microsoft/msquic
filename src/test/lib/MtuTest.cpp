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

struct MtuTestContext {
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        MtuTestContext* Ctx = static_cast<MtuTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->ShutdownEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

static QUIC_STATUS MtuStreamCallback(_In_ MsQuicStream*, _In_opt_ void*, _Inout_ QUIC_STREAM_EVENT*) {
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS MtuSettingsCallback(_In_ MsQuicConnection*, _In_opt_ void*, _Inout_ QUIC_CONNECTION_EVENT* Event) {
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, MtuStreamCallback, nullptr);
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestMtuSettings()
{
    {
        //
        // Test setting on library works
        //
        MsQuicSettings CurrentSettings;
        TEST_QUIC_SUCCEEDED(CurrentSettings.GetGlobal());

        MsQuicSettings NewSettings;
        QUIC_STATUS SetSuccess =
            NewSettings.
                SetMinimumMtu(1400).
                SetMaximumMtu(1400).
                SetGlobal();

        MsQuicSettings UpdatedSettings;
        QUIC_STATUS GetSuccess = UpdatedSettings.GetGlobal();

        CurrentSettings.IsSetFlags = 0;
        CurrentSettings.IsSet.MaximumMtu = TRUE;
        CurrentSettings.IsSet.MinimumMtu = TRUE;
        TEST_QUIC_SUCCEEDED(CurrentSettings.SetGlobal());

        TEST_QUIC_SUCCEEDED(SetSuccess);
        TEST_QUIC_SUCCEEDED(GetSuccess);

        TEST_EQUAL(NewSettings.MinimumMtu, UpdatedSettings.MinimumMtu);
        TEST_EQUAL(NewSettings.MaximumMtu, UpdatedSettings.MaximumMtu);
    }

    MsQuicRegistration Registration;
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());
    MsQuicAlpn Alpn("MsQuicTest");
    {
        {
            MsQuicCredentialConfig ClientCredConfig;
            MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
            TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

            MsQuicSettings Settings;

            //
            // Set out of range, correct order. This should just coerce our boundaries.
            //
            Settings.SetMaximumMtu(0xFFFF).SetMinimumMtu(1);

            TEST_QUIC_SUCCEEDED(ClientConfiguration.SetSettings(Settings));

            //
            // Invalid: Set Max < Min
            //
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                ClientConfiguration.SetSettings(
                    MsQuicSettings().SetMaximumMtu(1300).SetMinimumMtu(1400)));
        }

        MsQuicSettings ServerSettings;
        MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
        TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MtuSettingsCallback, nullptr);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        const uint16_t MinimumMtu = 1248;

        {
            MsQuicSettings Settings;
            Settings.SetMaximumMtu(1450).SetMinimumMtu(MinimumMtu);

            MsQuicCredentialConfig ClientCredConfig;
            MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
            TEST_TRUE(ClientConfiguration.IsValid());

            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
            TEST_QUIC_SUCCEEDED(Connection.StartLocalhost(ClientConfiguration, ServerLocalAddr));

            //
            // Set connection settings after open, should fail
            //
            Settings.SetMaximumMtu(1400).SetMinimumMtu(1300);
            TEST_QUIC_STATUS(
                QUIC_STATUS_INVALID_PARAMETER,
                Connection.SetSettings(Settings));

            MsQuicSettings CheckSettings;
            TEST_QUIC_SUCCEEDED(Connection.GetSettings(&CheckSettings));

            Connection.Shutdown(1);

            TEST_EQUAL(1450, CheckSettings.MaximumMtu);
            TEST_EQUAL(MinimumMtu, CheckSettings.MinimumMtu);
        }
    }

    {
        MsQuicSettings ServerSettings;
        ServerSettings.
            SetMaximumMtu(1500).
            SetMinimumMtu(1280).
            SetPeerUnidiStreamCount(1).
            SetIdleTimeoutMs(30000).
            SetDisconnectTimeoutMs(30000);
        MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSettings, ServerSelfSignedCredConfig);
        TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MtuSettingsCallback, nullptr);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

        {
            MsQuicSettings Settings;
            Settings.
                SetMaximumMtu(1500).
                SetMinimumMtu(1280).
                SetMtuDiscoveryMissingProbeCount(1).
                SetPeerUnidiStreamCount(1).
                SetIdleTimeoutMs(30000).
                SetDisconnectTimeoutMs(30000);

            MsQuicCredentialConfig ClientCredConfig;
            MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
            TEST_TRUE(ClientConfiguration.IsValid());

            MsQuicConnection Connection(Registration);
            TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

            MtuDropHelper ServerDropper(
                0,
                ServerLocalAddr.GetPort(),
                1499);
            TEST_QUIC_SUCCEEDED(Connection.StartLocalhost(ClientConfiguration, ServerLocalAddr));
            MsQuicStream Stream(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
            TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());

            //
            // Send a bunch of data.
            //
            uint8_t RawBuffer[100];
            QUIC_BUFFER Buffer { sizeof(RawBuffer), RawBuffer };
            TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START));
            CxPlatSleep(50);
            for (int i = 0; i < 10; i++) {
                TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_NONE));
                CxPlatSleep(50);
            }

            //
            // Ensure our MTU is in the middle somewhere
            //
            QUIC_STATISTICS Stats;
            TEST_QUIC_SUCCEEDED(Connection.GetStatistics(&Stats));
            TEST_NOT_EQUAL(1500, Stats.Send.PathMtu);
            TEST_NOT_EQUAL(1280, Stats.Send.PathMtu);

            ServerDropper.ClientDropPacketSize = 0xFFFF;

            TEST_QUIC_SUCCEEDED(Connection.SetSettings(MsQuicSettings().SetMtuDiscoverySearchCompleteTimeoutUs(1)));

            // Send a bunch more data
            for (int i = 0; i < 10; i++) {
                TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_NONE));
                CxPlatSleep(50);
            }

            //
            // Ensure our MTU is in the max
            //
            TEST_QUIC_SUCCEEDED(Connection.GetStatistics(&Stats));
            TEST_EQUAL(1500, Stats.Send.PathMtu);

            TEST_QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_FIN));

            Stream.Shutdown(1);
            Connection.Shutdown(1);
        }
    }
}

void
QuicTestMtuDiscovery(
    _In_ int Family,
    _In_ BOOLEAN DropClientProbePackets,
    _In_ BOOLEAN DropServerProbePackets,
    _In_ BOOLEAN RaiseMinimumMtu
    )
{
    MsQuicRegistration Registration;
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    const uint16_t MinimumMtu = RaiseMinimumMtu ? 1360 : 1248;
    const uint16_t MaximumMtu = 1500;

    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicSettings Settings;
    Settings.SetMinimumMtu(MinimumMtu).SetMaximumMtu(MaximumMtu).SetIdleTimeoutMs(30000).SetDisconnectTimeoutMs(30000);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, Settings, ClientCredConfig);
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MtuTestContext Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MtuTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MtuDropHelper ServerDropper(
        DropServerProbePackets ? MinimumMtu : 0,
        ServerLocalAddr.GetPort(),
        DropClientProbePackets ? MinimumMtu : 0);
    uint16_t ServerExpectedMtu = DropServerProbePackets ? MinimumMtu : MaximumMtu;
    uint16_t ClientExpectedMtu = DropClientProbePackets ? MinimumMtu : MaximumMtu;

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.StartLocalhost(ClientConfiguration, ServerLocalAddr));

    CxPlatSleep(4000); // Wait for the first idle period to expire.
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Assert our maximum MTUs
    //
    QUIC_STATISTICS ClientStats;
    QUIC_STATUS ClientSuccess = Connection.GetStatistics(&ClientStats);
    QUIC_STATISTICS ServerStats;
    QUIC_STATUS ServerSuccess = Context.Connection->GetStatistics(&ServerStats);

    Connection.Shutdown(1);
    Context.Connection->Shutdown(1);

    TEST_QUIC_SUCCEEDED(ClientSuccess);
    TEST_QUIC_SUCCEEDED(ServerSuccess);

    TEST_EQUAL(ClientExpectedMtu, ClientStats.Send.PathMtu);
    TEST_EQUAL(ServerExpectedMtu, ServerStats.Send.PathMtu);

    Context.ShutdownEvent.WaitTimeout(2000);
}
