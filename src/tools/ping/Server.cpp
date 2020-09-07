/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Server Implementation.

--*/

#include "QuicPing.h"

struct PingServer {

    HQUIC QuicListener;

    PingTracker Tracker;

    PingServer() : QuicListener(nullptr) { }

    ~PingServer() {
        if (QuicListener) {
            MsQuic->ListenerClose(QuicListener);
        }
    }

    bool Start(HQUIC Session) {
        if (QUIC_FAILED(
            MsQuic->ListenerOpen(
                Session,
                QuicCallbackHandler,
                this,
                &QuicListener))) {
            printf("MsQuic->ListenerOpen failed!\n");
            return false;
        }
        if (QUIC_FAILED(
            MsQuic->ListenerStart(
                QuicListener,
                &PingConfig.LocalIpAddr))) {
            printf("MsQuic->ListenerStart failed!\n");
        }
        return true;
    }

    void
    ProcessEvent(
        _Inout_ QUIC_LISTENER_EVENT* Event
        ) {
        switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            auto Connection = new PingConnection(&Tracker, Event->NEW_CONNECTION.Connection);
            if (Connection != NULL) {
                Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
                if (!Connection->Initialize(true)) {
                    delete Connection;
                }
            }
            break;
        }
        }
    }

    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC /* Listener */,
        _In_opt_ void* Context,
        _In_ QUIC_LISTENER_EVENT* Event
        ) {
        PingServer *pThis = (PingServer*)Context;
        pThis->ProcessEvent(Event);
        return QUIC_STATUS_SUCCESS;
    }
};

void QuicPingServerRun()
{
    QUIC_SETTINGS Settings{0};
    Settings.PeerBidiStreamCount = PingConfig.PeerBidirStreamCount;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.PeerUnidiStreamCount = PingConfig.PeerUnidirStreamCount;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.DisconnectTimeoutMs = PingConfig.DisconnectTimeout;
    Settings.IsSet.DisconnectTimeoutMs = TRUE;
    Settings.IdleTimeoutMs = PingConfig.IdleTimeout;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    if (PingConfig.MaxBytesPerKey != UINT64_MAX) {
        Settings.MaxBytesPerKey = PingConfig.MaxBytesPerKey;
        Settings.IsSet.MaxBytesPerKey = TRUE;
    }
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_ONLY;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    QuicSession Session;
    if (QUIC_FAILED(
        MsQuic->SessionOpen(
            Registration,
            sizeof(Settings),
            &Settings,
            &PingConfig.ALPN,
            1,
            NULL,
            &Session.Handle))) {
        printf("MsQuic->SessionOpen failed!\n");
        return;
    }

    {
        PingServer Server;
        if (!Server.Start(Session.Handle)) {
            printf("Failed to start the listener!\n");
            return;
        }

        if (PingConfig.ConnectionCount > 0) {
            for (uint32_t i = 0; i < PingConfig.ConnectionCount; i++) {
                Server.Tracker.AddItem();
            }
            Server.Tracker.Start();
            printf("Ready For Connections!\n\n");
            //
            // An explicit flush is needed in order to be detected in real time by the test runner
            //
            fflush(stdout);
            Server.Tracker.WaitForever();
        } else {
            printf("Press Enter to exit.\n\n");
            getchar();
        }
    }

    Session.Cancel();
}
