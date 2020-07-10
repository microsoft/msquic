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
    QuicSession Session;
    if (QUIC_FAILED(
        MsQuic->SessionOpen(
            Registration,
            &PingConfig.ALPN,
            1,
            NULL,
            &Session.Handle))) {
        printf("MsQuic->SessionOpen failed!\n");
        return;
    }
    if (QUIC_FAILED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT,
            sizeof(uint16_t),
            &PingConfig.PeerBidirStreamCount))) {
        printf("MsQuic->SetParam (SESSION_PEER_BIDI_STREAM_COUNT) failed!\n");
        return;
    }
    if (QUIC_FAILED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT,
            sizeof(uint16_t),
            &PingConfig.PeerUnidirStreamCount))) {
        printf("MsQuic->SetParam (SESSION_PEER_UNIDI_STREAM_COUNT) failed!\n");
        return;
    }
    if (QUIC_FAILED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_DISCONNECT_TIMEOUT,
            sizeof(uint32_t),
            &PingConfig.DisconnectTimeout))) {
        printf("MsQuic->SetParam (SESSION_DISCONNECT_TIMEOUT) failed!\n");
        return;
    }
    if (QUIC_FAILED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_IDLE_TIMEOUT,
            sizeof(uint64_t),
            &PingConfig.IdleTimeout))) {
        printf("MsQuic->SetParam (SESSION_IDLE_TIMEOUT) failed!\n");
        return;
    }
    if (PingConfig.MaxBytesPerKey != UINT64_MAX &&
        QUIC_FAILED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY,
            sizeof(uint64_t),
            &PingConfig.MaxBytesPerKey))) {
        printf("MsQuic.SetParam (SESSION_MAX_BYTES_PER_KEY) failed!\n");
        return;
    }
    QUIC_SERVER_RESUMPTION_LEVEL ResumeLevel = QUIC_SERVER_RESUME_ONLY;
    if (QUIC_FAILED(
        MsQuic->SetParam(
            Session.Handle,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(ResumeLevel),
            &ResumeLevel))) {
        printf("MsQuic.SetParam (SESSION_SERVER_RESUMPTION_LEVEL) failed!\n");
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
