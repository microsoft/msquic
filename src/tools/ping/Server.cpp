/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Server Implementation.

--*/

#include "QuicPing.h"

struct PingServer {

    HQUIC QuicListener;

    PingServer() : QuicListener(nullptr) { }

    ~PingServer() {
        if (QuicListener) {
            MsQuic->ListenerClose(QuicListener);
        }
    }

    bool Start() {
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
            if (IsPsciAlpn(
                    Event->NEW_CONNECTION.Info->NegotiatedAlpn,
                    Event->NEW_CONNECTION.Info->NegotiatedAlpnLength)) {
                auto Connection = new PingPsciConnection(true, Event->NEW_CONNECTION.Connection);
                if (Connection != NULL) {
                    Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
                }
            } else {
                auto Connection = new PingConnection(true, Event->NEW_CONNECTION.Connection);
                if (Connection != NULL) {
                    Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
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
    QuicSession SessionHelper;
    if (QUIC_FAILED(
        MsQuic->SessionOpen(
            Registration,
            PingConfig.ALPN,
            PingConfig.AlpnCount,
            NULL,
            &SessionHelper.Handle))) {
        printf("MsQuic->SessionOpen failed!\n");
        return;
    }
    Session = SessionHelper.Handle;

    if (PingConfig.MaxBytesPerKey != UINT64_MAX &&
        QUIC_FAILED(
        MsQuic->SetParam(
            Session,
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
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(ResumeLevel),
            &ResumeLevel))) {
        printf("MsQuic.SetParam (SESSION_SERVER_RESUMPTION_LEVEL) failed!\n");
        return;
    }

    {
        PingServer Server;
        if (!Server.Start()) {
            printf("Failed to start the listener!\n");
            return;
        }

        if (PingConfig.ConnectionCount > 0) {
            for (uint32_t i = 0; i < PingConfig.ConnectionCount; i++) {
                Tracker.AddItem();
            }
            Tracker.Start();
            printf("Ready For Connections!\n\n");
            //
            // An explicit flush is needed in order to be detected in real time by the test runner
            //
            fflush(stdout);
            Tracker.WaitForever();
        } else {
            printf("Press Enter to exit.\n\n");
            getchar();
        }
    }

    SessionHelper.Cancel();
}
