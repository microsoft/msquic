/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This is a test server meant to be used in conjunction with spinquic. All it
    does is accept whatever the peer gives it, but constantly starts and stops
    the listener to try to trigger race condition crashes.

--*/

#include <stdio.h>

#define QUIC_TEST_APIS 1 // Needed to self signed cert API
#include <msquichelper.h>

#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(1); \
    } \
} while (0);

static QUIC_API_V1 *MsQuic;
static HQUIC Registration;
static HQUIC Session;
static HQUIC Listener;
static QUIC_SEC_CONFIG* GlobalSecurityConfig;

extern "C" void QuicTraceRundown(void) { }

QUIC_STATUS QUIC_API VoidHandleStreamEvent(HQUIC Stream, void* /* Context */, QUIC_STREAM_EVENT *Event) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API VoidHandleConnectionEvent(HQUIC Connection, void* /* Context */, QUIC_CONNECTION_EVENT *Event) {
    switch(Event->Type){
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)VoidHandleStreamEvent, nullptr);
    default:
        break;
    }
    return ERROR_SUCCESS;
}

QUIC_STATUS QUIC_API VoidHandleListenerEvent(HQUIC /* Listener */, void* /* Context */, QUIC_LISTENER_EVENT *Event) {
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        Event->NEW_CONNECTION.SecurityConfig = GlobalSecurityConfig;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)VoidHandleConnectionEvent, nullptr);
    default:
        break;
    }
    return ERROR_SUCCESS;
}

void QUIC_API VoidGetSecConfigComplete(_In_opt_ void* Context, _In_ QUIC_STATUS /* Status */, _In_opt_ QUIC_SEC_CONFIG* SecConfig) {
    auto Event = (QUIC_EVENT *)Context;
    GlobalSecurityConfig = SecConfig;
    QuicEventSet(*Event);
}

void VoidInitializeBaseObjects() {
    EXIT_ON_FAILURE(MsQuicOpen(QUIC_API_VERSION_1, (void**)&MsQuic));
    EXIT_ON_FAILURE(MsQuic->RegistrationOpen("kqnc-srv", &Registration));

    auto SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    if (!SelfSignedCertParams) {
        exit(1);
    }

    QUIC_EVENT Event;
    QuicEventInitialize(&Event, FALSE, FALSE);

    EXIT_ON_FAILURE(
        MsQuic->SecConfigCreate(
            Registration,
            (QUIC_SEC_CONFIG_FLAGS)SelfSignedCertParams->Flags,
            SelfSignedCertParams->Certificate,
            SelfSignedCertParams->Principal,
            &Event,
            VoidGetSecConfigComplete));

    QuicEventWaitForever(Event);
    QuicEventUninitialize(Event);

    if (!GlobalSecurityConfig) exit(1);
}

void VoidInitializeSessionObjects() {
    QUIC_CONST_BUFFER_STR(Alpn, "spin");
    EXIT_ON_FAILURE(MsQuic->SessionOpen(Registration, &Alpn, 1, nullptr, &Session));

    uint16_t PeerStreamCount = 9999;
    EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));
    EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));

    EXIT_ON_FAILURE(MsQuic->ListenerOpen(Session, VoidHandleListenerEvent, nullptr, &Listener);

    QUIC_ADDR sAddr = { 0 };
    QuicAddrSetFamily(&sAddr, AF_INET);
    QuicAddrSetPort(&sAddr, 9998);
    EXIT_ON_FAILURE(MsQuic->ListenerStart(Listener, &sAddr)));
}

void VoidInitialize() {
    VoidInitializeBaseObjects();
    VoidInitializeSessionObjects();
}

void VoidReset() {
    //
    // Teardown
    //
    MsQuic->ListenerClose(Listener);
    MsQuic->SessionShutdown(Session, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    MsQuic->SessionClose(Session);

    //
    // Setup
    //
    VoidInitializeSessionObjects();
}

int
QUIC_MAIN_EXPORT
main(int argc, char** argv) {
    uint64_t RunTimeMs = UINT64_MAX;
    TryGetValue(argc, argv, "timeout", &RunTimeMs);

    VoidInitialize();

    uint64_t StartTimeMs = QuicTimeMs64();
    while (QuicTimeDiff64(StartTimeMs, QuicTimeMs64()) < RunTimeMs) {
        // TODO - Try to work in some sleeps?
        VoidReset();
    }
    return 0;
}
