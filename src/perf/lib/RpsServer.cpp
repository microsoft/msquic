/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf RPS Server Implementation.

--*/

#include "RpsServer.h"

#ifdef QUIC_CLOG
#include "RpsServer.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "RPS Server options:\n"
        "\n"
        "  -iter:<####>                The number of client iterations run. (def:%u)\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -thumbprint:<cert_hash>     The hash or thumbprint of the certificate to use.\n"
        "  -cert_store:<store name>    The certificate store to search for the thumbprint in.\n"
        "  -machine_cert:<0/1>         Use the machine, or current user's, certificate store. (def:0)\n"
        "  -response:<####>            The length of response payloads. (def:%u)\n"
        "\n",
        RPS_DEFAULT_ITERATIONS,
        RPS_DEFAULT_PORT,
        RPS_DEFAULT_RESPONSE_LENGTH
        );
}

RpsServer::RpsServer(
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    ) : SelfSignedConfig(SelfSignedConfig) {
    if (Session.IsValid()) {
        Session.SetAutoCleanup();
        Session.SetPeerBidiStreamCount(RPS_MAX_BIDI_STREAM_COUNT);
        Session.SetDisconnectTimeout(RPS_DEFAULT_DISCONNECT_TIMEOUT);
        Session.SetIdleTimeout(RPS_DEFAULT_IDLE_TIMEOUT);
    }
}

RpsServer::~RpsServer() {
    if (ResponseBuffer) {
        QUIC_FREE(ResponseBuffer);
    }
}

QUIC_STATUS
RpsServer::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (argc > 0 && (IsArg(argv[0], "?") || IsArg(argv[0], "help"))) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (!Listener.IsValid()) {
        return Listener.GetInitStatus();
    }

    TryGetValue(argc, argv, "iter", &Iterations);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "response", &ResponseLength);

    ResponseBuffer = (QUIC_BUFFER*)QUIC_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + ResponseLength);
    if (!ResponseBuffer) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    ResponseBuffer->Length = ResponseLength;
    ResponseBuffer->Buffer = (uint8_t*)(ResponseBuffer + 1);
    for (uint32_t i = 0; i < ResponseLength; ++i) {
        ResponseBuffer->Buffer[i] = (uint8_t)i;
    }

    return SecurityConfig.Initialize(argc, argv, Registration, SelfSignedConfig);
}

QUIC_STATUS
RpsServer::Start(
    _In_ QUIC_EVENT* StopEvent
    ) {
    QUIC_ADDR Address;
    QuicAddrSetFamily(&Address, AF_UNSPEC);
    QuicAddrSetPort(&Address, Port);

    CompletionEvent = StopEvent;

    return
        Listener.Start(
            &Address,
            [](HQUIC Handle, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                return ((RpsServer*)Context)->ListenerCallback(Handle, Event);
            },
            this);
}

QUIC_STATUS
RpsServer::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        QuicEventWaitWithTimeout(*CompletionEvent, Timeout);
    } else {
        QuicEventWaitForever(*CompletionEvent);
    }
    Session.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsServer::ListenerCallback(
    _In_ HQUIC /* ListenerHandle */,
    _Inout_ QUIC_LISTENER_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        QUIC_CONNECTION_CALLBACK_HANDLER Handler =
            [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                return ((RpsServer*)Context)->
                    ConnectionCallback(
                        Conn,
                        Event);
            };
        BOOLEAN Opt = FALSE;
        MsQuic->SetParam(
            Event->NEW_CONNECTION.Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_SEND_BUFFERING,
            sizeof(Opt),
            &Opt);
        MsQuic->SetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            (void*)Handler,
            this);
        InterlockedIncrement((volatile long*)&ActiveConnectionCount);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsServer::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(ConnectionHandle);
        if (InterlockedDecrement((volatile long*)&ActiveConnectionCount) == 0) {
            if (InterlockedDecrement((volatile long*)&Iterations) == 0) {
                QuicEventSet(*CompletionEvent);
            }
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        QUIC_STREAM_CALLBACK_HANDLER Handler =
            [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
                return ((RpsServer*)Context)->
                    StreamCallback(
                        Stream,
                        Event);
            };
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)Handler, this);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsServer::StreamCallback(
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamSend(StreamHandle, ResponseBuffer, 1, QUIC_SEND_FLAG_FIN, nullptr);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        MsQuic->StreamClose(StreamHandle);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}
