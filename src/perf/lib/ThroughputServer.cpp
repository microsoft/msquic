#ifdef QUIC_CLOG
#include "ThroughputServer.cpp.clog.h"
#endif

#include "ThroughputServer.h"
#include "msquichelper.h"
#include "ThroughputCommon.h"

ThroughputServer::ThroughputServer() {
    if (Session.IsValid()) {
        Session.SetAutoCleanup();
    }
}

QUIC_STATUS
ThroughputServer::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    uint16_t port = THROUGHPUT_DEFAULT_PORT;
    TryGetValue(argc, argv, "port", &port);

    const char* localAddress = nullptr;
    if (!TryGetValue(argc, argv, "listen", &localAddress)) {
        WriteOutput("Server mode must have -listen\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (!ConvertArgToAddress(localAddress, port, &Address)) {
        WriteOutput("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", localAddress);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    TryGetValue(argc, argv, "connections", &NumberOfConnections);

    QUIC_STATUS Status = SecurityConfig.Initialize(argc, argv, Registration);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::Start(QUIC_EVENT StopEvent) {

    QUIC_STATUS Status = Listener.Start(&Address, Function{ &ThroughputServer::ListenerCallback, this });
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    RefCount = CountHelper{StopEvent};
    if (NumberOfConnections > 0) {
        for (uint32_t i = 0; i < NumberOfConnections; i++) {
            RefCount.AddItem();
        }
    } else {
        //
        // Add a single item so we can wait on the Count Helper
        //
        RefCount.AddItem();
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::Wait(int Timeout) {
    if (Timeout > 0) {
        RefCount.Wait(Timeout);
    } else {
        RefCount.WaitForever();
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::ListenerCallback(HQUIC ListenerHandle, QUIC_LISTENER_EVENT* Event) {
    UNREFERENCED_PARAMETER(ListenerHandle);
    QUIC_CONNECTION_CALLBACK_HANDLER Handler;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        Handler = [](auto Conn, auto Context, auto Event) -> QUIC_STATUS {
            return ((ConnectionData*)Context)->Server->ConnectionCallback(Conn, Event, (ConnectionData*)Context);
        };
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)Handler, new ConnectionData{ this });
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::ConnectionCallback(HQUIC ConnectionHandle, QUIC_CONNECTION_EVENT* Event, ConnectionData* Connection) {
    UNREFERENCED_PARAMETER(Connection);
    QUIC_STREAM_CALLBACK_HANDLER Handler;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        WriteOutput("[conn][%p] Connected\n", ConnectionHandle);
        MsQuic->ConnectionSendResumptionTicket(ConnectionHandle, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        WriteOutput("[conn][%p] Shutdown\n", ConnectionHandle);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        WriteOutput("[conn][%p] All done\n", ConnectionHandle);
        MsQuic->ConnectionClose(ConnectionHandle);
        delete Connection;
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        WriteOutput("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        Handler = [](auto Stream, auto Context, auto Event) -> QUIC_STATUS {
            return ((StreamData*)Context)->Server->StreamCallback(Stream, Event, (StreamData*)Context);
        };
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)Handler, new StreamData{ this });
        MsQuic->ConnectionSendResumptionTicket(ConnectionHandle, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        WriteOutput("[conn][%p] Connection resumed!\n", ConnectionHandle);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::StreamCallback(HQUIC StreamHandle, QUIC_STREAM_EVENT* Event, StreamData* Stream) {
    UNREFERENCED_PARAMETER(StreamHandle);
    UNREFERENCED_PARAMETER(Stream);
    UNREFERENCED_PARAMETER(Event);
    // TODO Remember to delete stram at shutdown complete
    return QUIC_STATUS_SUCCESS;
}
