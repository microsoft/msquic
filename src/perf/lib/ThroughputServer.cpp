/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Throughput Server Implementation.

--*/

#ifdef QUIC_CLOG
#include "ThroughputServer.cpp.clog.h"
#endif

#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1
#endif
#include "msquichelper.h"
#include "ThroughputServer.h"
#include "ThroughputCommon.h"

ThroughputServer::ThroughputServer() {
    if (Session.IsValid()) {
        Session.SetAutoCleanup();
        Session.SetPeerUnidiStreamCount(THROUGHPUT_SERVER_PEER_UNI);
        Session.SetDisconnectTimeout(THROUGHPUT_DEFAULT_DISCONNECT_TIMEOUT);
        Session.SetIdleTimeout(THROUGHPUT_DEFAULT_IDLE_TIMEOUT);
    }
}

QUIC_STATUS
ThroughputServer::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (!Listener.IsValid()) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

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

QUIC_STATUS
ThroughputServer::Start(
    _In_ QUIC_EVENT StopEvent
    ) {
    QUIC_STATUS Status =
        Listener.Start(
            &Address,
            [](HQUIC Handle, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                return ((ThroughputServer*)Context)->ListenerCallback(Handle, Event);
            },
            this);
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

QUIC_STATUS
ThroughputServer::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        RefCount.Wait(Timeout);
    } else {
        RefCount.WaitForever();
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputServer::ListenerCallback(
    _In_ HQUIC /*ListenerHandle*/,
    _Inout_ QUIC_LISTENER_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        QUIC_CONNECTION_CALLBACK_HANDLER Handler =
            [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                return ((ThroughputServer*)Context)->
                    ConnectionCallback(
                        Conn,
                        Event);
            };
        MsQuic->SetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            (void*)Handler,
            this);
        break;
    }
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputServer::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
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
        if (NumberOfConnections > 0) {
            RefCount.CompleteItem();
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        WriteOutput("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        QUIC_STREAM_CALLBACK_HANDLER Handler =
            [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
                return ((ThroughputServer*)Context)->
                    StreamCallback(
                        Stream,
                        Event);
            };
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)Handler, this);
        MsQuic->ConnectionSendResumptionTicket(ConnectionHandle, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);
        break;
    }
    case QUIC_CONNECTION_EVENT_RESUMED:
        WriteOutput("[conn][%p] Connection resumed!\n", ConnectionHandle);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputServer::StreamCallback(
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(
            StreamHandle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        WriteOutput("Shutdown Complete!\n");
        MsQuic->StreamClose(StreamHandle);
        break;
    }
    }
    return QUIC_STATUS_SUCCESS;
}
