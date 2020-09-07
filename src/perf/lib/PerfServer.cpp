/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Server Implementation.

--*/

#include "PerfServer.h"

#ifdef QUIC_CLOG
#include "PerfServer.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "Perf Server options:\n"
        "\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -selfsign:<0/1>             Uses a self-signed server certificate.\n"
        "  -thumbprint:<cert_hash>     The hash or thumbprint of the certificate to use.\n"
        "  -cert_store:<store name>    The certificate store to search for the thumbprint in.\n"
        "  -machine_cert:<0/1>         Use the machine, or current user's, certificate store. (def:0)\n"
        "\n",
        PERF_DEFAULT_PORT
        );
}

QUIC_STATUS
PerfServer::Init(
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

    TryGetValue(argc, argv, "port", &Port);

    QUIC_STATUS Status = SecurityConfig.Initialize(argc, argv, Registration, SelfSignedConfig);
    if (QUIC_FAILED(Status)) {
        PrintHelp();
        return Status;
    }

    DataBuffer = (QUIC_BUFFER*)QUIC_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + PERF_DEFAULT_IO_SIZE);
    if (!DataBuffer) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    DataBuffer->Length = PERF_DEFAULT_IO_SIZE;
    DataBuffer->Buffer = (uint8_t*)(DataBuffer + 1);
    for (uint32_t i = 0; i < PERF_DEFAULT_IO_SIZE; ++i) {
        DataBuffer->Buffer[i] = (uint8_t)i;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfServer::Start(
    _In_ QUIC_EVENT* _StopEvent
    ) {
    QUIC_ADDR Address;
    QuicAddrSetFamily(&Address, AF_UNSPEC);
    QuicAddrSetPort(&Address, Port);

    StopEvent = _StopEvent;

    return
        Listener.Start(
            &Address,
            [](HQUIC Handle, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                return ((PerfServer*)Context)->ListenerCallback(Handle, Event);
            },
            this);
}

QUIC_STATUS
PerfServer::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        QuicEventWaitWithTimeout(*StopEvent, Timeout);
    } else {
        QuicEventWaitForever(*StopEvent);
    }
    Session.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfServer::ListenerCallback(
    _In_ HQUIC /*ListenerHandle*/,
    _Inout_ QUIC_LISTENER_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        BOOLEAN value = TRUE;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                sizeof(value),
                &value))) {
            WriteOutput("MsQuic->SetParam (CONN_DISABLE_1RTT_ENCRYPTION) failed!\n");
        }
        QUIC_CONNECTION_CALLBACK_HANDLER Handler =
            [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                return ((PerfServer*)Context)->
                    ConnectionCallback(
                        Conn,
                        Event);
            };
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)Handler, this);
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        break;
    }
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfServer::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(ConnectionHandle);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        auto Context =
            StreamContextAllocator.Alloc(
                this,
                Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                false); // TODO - Support buffered IO
        if (!Context) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        QUIC_STREAM_CALLBACK_HANDLER Handler =
            [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
                return ((PerfServer::StreamContext*)Context)->Server->
                    StreamCallback(
                        (PerfServer::StreamContext*)Context,
                        Stream,
                        Event);
            };
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)Handler, Context);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfServer::StreamCallback(
    _In_ PerfServer::StreamContext* Context,
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (!Context->ResponseSizeSet) {
            uint8_t* Dest = (uint8_t*)&Context->ResponseSize;
            uint64_t Offset = Event->RECEIVE.AbsoluteOffset;
            for (uint32_t i = 0; Offset < sizeof(uint64_t) && i < Event->RECEIVE.BufferCount; ++i) {
                uint32_t Length = min((uint32_t)(sizeof(uint64_t) - Offset), Event->RECEIVE.Buffers[i].Length);
                memcpy(Dest + Offset, Event->RECEIVE.Buffers[i].Buffer, Length);
                Offset += Length;
            }
            if (Offset == sizeof(uint64_t)) {
                Context->ResponseSize = QuicByteSwapUint64(Context->ResponseSize);
                Context->ResponseSizeSet = true;
            }
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        Context->OutstandingBytes -= ((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length;
        if (!Event->SEND_COMPLETE.Canceled) {
            SendResponse(Context, StreamHandle);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (!Context->ResponseSizeSet) {
            MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        } else if (Context->ResponseSize != 0) {
            if (Context->Unidirectional) {
                // TODO - Not supported right now
                MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            } else {
                SendResponse(Context, StreamHandle);
            }
        } else if (!Context->Unidirectional) {
            MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        MsQuic->StreamClose(StreamHandle);
        StreamContextAllocator.Free(Context);
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        if (!Context->BufferedIo &&
            Context->IdealSendBuffer < Event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            Context->IdealSendBuffer = Event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            SendResponse(Context, StreamHandle);
        }
        break;
    default:
        break;
    }
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfServer::SendResponse(
    _In_ PerfServer::StreamContext* Context,
    _In_ HQUIC StreamHandle
    )
{
    while (Context->BytesSent < Context->ResponseSize &&
           Context->OutstandingBytes < Context->IdealSendBuffer) {

        uint64_t BytesLeftToSend = Context->ResponseSize - Context->BytesSent;
        uint32_t IoSize = Context->IoSize;
        QUIC_BUFFER* Buffer = DataBuffer;
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;

        if ((uint64_t)IoSize >= BytesLeftToSend) {
            IoSize = (uint32_t)BytesLeftToSend;
            Context->LastBuffer.Buffer = Buffer->Buffer;
            Context->LastBuffer.Length = IoSize;
            Buffer = &Context->LastBuffer;
            Flags = QUIC_SEND_FLAG_FIN;
        }

        Context->BytesSent += IoSize;
        Context->OutstandingBytes += IoSize;

        MsQuic->StreamSend(StreamHandle, Buffer, 1, Flags, Buffer);
    }
}
