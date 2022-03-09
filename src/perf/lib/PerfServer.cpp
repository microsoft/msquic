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

QUIC_STATUS
PerfServer::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (QUIC_FAILED(InitStatus)) {
        return InitStatus;
    }

    TryGetValue(argc, argv, "stats", &PrintStats);

    const char* LocalAddress = nullptr;
    if (TryGetValue(argc, argv, "bind", &LocalAddress)) {
        if (!ConvertArgToAddress(LocalAddress, PERF_DEFAULT_PORT, &LocalAddr)) {
            WriteOutput("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", LocalAddress);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    const char* CibirBytes = nullptr;
    if (TryGetValue(argc, argv, "cibir", &CibirBytes)) {
        CibirId[0] = 0; // offset
        if ((CibirIdLength = DecodeHexBuffer(CibirBytes, 6, CibirId+1)) == 0) {
            WriteOutput("Cibir ID must be a hex string <= 6 bytes.\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    DataBuffer = (QUIC_BUFFER*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + PERF_DEFAULT_IO_SIZE, QUIC_POOL_PERF);
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
    _In_ CXPLAT_EVENT* _StopEvent
    ) {
    if (!Server.Start(&LocalAddr)) { // TCP
        //printf("TCP Server failed to start!\n");
    }

    StopEvent = _StopEvent;

    QUIC_STATUS Status;
    if (CibirIdLength &&
        QUIC_FAILED(Status = Listener.SetCibirId(CibirId, (uint8_t)CibirIdLength+1))) {
        WriteOutput("Failed to set CibirId!\n");
        return Status;
    }

    return Listener.Start(Alpn, &LocalAddr);
}

QUIC_STATUS
PerfServer::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        CxPlatEventWaitWithTimeout(*StopEvent, Timeout);
    } else {
        CxPlatEventWaitForever(*StopEvent);
    }
    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    return QUIC_STATUS_SUCCESS;
}

void
PerfServer::GetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Result
    )
{
    Result->TestType = PerfTestType::Server;
    Result->ExtraDataLength = 0;
}


QUIC_STATUS
PerfServer::GetExtraData(
    _Out_writes_bytes_(*Length) uint8_t*,
    _Inout_ uint32_t* Length
    )
{
    *Length = 0;
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfServer::ListenerCallback(
    _In_ HQUIC /*ListenerHandle*/,
    _Inout_ QUIC_LISTENER_EVENT* Event
    ) {
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        BOOLEAN value = TRUE;
        MsQuic->SetParam(
            Event->NEW_CONNECTION.Connection,
            QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
            sizeof(value),
            &value);
        QUIC_CONNECTION_CALLBACK_HANDLER Handler =
            [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                return ((PerfServer*)Context)->
                    ConnectionCallback(
                        Conn,
                        Event);
            };
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)Handler, this);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    }
    default:
        break;
    }
    return Status;
}

QUIC_STATUS
PerfServer::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            if (PrintStats) {
                QuicPrintConnectionStatistics(MsQuic, ConnectionHandle);
            }
            MsQuic->ConnectionClose(ConnectionHandle);
        }
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
                uint32_t Length = CXPLAT_MIN((uint32_t)(sizeof(uint64_t) - Offset), Event->RECEIVE.Buffers[i].Length);
                memcpy(Dest + Offset, Event->RECEIVE.Buffers[i].Buffer, Length);
                Offset += Length;
            }
            if (Offset == sizeof(uint64_t)) {
                Context->ResponseSize = CxPlatByteSwapUint64(Context->ResponseSize);
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

void
PerfServer::SendTcpResponse(
    _In_ PerfServer::StreamContext* Context,
    _In_ TcpConnection* Connection
    )
{
    while (Context->BytesSent < Context->ResponseSize &&
           Context->OutstandingBytes < Context->IdealSendBuffer) {

        uint64_t BytesLeftToSend = Context->ResponseSize - Context->BytesSent;

        auto SendData = new(std::nothrow) TcpSendData();
        SendData->StreamId = (uint32_t)Context->Entry.Signature;
        SendData->Open = Context->BytesSent == 0 ? 1 : 0;
        SendData->Buffer = DataBuffer->Buffer;
        if ((uint64_t)Context->IoSize >= BytesLeftToSend) {
            SendData->Length = (uint32_t)BytesLeftToSend;
            SendData->Fin = true;
        } else {
            SendData->Length = Context->IoSize;
            SendData->Fin = false;
        }

        Context->BytesSent += SendData->Length;
        Context->OutstandingBytes += SendData->Length;

        Connection->Send(SendData);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpAcceptCallback)
void
PerfServer::TcpAcceptCallback(
    _In_ TcpServer* Server,
    _In_ TcpConnection* Connection
    )
{
    auto This = (PerfServer*)Server->Context;
    Connection->Context = This;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpConnectCallback)
void
PerfServer::TcpConnectCallback(
    _In_ TcpConnection* Connection,
    bool IsConnected
    )
{
    if (!IsConnected) {
        Connection->Close();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpReceiveCallback)
void
PerfServer::TcpReceiveCallback(
    _In_ TcpConnection* Connection,
    uint32_t StreamID,
    bool Open,
    bool Fin,
    bool Abort,
    uint32_t Length,
    uint8_t* Buffer
    )
{
    auto This = (PerfServer*)Connection->Context;
    StreamContext* Stream;
    if (Open) {
        if ((Stream = This->StreamContextAllocator.Alloc(This, false, false)) != nullptr) {
            Stream->Entry.Signature = StreamID;
            Stream->IdealSendBuffer = 1; // TCP uses send buffering, so just set to 1.
            This->StreamTable.Insert(&Stream->Entry);
        }
    } else {
        auto Entry = This->StreamTable.Lookup(StreamID);
        Stream = CXPLAT_CONTAINING_RECORD(Entry, StreamContext, Entry);
    }
    if (!Stream) return;
    if (!Stream->ResponseSizeSet && Length != 0) {
        CXPLAT_DBG_ASSERT(Length >= sizeof(uint64_t));
        CxPlatCopyMemory(&Stream->ResponseSize, Buffer, sizeof(uint64_t));
        Stream->ResponseSize = CxPlatByteSwapUint64(Stream->ResponseSize);
        Stream->ResponseSizeSet = true;
    }
    if (Abort) {
        Stream->ResponseSize = 0; // Reset to make sure we stop sending more
        auto SendData = new(std::nothrow) TcpSendData();
        SendData->StreamId = StreamID;
        SendData->Open = Open ? TRUE : FALSE;
        SendData->Abort = TRUE;
        SendData->Buffer = This->DataBuffer->Buffer;
        SendData->Length = 0;
        Connection->Send(SendData);

    } else if (Fin) {
        if (Stream->ResponseSizeSet && Stream->ResponseSize != 0) {
            This->SendTcpResponse(Stream, Connection);
        } else {
            auto SendData = new(std::nothrow) TcpSendData();
            SendData->StreamId = StreamID;
            SendData->Open = TRUE;
            SendData->Fin = TRUE;
            SendData->Buffer = This->DataBuffer->Buffer;
            SendData->Length = 0;
            Connection->Send(SendData);
        }
        Stream->RecvShutdown = true;
        if (Stream->SendShutdown) {
            This->StreamTable.Remove(&Stream->Entry);
            This->StreamContextAllocator.Free(Stream);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpSendCompleteCallback)
void
PerfServer::TcpSendCompleteCallback(
    _In_ TcpConnection* Connection,
    TcpSendData* SendDataChain
    )
{
    auto This = (PerfServer*)Connection->Context;
    while (SendDataChain) {
        auto Data = SendDataChain;
        auto Entry = This->StreamTable.Lookup(Data->StreamId);
        if (Entry) {
            auto Stream = CXPLAT_CONTAINING_RECORD(Entry, StreamContext, Entry);
            Stream->OutstandingBytes -= Data->Length;
            This->SendTcpResponse(Stream, Connection);
            if ((Data->Fin || Data->Abort) && !Stream->SendShutdown) {
                Stream->SendShutdown = true;
                if (Stream->RecvShutdown) {
                    This->StreamTable.Remove(&Stream->Entry);
                    This->StreamContextAllocator.Free(Stream);
                }
            }
        }
        SendDataChain = SendDataChain->Next;
        delete Data;
    }
}
