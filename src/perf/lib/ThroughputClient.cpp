#ifdef QUIC_CLOG
#include "ThroughputClient.cpp.clog.h"
#endif

#include "ThroughputClient.h"
#include "msquichelper.h"
#include "ThroughputCommon.h"

ThroughputClient::ThroughputClient() {
    if (Session.IsValid()) {
        Session.SetAutoCleanup();
    }
}

QUIC_STATUS
ThroughputClient::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    Port = THROUGHPUT_DEFAULT_PORT;
    TryGetValue(argc, argv, "port", &Port);

    const char* Target;
    if (!TryGetValue(argc, argv, "target", &Target)) {
        WriteOutput("Must specify '-target' argument!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    TryGetValue(argc, argv, "length", &Length);

    size_t Len = strlen(Target);
    TargetData.reset(new char[Len + 1]);
    QuicCopyMemory(TargetData.get(), Target, Len);
    TargetData[Len] = '\0';

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputClient::Start(QUIC_EVENT StopEvnt) {
    UniquePtr<ConnectionData> ConnData;
    ConnData.reset(new ConnectionData);
    QUIC_STATUS Status = MsQuic->ConnectionOpen(Session, [](auto Handle, auto Context, auto Event) -> QUIC_STATUS {
        return ((ConnectionData*)Context)->Client->ConnectionCallback(Handle, Event, (ConnectionData*)Context);
    }, ConnData.get(), &ConnData->Connection.Handle);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Status = MsQuic->ConnectionStart(ConnData->Connection, AF_UNSPEC, TargetData.get(), Port);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    auto LocalConnData = ConnData.release();

    UniquePtr<StreamData> StrmData;
    StrmData.reset(new StreamData);

    Status = MsQuic->StreamOpen(LocalConnData->Connection, QUIC_STREAM_OPEN_FLAG_NONE, [](auto Handle, auto Context, auto Event) -> QUIC_STATUS {
        return ((StreamData*)Context)->Client->StreamCallback(Handle, Event, (StreamData*)Context);
    }, StrmData.get(), &StrmData->Stream.Handle);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Status = MsQuic->StreamStart(StrmData->Stream.Handle, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    auto LocalStreamData = StrmData.release();

    if (Length == 0) {
        return MsQuic->StreamShutdown(LocalStreamData->Stream.Handle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
    }

    // Always buffered, we'll fix this up later
    // Also need to fix up IO SIze
    constexpr uint32_t IoSize = 0x10000;
    void* RawBuf = QUIC_ALLOC_PAGED(IoSize + sizeof(QUIC_BUFFER));
    QUIC_BUFFER* Buf = (QUIC_BUFFER*)RawBuf;

    Buf->Buffer = ((uint8_t*)RawBuf) + sizeof(QUIC_BUFFER);
    QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;
    if (Length > IoSize) {
        Buf->Length = IoSize;
    } else {
        Flags |= QUIC_SEND_FLAG_FIN;
        Buf->Length = (uint32_t)Length;
    }
    LocalStreamData->BytesSent += Buf->Length;

    Status = MsQuic->StreamSend(LocalStreamData->Stream.Handle, Buf, 1, Flags, Buf);
    if (QUIC_FAILED(Status)) {
        QUIC_FREE(RawBuf);
    }
    this->StopEvent = StopEvnt;
    return Status;
}

QUIC_STATUS ThroughputClient::Wait(int Timeout) {
    if (Timeout > 0) {
        QuicEventWaitWithTimeout(StopEvent, Timeout);
    } else {
        QuicEventWaitForever(StopEvent);
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputClient::ConnectionCallback(HQUIC ConnectionHandle, QUIC_CONNECTION_EVENT* Event, ConnectionData* ConnData) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        WriteOutput("[conn][%p] Connected\n", ConnectionHandle);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        WriteOutput("[conn][%p] Shutdown\n", ConnectionHandle);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        WriteOutput("[conn][%p] All done\n", ConnectionHandle);
        delete ConnData;
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        WriteOutput("[conn][%p] Resumption ticket received (%u bytes):\n", ConnectionHandle, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            WriteOutput("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        WriteOutput("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputClient::StreamCallback(HQUIC StreamHandle, QUIC_STREAM_EVENT* Event, StreamData* StrmData) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(
            StreamHandle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        delete StrmData;
        break;
    }
    }
    UNREFERENCED_PARAMETER(StreamHandle);
    UNREFERENCED_PARAMETER(Event);
    return QUIC_STATUS_SUCCESS;
}

