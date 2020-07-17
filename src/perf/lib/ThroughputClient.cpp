#ifdef QUIC_CLOG
#include "ThroughputClient.cpp.clog.h"
#endif

#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1
#endif
#include "ThroughputClient.h"
#include "msquichelper.h"
#include "ThroughputCommon.h"

// Always buffered, we'll fix this up later
// Also need to fix up IO SIze
static uint32_t IoSize = 0x100000;
static uint32_t IoCount = 8;

static uint8_t* RawIoBuffer{nullptr};

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
    if (Length == 0) {
        WriteOutput("Must specify a positive 'length'\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t Len = strlen(Target);
    TargetData.reset(new char[Len + 1]);
    QuicCopyMemory(TargetData.get(), Target, Len);
    TargetData[Len] = '\0';

    RawIoBuffer = new uint8_t[IoSize];

    return QUIC_STATUS_SUCCESS;
}

struct SendRequest {
    QUIC_SEND_FLAGS Flags {QUIC_SEND_FLAG_NONE};
    QUIC_BUFFER QuicBuffer;
    SendRequest(
        ) {
        QuicBuffer.Buffer = RawIoBuffer;
        QuicBuffer.Length = 0;
    }

    void SetLength(uint64_t BytesLeftToSend) {
        if (BytesLeftToSend > IoSize) {
            QuicBuffer.Length = IoSize;
        } else {
            Flags |= QUIC_SEND_FLAG_FIN;
            QuicBuffer.Length = (uint32_t)BytesLeftToSend;
        }
    }
};

QUIC_STATUS
ThroughputClient::Start(
    _In_ QUIC_EVENT StopEvnt
    ) {
    UniquePtr<ConnectionData> ConnData{new ConnectionData{this}};
    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Session,
            [](HQUIC Handle, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                ConnectionData* ConnData = (ConnectionData*)Context;
                return ConnData->Client->
                    ConnectionCallback(
                        Handle,
                        Event,
                        ConnData);
            },
            ConnData.get(),
            &ConnData->Connection.Handle);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    uint32_t SecFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    Status =
        MsQuic->SetParam(
            ConnData->Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(SecFlags),
            &SecFlags);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    BOOLEAN Opt = FALSE;
    Status =
        MsQuic->SetParam(
            ConnData->Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_SEND_BUFFERING,
            sizeof(Opt),
            &Opt);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Status =
        MsQuic->ConnectionStart(
            ConnData->Connection,
            AF_UNSPEC,
            TargetData.get(),
            Port);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    ConnectionData* LocalConnData = ConnData.release();

    UniquePtr<StreamData> StrmData{new StreamData{this, LocalConnData->Connection}};

    Status =
        MsQuic->StreamOpen(
            LocalConnData->Connection,
            QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
            [](HQUIC Handle, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
                return ((StreamData*)Context)->Client->
                    StreamCallback(
                        Handle,
                        Event,
                        (StreamData*)Context);
            },
            StrmData.get(),
            &StrmData->Stream.Handle);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Status =
        MsQuic->StreamStart(
            StrmData->Stream.Handle,
            QUIC_STREAM_START_FLAG_NONE);

    if (QUIC_FAILED(Status)) {
        return Status;
    }

    StreamData* LocalStreamData = StrmData.release();

    this->StopEvent = StopEvnt;
    LocalStreamData->StartTime = QuicTimeUs64();

    if (Length == 0) {
        Status =
            MsQuic->StreamShutdown(
                LocalStreamData->Stream.Handle,
                QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                0);
        return Status;
    }

    uint32_t SendRequestCount = 0;
    while (LocalStreamData->BytesSent < Length && SendRequestCount < IoCount) {
        SendRequest* SendReq = new SendRequest{};
        SendReq->SetLength(Length - LocalStreamData->BytesSent);
        LocalStreamData->BytesSent += SendReq->QuicBuffer.Length;
        ++SendRequestCount;
        Status =
            MsQuic->StreamSend(
                LocalStreamData->Stream,
                &SendReq->QuicBuffer,
                1,
                SendReq->Flags,
                SendReq);
        if (QUIC_FAILED(Status)) {
            delete SendReq;
            return Status;
        }
    }

    // void* RawBuf = QUIC_ALLOC_PAGED(IoSize + sizeof(QUIC_BUFFER));
    // QUIC_BUFFER* Buf = (QUIC_BUFFER*)RawBuf;

    // Buf->Buffer = ((uint8_t*)RawBuf) + sizeof(QUIC_BUFFER);
    // QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;
    // if (Length > IoSize) {
    //     Buf->Length = IoSize;
    // } else {
    //     Flags |= QUIC_SEND_FLAG_FIN;
    //     WriteOutput("Sending Fin!\n");
    //     Buf->Length = (uint32_t)Length;
    // }
    // LocalStreamData->BytesSent += Buf->Length;

    // Status =
    //     MsQuic->StreamSend(
    //         LocalStreamData->Stream.Handle,
    //         Buf,
    //         1,
    //         Flags,
    //         Buf);

    // if (QUIC_FAILED(Status)) {
    //     QUIC_FREE(RawBuf);
    // }
    WriteOutput("Started!\n");
    return Status;
}

QUIC_STATUS
ThroughputClient::Wait(
    _In_ int Timeout
    ) {
    WriteOutput("Waiting for: %d\n", Timeout);
    if (Timeout > 0) {
        QuicEventWaitWithTimeout(StopEvent, Timeout);
    } else {
        QuicEventWaitForever(StopEvent);
    }
    WriteOutput("Finished!\n");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputClient::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event,
    _Inout_ ConnectionData* ConnData
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        WriteOutput("[conn][%p] Connected\n", ConnectionHandle);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT) {
            WriteOutput("Transport Status %d %s\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status, QuicStatusToString(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
        }
        WriteOutput("[conn][%p] Shutdown\n", ConnectionHandle);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        WriteOutput("[conn][%p] All done\n", ConnectionHandle);
        delete ConnData;
        QuicEventSet(StopEvent);
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        WriteOutput("[conn][%p] Resumption ticket received (%u bytes):\n",
            ConnectionHandle,
            Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
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

QUIC_STATUS
ThroughputClient::StreamCallback(
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event,
    _Inout_ StreamData* StrmData
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        SendRequest* Req = (SendRequest*)Event->SEND_COMPLETE.ClientContext;
        if (!Event->SEND_COMPLETE.Canceled) {
            uint64_t BytesLeftToSend = Length - StrmData->BytesSent;
            StrmData->BytesCompleted += Req->QuicBuffer.Length;
            if (BytesLeftToSend != 0) {
                Req->SetLength(BytesLeftToSend);
                StrmData->BytesSent += Req->QuicBuffer.Length;

                QUIC_STATUS Status =
                    MsQuic->StreamSend(
                        StrmData->Stream.Handle,
                        &Req->QuicBuffer,
                        1,
                        Req->Flags,
                        Req);

                if (QUIC_SUCCEEDED(Status)) {
                    Req = nullptr;
                }
            }
        }
        if (Req) {
            delete Req;
        }
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:

        MsQuic->StreamShutdown(
            StreamHandle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        StrmData->EndTime = QuicTimeUs64();
        uint64_t ElapsedMicroseconds = StrmData->EndTime - StrmData->StartTime;
        uint32_t SendRate = (uint32_t)((StrmData->BytesCompleted * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));

        WriteOutput("[%p][%llu] Closed [%s] after %u.%u ms. (TX %llu bytes @ %u kbps).\n",
            StrmData->Connection,
            GetStreamID(MsQuic, StreamHandle),
            "Complete",
            (uint32_t)(ElapsedMicroseconds / 1000),
            (uint32_t)(ElapsedMicroseconds % 1000),
            StrmData->BytesCompleted, SendRate);

        MsQuic->ConnectionShutdown(
            StrmData->Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            0);
        delete StrmData;
        break;
    }
    }
    return QUIC_STATUS_SUCCESS;
}

