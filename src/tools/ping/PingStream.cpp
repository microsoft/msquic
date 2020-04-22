/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Client Implementation. Supports connecting to a remote QUIC
    endpoint and sending a variable length payload of semi-random data. It
    then waits for the remote to acknowledge the data via closing the stream.
    The remote may or may not echo the payload.

--*/

#include "QuicPing.h"

uint8_t* QuicPingRawIoBuffer = nullptr;

PingStream::PingStream(
    _In_ PingConnection *connection,
    _In_ PingStreamMode mode
    ) :
    Connection(connection), QuicStream(nullptr),
    Mode(mode), Aborted(false),
    BytesSent(0), BytesCompleted(0), BytesReceived(0) {
}

//
// Constructor for incoming stream.
//
PingStream::PingStream(
    _In_ PingConnection *connection,
    _In_ HQUIC stream,
    _In_ PingStreamMode mode
    ) :
    Connection(connection), QuicStream(stream),
    Mode(mode), Aborted(false),
    BytesSent(0), BytesCompleted(0), BytesReceived(0) {
    StartTime = QuicTimeUs64();
    MsQuic->SetCallbackHandler(QuicStream, (void*)QuicCallbackHandler, this);

    printf("[%p][%llu] Opened.\n", Connection->QuicConnection, GetStreamID(MsQuic, QuicStream));
}

PingStream::~PingStream() {
    if (QuicStream) {
        MsQuic->StreamClose(QuicStream);
    }
}

bool
PingStream::Start(
    ) {
    StartTime = QuicTimeUs64();
    QUIC_STREAM_OPEN_FLAGS OpenFlags = QUIC_STREAM_OPEN_FLAG_NONE;
    if (Mode == UniSendMode) {
        OpenFlags = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
    }
    if (QUIC_SUCCEEDED(MsQuic->StreamOpen(Connection->QuicConnection, OpenFlags, QuicCallbackHandler, this, &QuicStream)) &&
        QUIC_SUCCEEDED(MsQuic->StreamStart(QuicStream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("[%p][%llu] Opened.\n", Connection->QuicConnection, GetStreamID(MsQuic, QuicStream));
        return StartSend();
    } else {
        return false;
    }
}

bool
PingStream::QueueSendRequest(
    PingSendRequest* SendRequest
    )
{
    return
        QUIC_SUCCEEDED(
        MsQuic->StreamSend(
            QuicStream,
            &SendRequest->QuicBuffer,
            1,
            SendRequest->Flags,
            SendRequest));
}

bool
PingStream::StartSend(
    ) {
    if (PingConfig.StreamPayloadLength == 0) {
        MsQuic->StreamShutdown(QuicStream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        return true;
    }

    uint32_t SendRequestsCount = 0;
    while (BytesSent < PingConfig.StreamPayloadLength && SendRequestsCount < PingConfig.IoCount) {
        auto SendRequest = new PingSendRequest();
        SendRequest->SetLength(PingConfig.StreamPayloadLength - BytesSent);
        BytesSent += SendRequest->QuicBuffer.Length;
        SendRequestsCount++;
        if (!QueueSendRequest(SendRequest)) {
            delete SendRequest;
            return false;
        }
    }

    return true;
}

void
PingStream::ProcessEvent(
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        BytesReceived += Event->RECEIVE.TotalBufferLength;
        if (Mode == BidiEchoMode) {
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                const QUIC_BUFFER* Buffer = &Event->RECEIVE.Buffers[i];
                auto SendRequest = new PingSendRequest(Buffer->Buffer, Buffer->Length);
                BytesSent += Buffer->Length;

                if (!QueueSendRequest(SendRequest)) {
                    delete SendRequest;
                    MsQuic->StreamShutdown(
                        QuicStream,
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
                        1);
                    break;
                }
            }
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        auto SendRequest = (PingSendRequest*)Event->SEND_COMPLETE.ClientContext;
        if (!Event->SEND_COMPLETE.Canceled) {
            BytesCompleted += SendRequest->QuicBuffer.Length;
            if (Mode == BidiSendMode || Mode == UniSendMode) {
                //
                // In Bidi or Uni Send mode, we continue to send data until we
                // have sent the correct number of bytes.
                //
                auto BytesLeftToSend = PingConfig.StreamPayloadLength - BytesSent;
                if (BytesLeftToSend != 0) {
                    SendRequest->SetLength(BytesLeftToSend);
                    BytesSent += SendRequest->QuicBuffer.Length;
                    if (QueueSendRequest(SendRequest)) {
                        SendRequest = nullptr;
                    }
                }
            }
        }
        delete SendRequest;
        break;
    }

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (Mode == BidiEchoMode) {
            //
            // In Bidi Echo mode, we shutdown our send path once the remote
            // shutdowns their send path.
            //
            MsQuic->StreamShutdown(
                QuicStream,
                QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                0);
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        Aborted = true;
        MsQuic->StreamShutdown(
            QuicStream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        CompleteTime = QuicTimeUs64();

        bool Completed;
        switch (Mode) {
        case UniSendMode:
            Completed = BytesCompleted == PingConfig.StreamPayloadLength;
            break;
        case UniRecvMode:
            Completed = true;
            break;
        case BidiSendMode:
            Completed =
                BytesCompleted == PingConfig.StreamPayloadLength &&
                BytesReceived == PingConfig.StreamPayloadLength;
            break;
        case BidiEchoMode:
            Completed = BytesCompleted == BytesReceived;
            break;
        }

        Completed &= !Aborted;

        uint64_t ElapsedMicroseconds = CompleteTime - StartTime;

        if (BytesCompleted != 0 || BytesReceived != 0) {

            uint32_t SendRate = (uint32_t)((BytesCompleted * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));
            uint32_t RecvRate = (uint32_t)((BytesReceived * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));

            printf("[%p][%llu] Closed [%s] after %u.%u ms. (TX %llu bytes @ %u kbps | RX %llu bytes @ %u kbps).\n",
                Connection->QuicConnection, GetStreamID(MsQuic, QuicStream),
                Completed ? "Complete" : "Cancel",
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000),
                BytesCompleted, SendRate, BytesReceived, RecvRate);

        } else {
            printf("[%p][%llu] Closed [%s] after %u.%u ms.\n",
                Connection->QuicConnection, GetStreamID(MsQuic, QuicStream),
                Completed ? "Complete" : "Cancel",
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000));
        }

        Connection->OnPingStreamShutdownComplete(this);

        delete this;
        break;
    }

    default:
        break;
    }
}

QUIC_STATUS
QUIC_API
PingStream::QuicCallbackHandler(
    _In_ HQUIC /* Stream */,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    PingStream *pThis = (PingStream*)Context;
    pThis->ProcessEvent(Event);
    return QUIC_STATUS_SUCCESS;
}
