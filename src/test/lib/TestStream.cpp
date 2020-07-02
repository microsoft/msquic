/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Stream Wrapper

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "TestStream.cpp.clog.h"
#endif

TestStream::TestStream(
    _In_ HQUIC Handle,
    _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
    _In_ bool IsUnidirectional,
    _In_ bool IsPingSource
    ) :
    QuicStream(Handle), Context(nullptr),
    IsUnidirectional(IsUnidirectional), IsPingSource(IsPingSource), UsedZeroRtt(false),
    AllDataSent(IsUnidirectional && !IsPingSource), AllDataReceived(IsUnidirectional && IsPingSource),
    SendShutdown(IsUnidirectional && !IsPingSource), RecvShutdown(IsUnidirectional && IsPingSource),
    IsShutdown(false), BytesToSend(0), OutstandingSendRequestCount(0), BytesReceived(0),
    StreamShutdownCallback(StreamShutdownHandler)
{
    QuicEventInitialize(&EventSendShutdownComplete, TRUE, (IsUnidirectional && !IsPingSource) ? TRUE : FALSE);
    QuicEventInitialize(&EventRecvShutdownComplete, TRUE, (IsUnidirectional && IsPingSource) ? TRUE : FALSE);
    if (QuicStream == nullptr) {
        TEST_FAILURE("Invalid handle passed into TestStream.");
    }
}

TestStream*
TestStream::FromStreamHandle(
    _In_ HQUIC QuicStreamHandle,
    _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags
    )
{
    auto IsUnidirectionalStream = !!(Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    auto Stream = new TestStream(QuicStreamHandle, StreamShutdownHandler, IsUnidirectionalStream, false);
    if (Stream == nullptr || !Stream->IsValid()) {
        TEST_FAILURE("Failed to create new TestStream.");
        delete Stream;
        return nullptr;
    }
    MsQuic->SetCallbackHandler(QuicStreamHandle, reinterpret_cast<void*>(QuicStreamHandler), Stream);
    return Stream;
}

TestStream*
TestStream::FromConnectionHandle(
    _In_ HQUIC QuicConnectionHandle,
    _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags
    )
{
    auto IsUnidirectionalStream = !!(Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
    HQUIC QuicStreamHandle;
    QUIC_STATUS Status =
        MsQuic->StreamOpen(
            QuicConnectionHandle,
            Flags,
            QuicStreamHandler,
            nullptr,
            &QuicStreamHandle);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("MsQuic->StreamOpen failed, 0x%x.", Status);
        return nullptr;
    }
    Status =
        MsQuic->StreamStart(
            QuicStreamHandle,
            QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("MsQuic->StreamStart failed, 0x%x.", Status);
        MsQuic->StreamClose(QuicStreamHandle);
        return nullptr;
    }
    auto Stream = new TestStream(QuicStreamHandle, StreamShutdownHandler, IsUnidirectionalStream, true);
    if (Stream == nullptr || !Stream->IsValid()) {
        TEST_FAILURE("Failed to create new TestStream.");
        delete Stream;
        return nullptr;
    }
    MsQuic->SetContext(QuicStreamHandle, Stream);
    return Stream;
}

TestStream::~TestStream()
{
    MsQuic->StreamClose(QuicStream);
    QuicEventUninitialize(EventRecvShutdownComplete);
    QuicEventUninitialize(EventSendShutdownComplete);
}

QUIC_STATUS
TestStream::Shutdown(
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ QUIC_UINT62 ErrorCode // Application defined error code
    )
{
    return
        MsQuic->StreamShutdown(
            QuicStream,
            Flags,
            ErrorCode);
}

bool
TestStream::StartPing(
    _In_ uint64_t PayloadLength
    )
{
    BytesToSend = (int64_t)(PayloadLength / MaxSendBuffers);

    if (BytesToSend != 0) {
        while (BytesToSend != 0 && OutstandingSendRequestCount < MaxSendRequestQueue) {

            auto SendBufferLength = (uint32_t)min(BytesToSend, MaxSendLength);
            auto SendBuffer = new QuicSendBuffer(MaxSendBuffers, SendBufferLength);
            if (SendBuffer == nullptr) {
                TEST_FAILURE("Failed to alloc QuicSendBuffer");
                return false;
            }

            auto resultingBytesLeft = InterlockedSubtract64(&BytesToSend, SendBufferLength);

            QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_ALLOW_0_RTT;
            if (resultingBytesLeft == 0) {
                Flags |= QUIC_SEND_FLAG_FIN;
            }

            InterlockedIncrement(&OutstandingSendRequestCount);
            QUIC_STATUS Status =
                MsQuic->StreamSend(
                    QuicStream,
                    SendBuffer->Buffers,
                    SendBuffer->BufferCount,
                    Flags,
                    SendBuffer);
            if (QUIC_FAILED(Status)) {
                InterlockedDecrement(&OutstandingSendRequestCount);
                delete SendBuffer;
                TEST_FAILURE("MsQuic->StreamSend failed, 0x%x.", Status);
                return false;
            }
            if (resultingBytesLeft == 0) {
                // On the finish packet if it succeeds, the instance
                // we are executing in will be deleted. Return
                // so we don't execute the while on a deleted instance.
                return true;
            }
        }

    } else {
        //
        // No data to send out, so just close the stream.
        //
        QUIC_STATUS Status =
            Shutdown(QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, QUIC_TEST_NO_ERROR);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamShutdown failed, 0x%x.", Status);
            return false;
        }
    }

    return true;
}

bool
TestStream::WaitForSendShutdownComplete()
{
    if (!QuicEventWaitWithTimeout(EventSendShutdownComplete, TestWaitTimeout)) {
        TEST_FAILURE("WaitForSendShutdownComplete timed out after %u ms.", TestWaitTimeout);
        return false;
    }
    return true;
}

bool
TestStream::WaitForRecvShutdownComplete()
{
    if (!QuicEventWaitWithTimeout(EventRecvShutdownComplete, TestWaitTimeout)) {
        TEST_FAILURE("WaitForRecvShutdownComplete timed out after %u ms.", TestWaitTimeout);
        return false;
    }
    return true;
}

//
// Stream Parameters
//

uint64_t
TestStream::GetStreamID()
{
    uint64_t value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicStream,
            QUIC_PARAM_LEVEL_STREAM,
            QUIC_PARAM_STREAM_ID,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(QUIC_PARAM_STREAM_ID) failed, 0x%x.", Status);
    }
    return value;
}

QUIC_STATUS
TestStream::SetReceiveEnabled(
    bool value
    )
{
    return MsQuic->StreamReceiveSetEnabled(QuicStream, value ? TRUE : FALSE);
}

void
TestStream::HandleStreamRecv(
    _In_reads_(Length)
        const uint8_t * Buffer,
    _In_ uint32_t Length,
    _In_ QUIC_RECEIVE_FLAGS Flags
    )
{
    if (Buffer == nullptr) {
        TEST_FAILURE("Null Buffer");
        return;
    }
    if (Length == 0) {
        TEST_FAILURE("Zero Length Buffer");
        return;
    }

    BytesReceived += Length;

    if (!IsPingSource) {
        if (!!(Flags & QUIC_RECEIVE_FLAG_0_RTT)) {
            UsedZeroRtt = true;
        }

        if (!IsUnidirectional) {
            auto SendBuffer = new QuicSendBuffer(Length, Buffer);

            QUIC_STATUS Status =
                MsQuic->StreamSend(
                    QuicStream,
                    SendBuffer->Buffers,
                    SendBuffer->BufferCount,
                    QUIC_SEND_FLAG_NONE,
                    SendBuffer);

            if (QUIC_FAILED(Status)) {
                delete SendBuffer;
            }
            if (!SendShutdown) {
                if (QUIC_FAILED(Status)) {
                    TEST_FAILURE("MsQuic->StreamSend failed, 0x%x.", Status);
                }
            }
        }
    }
}

void
TestStream::HandleStreamSendComplete(
    _In_ bool Canceled,
    _In_ QuicSendBuffer* SendBuffer
    )
{
    if (IsPingSource) {
        if (BytesToSend == 0 || Canceled) {
            InterlockedDecrement(&OutstandingSendRequestCount);
            delete SendBuffer;
        } else {
            QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;
            auto SendBufferLength = (uint32_t)min(BytesToSend, MaxSendLength);
            for (uint32_t i = 0; i < SendBuffer->BufferCount; ++i) {
                SendBuffer->Buffers[i].Length = SendBufferLength;
            }
            if (InterlockedSubtract64(&BytesToSend, SendBufferLength) == 0) {
                Flags |= QUIC_SEND_FLAG_FIN;
            }
            QUIC_STATUS Status =
                MsQuic->StreamSend(
                    QuicStream,
                    SendBuffer->Buffers,
                    SendBuffer->BufferCount,
                    Flags,
                    SendBuffer);
            if (QUIC_FAILED(Status)) {
                InterlockedDecrement(&OutstandingSendRequestCount);
                delete SendBuffer;
            }
        }
    } else {
        delete SendBuffer;
    }
}

QUIC_STATUS
TestStream::HandleStreamEvent(
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    uint64_t Param = 0;
    uint32_t ParamLength = sizeof(Param);

    switch (Event->Type) {

    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            HandleStreamRecv(
                Event->RECEIVE.Buffers[i].Buffer,
                Event->RECEIVE.Buffers[i].Length,
                Event->RECEIVE.Flags);
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        HandleStreamSendComplete(
            Event->SEND_COMPLETE.Canceled,
            (QuicSendBuffer*)Event->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        AllDataReceived = true;
        RecvShutdown = true;
        QuicEventSet(EventRecvShutdownComplete);
        if (!IsPingSource) {
            Shutdown(QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, QUIC_TEST_NO_ERROR);
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        AllDataReceived = false;
        RecvShutdown = true;
        QuicEventSet(EventRecvShutdownComplete);
        break;

    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        break;

    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        if (Event->SEND_SHUTDOWN_COMPLETE.Graceful) {
            AllDataSent = true;
        }
        SendShutdown = true;
        QuicEventSet(EventSendShutdownComplete);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        IsShutdown = true;
        if (QUIC_SUCCEEDED(
            MsQuic->GetParam(
                QuicStream,
                QUIC_PARAM_LEVEL_STREAM,
                QUIC_PARAM_STREAM_0RTT_LENGTH,
                &ParamLength,
                &Param)) &&
            Param > 0) {
            UsedZeroRtt = true;
        }
        if (StreamShutdownCallback != nullptr) {
            StreamShutdownCallback(this);
        }
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}
