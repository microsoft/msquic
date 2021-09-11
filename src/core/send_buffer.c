/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Send buffering logic.

    "Buffering" here means copying and completing send requests immediately rather
    than waiting for the bytes to be acknowledged. We buffer enough send bytes
    to maintain a high throughput, and then we pend subsequent send requests.
    When we do this, the QUIC client can simply post a single send request and
    wait for its completion in a loop, and doesn't have to worry about how many
    bytes it should keep posted.

    We copy requests into fixed-sized blocks when possible, and fall back on
    CXPLAT_ALLOC for large send requests.

    We buffer send requests until we've buffered AT LEAST the desired number
    of bytes, rather than using the ideal buffer size as a hard limit. This
    covers several corner cases (such as an app that posts sends larger than
    the ideal buffer size) and ensures that multiple requests will always be
    posted (which is important for maintaining throughput, since we are
    guaranteed to be stalled upon request completion if only one request
    is posted at a time).


    Ideal send buffer size (ISB) adjustment:

    IdealBytes is increased as appropriate to keep it from limiting BytesInFlight.

    IdealBytes is the ideal number of bytes to buffer on the connection as a
    whole. We have to map this value to per-stream IDEAL_SEND_BUFFER_SIZE events.
    This is difficult because we don't know how many bytes the app plans to send
    on each stream. For example, the app may have many streams open but only send
    data on one of them. This means we cannot indicate (SendBuffer.IdealBytes/N)
    bytes as the ISB to each of the N streams (it could limit throughput by a
    factor of N).

    This begs a question: why doesn't the QUIC API indicate a per-connection
    ISB value, and let the app divide it up? This was not done because in the
    case of legacy middleware (such as HTTP), it simply moves part of the
    buffer-sizing problem up one layer (thereby splitting it between two
    layers). HTTP similarly doesn't know how its app wants to send on the
    streams, and its legacy APIs don't let it pass the problem further up the
    stack to the layer that really knows.

    So then, we indicate min(SendBuffer.IdealBytes, Stream.SendWindow) as the
    ISB to each stream. If the app steadily sends on multiple streams, this
    means more data will be buffered than needed. But usually we expect only
    one stream to be steadily sending, in which case this scheme will
    maximize throughput and minimize memory usage.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "send_buffer.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendBufferInitialize(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer
    )
{
    SendBuffer->IdealBytes = QUIC_DEFAULT_IDEAL_SEND_BUFFER_SIZE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendBufferUninitialize(
    _In_ QUIC_SEND_BUFFER* SendBuffer
    )
{
    UNREFERENCED_PARAMETER(SendBuffer);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
uint8_t*
QuicSendBufferAlloc(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer,
    _In_ uint32_t Size
    )
{
    uint8_t* Buf = (uint8_t*)CXPLAT_ALLOC_NONPAGED(Size, QUIC_POOL_SENDBUF);

    if (Buf != NULL) {
        SendBuffer->BufferedBytes += Size;
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "sendbuffer",
            Size);
    }

    return Buf;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendBufferFree(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer,
    _In_ uint8_t* Buf,
    _In_ uint32_t Size
    )
{
    CXPLAT_FREE(Buf, QUIC_POOL_SENDBUF);
    SendBuffer->BufferedBytes -= Size;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendBufferHasSpace(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer
    )
{
    return SendBuffer->BufferedBytes < SendBuffer->IdealBytes;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendBufferFill(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Buffer send requests until the buffer is full.
    //
    // A buffered request is completed immediately. To ensure requests
    // are completed in the order they were posted with respect to each
    // stream, we always buffer the oldest unbuffered request on a stream,
    // and if that fails, we terminate early rather than skipping to the
    // next request. Such an error is nonfatal: we just try again the next
    // time this function is called.
    //

    //
    // TODO: which streams should we buffer? For now, just loop over
    // streams and buffer whatever unbuffered requests we find first.
    //

    QUIC_SEND_REQUEST* Req;
    CXPLAT_LIST_ENTRY* Entry;

    CXPLAT_DBG_ASSERT(Connection->Settings.SendBufferingEnabled);

    Entry = Connection->Send.SendStreams.Flink;
    while (QuicSendBufferHasSpace(&Connection->SendBuffer) && Entry != &(Connection->Send.SendStreams)) {

        QUIC_STREAM* Stream = CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink);
        Entry = Entry->Flink;

#if DEBUG
        //
        // Sanity check: SendBufferBookmark should always point to the
        // first unbuffered send request (if there is one), and no requests
        // after SendBufferBookmark should be buffered yet (i.e., buffering
        // should happen in order).
        //
        Req = Stream->SendRequests;
        while (Req != NULL && !!(Req->Flags & QUIC_SEND_FLAG_BUFFERED)) {
            Req = Req->Next;
        }
        CXPLAT_DBG_ASSERT(Req == Stream->SendBufferBookmark);
        while (Req != NULL) {
            CXPLAT_DBG_ASSERT(!(Req->Flags & QUIC_SEND_FLAG_BUFFERED));
            Req = Req->Next;
        }
#endif

        Req = Stream->SendBufferBookmark;

        //
        // Buffer as many requests as we can before moving to the next stream.
        //
        while (Req != NULL && QuicSendBufferHasSpace(&Connection->SendBuffer)) {
            if (QUIC_FAILED(QuicStreamSendBufferRequest(Stream, Req))) {
                return;
            }
            Req = Req->Next;
        }

    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicGetNextIdealBytes(
    _In_ uint32_t BaseValue
    )
{
    uint32_t Threshold = QUIC_DEFAULT_IDEAL_SEND_BUFFER_SIZE;

    //
    // We calculate the threshold as an exponential growth from the default
    // value up to the max, rounding up to the next threshold when equal.
    //
    while (Threshold <= BaseValue) {
        uint32_t NextThreshold = Threshold + (Threshold / 2); // 1.5x growth
        if (NextThreshold > QUIC_MAX_IDEAL_SEND_BUFFER_SIZE) {
            Threshold = QUIC_MAX_IDEAL_SEND_BUFFER_SIZE;
            break;
        }
        Threshold = NextThreshold;
    }

    return Threshold;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendBufferStreamAdjust(
    _In_ QUIC_STREAM* Stream
    )
{
    //
    // Calculate the value to actually indicate to the app for this stream as
    // a minimum of the connection-wide IdealBytes and the value based on the
    // stream's estimated SendWindow.
    //
    uint64_t ByteCount = Stream->Connection->SendBuffer.IdealBytes;
    if ((uint64_t)Stream->SendWindow < ByteCount) {
        const uint64_t SendWindowIdealBytes =
            QuicGetNextIdealBytes(Stream->SendWindow);
        if (SendWindowIdealBytes < ByteCount) {
            ByteCount = SendWindowIdealBytes;
        }
    }

    if (Stream->LastIdealSendBuffer != ByteCount) {
        Stream->LastIdealSendBuffer = ByteCount;

        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE;
        Event.IDEAL_SEND_BUFFER_SIZE.ByteCount = ByteCount;
        QuicTraceLogStreamVerbose(
            IndicateIdealSendBuffer,
            Stream,
            "Indicating QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = %llu",
            Event.IDEAL_SEND_BUFFER_SIZE.ByteCount);
        (void)QuicStreamIndicateEvent(Stream, &Event);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendBufferConnectionAdjust(
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->SendBuffer.IdealBytes == QUIC_MAX_IDEAL_SEND_BUFFER_SIZE ||
        Connection->Streams.StreamTable == NULL) {
        return; // Nothing to do.
    }

    const uint64_t NewIdealBytes =
        QuicGetNextIdealBytes(
            QuicCongestionControlGetBytesInFlightMax(&Connection->CongestionControl));

    //
    // TODO: Currently, IdealBytes only grows and never shrinks. Add appropriate
    // shrinking logic.
    //
    if (NewIdealBytes > Connection->SendBuffer.IdealBytes) {
        Connection->SendBuffer.IdealBytes = NewIdealBytes;

        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(Connection->Streams.StreamTable, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(Connection->Streams.StreamTable, &Enumerator)) != NULL) {
            QUIC_STREAM* Stream = CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, TableEntry);
            if (Stream->Flags.SendEnabled) {
                QuicSendBufferStreamAdjust(Stream);
            }
        }
        CxPlatHashtableEnumerateEnd(Connection->Streams.StreamTable, &Enumerator);

        if (Connection->Settings.SendBufferingEnabled) {
            QuicSendBufferFill(Connection);
        }
    }
}
