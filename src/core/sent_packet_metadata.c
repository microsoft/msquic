/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    When a packet is sent, a QUIC_SENT_PACKET_METADATA is allocated from
    this module and filled with information about the packet. When the
    packet is later acknowledged or inferred lost, this metadata is used
    to determine what exactly was acknowledged or lost.

    The size of a QUIC_SENT_PACKET_METADATA depends on the number of frames
    contained in the packet. The allocator uses a different pool for each
    possible size.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "sent_packet_metadata.c.clog.h"
#endif

void
QuicSentPacketMetadataReleaseFrames(
    _In_ QUIC_SENT_PACKET_METADATA* Metadata
    )
{
    for (uint8_t i = 0; i < Metadata->FrameCount; i++) {
        switch (Metadata->Frames[i].Type)
        {
        case QUIC_FRAME_RESET_STREAM:
            QuicStreamRelease(Metadata->Frames[i].RESET_STREAM.Stream, QUIC_STREAM_REF_SEND_PACKET);
            break;
        case QUIC_FRAME_MAX_STREAM_DATA:
            QuicStreamRelease(Metadata->Frames[i].MAX_STREAM_DATA.Stream, QUIC_STREAM_REF_SEND_PACKET);
            break;
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            QuicStreamRelease(Metadata->Frames[i].STREAM_DATA_BLOCKED.Stream, QUIC_STREAM_REF_SEND_PACKET);
            break;
        case QUIC_FRAME_STOP_SENDING:
            QuicStreamRelease(Metadata->Frames[i].STOP_SENDING.Stream, QUIC_STREAM_REF_SEND_PACKET);
            break;
        case QUIC_FRAME_STREAM:
            QuicStreamRelease(Metadata->Frames[i].STREAM.Stream, QUIC_STREAM_REF_SEND_PACKET);
            break;
        default:
            //
            // Nothing to clean up for other frame types.
            //
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolInitialize(
    _Inout_ QUIC_SENT_PACKET_POOL* Pool
    )
{
    for (uint8_t i = 0; i < ARRAYSIZE(Pool->Pools); i++) {
        uint16_t PacketMetadataSize =
            (i + 1) * sizeof(QUIC_SENT_FRAME_METADATA) +
            sizeof(QUIC_SENT_PACKET_METADATA);

        QuicPoolInitialize(
            FALSE,  // IsPaged
            PacketMetadataSize,
            Pool->Pools + i);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolUninitialize(
    _In_ QUIC_SENT_PACKET_POOL* Pool
    )
{
    for (uint8_t i = 0; i < ARRAYSIZE(Pool->Pools); i++) {
        QuicPoolUninitialize(Pool->Pools + i);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_SENT_PACKET_METADATA*
QuicSentPacketPoolGetPacketMetadata(
    _In_ QUIC_SENT_PACKET_POOL* Pool,
    _In_ uint8_t FrameCount
    )
{
    QUIC_SENT_PACKET_METADATA* Metadata =
        QuicPoolAlloc(Pool->Pools + FrameCount - 1);
#if DEBUG
    Metadata->Flags.Freed = FALSE;
#endif
    return Metadata;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolReturnPacketMetadata(
    _In_ QUIC_SENT_PACKET_POOL* Pool,
    _In_ QUIC_SENT_PACKET_METADATA* Metadata
    )
{
    _Analysis_assume_(
        Metadata->FrameCount > 0 &&
        Metadata->FrameCount <= QUIC_MAX_FRAMES_PER_PACKET);

#if DEBUG
    Metadata->Flags.Freed = TRUE;
#endif

    QuicSentPacketMetadataReleaseFrames(Metadata);
    QuicPoolFree(Pool->Pools + Metadata->FrameCount - 1, Metadata);
}
