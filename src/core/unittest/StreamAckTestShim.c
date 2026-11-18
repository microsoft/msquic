/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

//
// Exposes the production STREAM ACK handler to the core unit tests.
//
void
QuicTestStreamOnAck(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SEND_PACKET_FLAGS PacketFlags,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    )
{
    QuicStreamOnAck(Stream, PacketFlags, FrameMetadata);
}
