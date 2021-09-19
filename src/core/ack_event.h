/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

typedef struct QUIC_ACK_EVENT {

    uint64_t TimeNow; // microsecond

    uint64_t LargestPacketNumberAcked;

    uint32_t NumRetransmittableBytes;

    uint32_t SmoothedRtt;

    //
    // Indicate it's an implicit ACK rather than a real one
    // 
    BOOLEAN IsImplicit : 1;

} QUIC_ACK_EVENT;

//
// Helper function to create and initialize `QUIC_ACK_EVENT`
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
QUIC_ACK_EVENT
CreateQuicAckEvent(
    )
{
    QUIC_ACK_EVENT AckEvent = {
        .TimeNow = 0,
        .LargestPacketNumberAcked = 0,
        .NumRetransmittableBytes = 0,
        .IsImplicit = FALSE,
    };
    return AckEvent;
}