/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_LOSS_EVENT {

    uint64_t LargestPacketNumberLost;

    uint64_t LargestPacketNumberSent;

    uint32_t NumRetransmittableBytes;

    BOOLEAN PersistentCongestion : 1;

} QUIC_LOSS_EVENT;

//
// Helper function to create and initialize `QUIC_ACK_EVENT`
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
QUIC_LOSS_EVENT
CreateQuicLossEvent(
    )
{
    QUIC_LOSS_EVENT LossEvent = {
        .LargestPacketNumberLost = 0,
        .LargestPacketNumberSent = 0,
        .NumRetransmittableBytes = 0,
        .PersistentCongestion = FALSE,
    };
    return LossEvent;
}
