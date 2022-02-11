/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_ACK_TRACKER {

    //
    // Range of packet numbers we have received. Used for duplicate packet
    // detection. The range's growth is limited to QUIC_MAX_RANGE_DUPLICATE_PACKETS
    // bytes. When this limit is hit, older packets are silently dropped.
    //
    QUIC_RANGE PacketNumbersReceived;

    //
    // Range of packet numbers we have received and should ACK. The range's
    // growth is limited to QUIC_MAX_RANGE_ACK_PACKETS bytes. When this limit is
    // hit, older packets are silently dropped.
    //
    QUIC_RANGE PacketNumbersToAck;

    //
    // The current count of recieved ECNs
    //
    QUIC_ACK_ECN_EX ReceivedECN;

    //
    // The largest packet number we have sent an ACK for.
    //
    uint64_t LargestPacketNumberAcknowledged;

    //
    // The time (in us) we received the largest packet number.
    //
    uint64_t LargestPacketNumberRecvTime;

    //
    // The number of ACK eliciting packets that need to be acknowledged.
    //
    uint16_t AckElicitingPacketsToAcknowledge;

    //
    // Indicates an ACK frame has already been written for all the currently
    // queued packet numbers.
    //
    BOOLEAN AlreadyWrittenAckFrame : 1;

    //
    // Indicates that we have received a non-zero ECN type.
    //
    BOOLEAN NonZeroRecvECN : 1;

} QUIC_ACK_TRACKER;

//
// Initializes a new ack tracker.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerInitialize(
    _Inout_ QUIC_ACK_TRACKER* Tracker
    );

//
// Uninitializes the ack tracker.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicAckTrackerUninitialize(
    _Inout_ QUIC_ACK_TRACKER* Tracker
    );

//
// Resets the ack tracker.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerReset(
    _Inout_ QUIC_ACK_TRACKER* Tracker
    );

//
// Returns TRUE if the packet is a duplicate.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicAckTrackerAddPacketNumber(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _In_ uint64_t PacketNumber
    );

typedef enum QUIC_ACK_TYPE {
    QUIC_ACK_TYPE_NON_ACK_ELICITING,
    QUIC_ACK_TYPE_ACK_ELICITING,
    QUIC_ACK_TYPE_ACK_IMMEDIATE,
} QUIC_ACK_TYPE;

//
// Adds the packet number to the list of packets that should be acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerAckPacket(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _In_ uint64_t PacketNumber,
    _In_ uint64_t RecvTimeUs,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ QUIC_ACK_TYPE AckType
    );

//
// Called by the send module to write the current ACK blocks. Returns FALSE if
// there wasn't enough room to write to the packet.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicAckTrackerAckFrameEncode(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

//
// Called by the loss detection when an ACK frame has been acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerOnAckFrameAcked(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _In_ uint64_t LargestAckedPacketNumber
    );

//
// Helper function that indicates if any (even non-ACK eliciting) packets are
// queued up to be acknowledged in a new ACK frame.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicAckTrackerHasPacketsToAck(
    _In_ const QUIC_ACK_TRACKER* Tracker
    )
{
    return
        !Tracker->AlreadyWrittenAckFrame &&
        QuicRangeSize(&Tracker->PacketNumbersToAck) != 0;
}
