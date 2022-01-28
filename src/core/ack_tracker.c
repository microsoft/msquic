/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The Ack Tracker manages all the packet numbers that have been received
    (for duplicate packet detection) and all the packet numbers that need
    to be acknowledged via an ACK_FRAME sent back to the peer. It does all
    the framing for the ACK_FRAME. It also handles the receipt of an
    acknowledgement for a previously sent ACK_FRAME. In response to that
    acknowledgement, the Ack Tracker removes the packet number range (less than
    the largest packet number) that was sent in the ACK_FRAME from the current
    internal tracking structures. The result is that the Ack Tracker will
    continue to send ACK_FRAMES for received packet numbers until it receives
    an acknowledgement for the frame; then those packet numbers are no longer
    sent in ACK_FRAMES.

    The reason the Ack Tracker removes all packet numbers less than or equal to
    the largest packet number in an ACK_FRAME when that frame is acknowledged
    is because we make the assumption that by the time it gets that
    acknowledgement, everything in that range was either completely lost or
    included in the ACK_FRAME and has been acknowledged.

    There is a possible scenario where the Ack Tracker receives packets out of
    order and ends up sending an ACK_FRAME with gaps for the missing packets,
    and then later receives those missing packets. Then it sends a new
    ACK_FRAME, which might be lost. If it was lost, and we never happen to send
    any more ACK_FRAMEs after it, we would still remove those packet numbers
    from the tracker in response to the original ACK_FRAME being
    acknowledged by the peer. Since we constantly send ACK_FRAMEs with the
    current state, most of the time having a lot of duplicate information in
    them, we assume the data eventually gets there in one form or another. Worst
    case, the peer has to do an additional retransmission, in an already lossy
    environment.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "ack_tracker.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerInitialize(
    _Inout_ QUIC_ACK_TRACKER* Tracker
    )
{
    QuicRangeInitialize(
        QUIC_MAX_RANGE_DUPLICATE_PACKETS,
        &Tracker->PacketNumbersReceived);

    QuicRangeInitialize(
        QUIC_MAX_RANGE_ACK_PACKETS,
        &Tracker->PacketNumbersToAck);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicAckTrackerUninitialize(
    _Inout_ QUIC_ACK_TRACKER* Tracker
    )
{
    QuicRangeUninitialize(&Tracker->PacketNumbersToAck);
    QuicRangeUninitialize(&Tracker->PacketNumbersReceived);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerReset(
    _Inout_ QUIC_ACK_TRACKER* Tracker
    )
{
    Tracker->AckElicitingPacketsToAcknowledge = 0;
    Tracker->LargestPacketNumberAcknowledged = 0;
    Tracker->LargestPacketNumberRecvTime = 0;
    Tracker->AlreadyWrittenAckFrame = FALSE;
    Tracker->NonZeroRecvECN = FALSE;
    CxPlatZeroMemory(&Tracker->ReceivedECN, sizeof(Tracker->ReceivedECN));
    QuicRangeReset(&Tracker->PacketNumbersToAck);
    QuicRangeReset(&Tracker->PacketNumbersReceived);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicAckTrackerAddPacketNumber(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _In_ uint64_t PacketNumber
    )
{
    BOOLEAN RangeUpdated;
    return
        QuicRangeAddRange(&Tracker->PacketNumbersReceived, PacketNumber, 1, &RangeUpdated) == NULL ||
        !RangeUpdated;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerAckPacket(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _In_ uint64_t PacketNumber,
    _In_ uint64_t RecvTimeUs,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ QUIC_ACK_TYPE AckType
    )
{
    QUIC_CONNECTION* Connection = QuicAckTrackerGetPacketSpace(Tracker)->Connection;
    _Analysis_assume_(Connection != NULL);

    //
    // Before entering this function, a check is done for duplicate packets,
    // so this is guaranteed to only receive non-duplicated packets.
    //

    CXPLAT_DBG_ASSERT(PacketNumber <= QUIC_VAR_INT_MAX);

    uint64_t CurLargestPacketNumber;
    if (QuicRangeGetMaxSafe(&Tracker->PacketNumbersToAck, &CurLargestPacketNumber) &&
        CurLargestPacketNumber > PacketNumber) {
        //
        // Any time the largest known packet number is greater than the one
        // we just received, we consider it reordering.
        //
        Connection->Stats.Recv.ReorderedPackets++;
    }

    if (!QuicRangeAddValue(&Tracker->PacketNumbersToAck, PacketNumber)) {
        //
        // Allocation failure. Fatal error for the connection in this case.
        //
        QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
        return;
    }

    QuicTraceLogVerbose(
        PacketRxMarkedForAck,
        "[%c][RX][%llu] Marked for ACK (ECN=%hhu)",
        PtkConnPre(Connection),
        PacketNumber,
        (uint8_t)ECN);

    BOOLEAN NewLargestPacketNumber =
        PacketNumber == QuicRangeGetMax(&Tracker->PacketNumbersToAck);
    if (NewLargestPacketNumber) {
        Tracker->LargestPacketNumberRecvTime = RecvTimeUs;
    }

    switch (ECN) {
        case CXPLAT_ECN_ECT_1:
            Tracker->NonZeroRecvECN = TRUE;
            Tracker->ReceivedECN.ECT_1_Count++;
            break;
        case CXPLAT_ECN_ECT_0:
            Tracker->NonZeroRecvECN = TRUE;
            Tracker->ReceivedECN.ECT_0_Count++;
            break;
        case CXPLAT_ECN_CE:
            Tracker->NonZeroRecvECN = TRUE;
            Tracker->ReceivedECN.CE_Count++;
            break;
        default:
            break;
    }

    Tracker->AlreadyWrittenAckFrame = FALSE;

    if (AckType == QUIC_ACK_TYPE_NON_ACK_ELICITING) {
        goto Exit;
    }

    Tracker->AckElicitingPacketsToAcknowledge++;

    if (Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK) {
        goto Exit; // Already queued to send an ACK, no more work to do.
    }

    //
    // There are several conditions where we decide to send an ACK immediately:
    //
    //   1. We have received 'PacketTolerance' ACK eliciting packets.
    //   2. We received an ACK eliciting packet that doesn't directly follow the
    //      previously received packet number. So we assume there might have
    //      been loss and should indicate this info to the peer. This logic is
    //      disabled if 'IgnoreReordering' is TRUE.
    //   3. The delayed ACK timer fires after the configured time.
    //   4. The packet included an IMMEDIATE_ACK frame.
    //
    // If we don't queue an immediate ACK and this is the first ACK eliciting
    // packet received, we make sure the ACK delay timer is started.
    //

    if (AckType == QUIC_ACK_TYPE_ACK_IMMEDIATE ||
        (Tracker->AckElicitingPacketsToAcknowledge >= (uint16_t)Connection->PacketTolerance) ||
        (!Connection->State.IgnoreReordering &&
         (NewLargestPacketNumber &&
          QuicRangeSize(&Tracker->PacketNumbersToAck) > 1 && // There are more than two ranges, i.e. a gap somewhere.
            QuicRangeGet(
            &Tracker->PacketNumbersToAck,
          QuicRangeSize(&Tracker->PacketNumbersToAck) - 1)->Count == 1))) { // The gap is right before the last packet number.
        //
        // Always send an ACK immediately if we have received enough ACK
        // eliciting packets OR the latest one indicate a gap in the packet
        // numbers, which likely means there was loss.
        //
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_ACK);

    } else if (Tracker->AckElicitingPacketsToAcknowledge == 1) {
        //
        // We now have ACK eliciting payload to acknowledge but haven't met the
        // criteria to send an ACK frame immediately, so just ensure the delayed
        // ACK timer is running.
        //
        QuicSendStartDelayedAckTimer(&Connection->Send);
    }

Exit:

    QuicSendValidate(&Connection->Send);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicAckTrackerAckFrameEncode(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(QuicAckTrackerHasPacketsToAck(Tracker));

    uint64_t AckDelay =
        CxPlatTimeDiff64(Tracker->LargestPacketNumberRecvTime, CxPlatTimeUs64());

    AckDelay >>= Builder->Connection->AckDelayExponent;

    if (!QuicAckFrameEncode(
            &Tracker->PacketNumbersToAck,
            AckDelay,
            Tracker->NonZeroRecvECN ?
                &Tracker->ReceivedECN :
                NULL,
            &Builder->DatagramLength,
            (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead,
            Builder->Datagram->Buffer)) {
        return FALSE;
    }

    if (Tracker->AckElicitingPacketsToAcknowledge) {
        Tracker->AckElicitingPacketsToAcknowledge = 0;
        QuicSendUpdateAckState(&Builder->Connection->Send);
    }

    Tracker->AlreadyWrittenAckFrame = TRUE;
    Tracker->LargestPacketNumberAcknowledged =
        Builder->Metadata->Frames[Builder->Metadata->FrameCount].ACK.LargestAckedPacketNumber =
        QuicRangeGetMax(&Tracker->PacketNumbersToAck);
    (void)QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_ACK, FALSE);

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicAckTrackerOnAckFrameAcked(
    _Inout_ QUIC_ACK_TRACKER* Tracker,
    _In_ uint64_t LargestAckedPacketNumber
    )
{
    QUIC_CONNECTION* Connection = QuicAckTrackerGetPacketSpace(Tracker)->Connection;

    //
    // Drop all packet numbers less than or equal to the largest acknowledged
    // packet number.
    //
    QuicRangeSetMin(
        &Tracker->PacketNumbersToAck,
        LargestAckedPacketNumber + 1);

    if (!QuicAckTrackerHasPacketsToAck(Tracker) &&
        Tracker->AckElicitingPacketsToAcknowledge) {
        //
        // If we received packets out of order and ended up sending an ACK for
        // larger packet numbers before receiving the smaller ones, it's
        // possible we will remove all the ACK ranges even though we haven't
        // acknowledged the smaller one yet. In that case, we need to make sure
        // have all other state match up to the ranges.
        //
        Tracker->AckElicitingPacketsToAcknowledge = 0;
        QuicSendUpdateAckState(&Connection->Send);
    }
}
