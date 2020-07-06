/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This module tracks in-flight packets and determines when they
    have been lost or delivered to the peer.


    RACK (time-based loss detection) algorithm:

    An unacknowledged packet sent before an acknowledged packet and
    sent more than QUIC_TIME_REORDER_THRESHOLD ago is assumed lost.


    There are three logical timers in this module:

    1)  Disconnect timer: if a packet is outstanding for DisconnectTimeoutUs
        without being acknowledged or determined lost (for example, if no ACKs
        are received at all after sending the packet), the connection is
        terminated. This is the last-resort "give-up" timer, and is armed
        whenever there is an outstanding packet.

    2)  RACK timer: armed whenever there is an outstanding packet with a later
        packet acknowledged. This is required to trigger the RACK loss detection
        algorithm described above. When this is armed, the probe timer is not.

    3)  Probe timer: the purpose of this timer is to ensure the RACK algorithm
        discovers lost packets in all cases. One example case where this helps
        is when the very last packet sent is dropped. RACK cannot determine
        that the last packet was lost, since it is defined based on later
        packets being ACKed.

        The probe timer is armed whenever the RACK timer is not armed and there
        is an outstanding packet. Its period is a function of RTT, and doubles
        for each consecutive fire. The expiry time is based on the earliest
        packet in the set consisting of the latest outstanding packet sent in
        each packet number space.

        When the probe timer fires, two probe packets are sent.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "loss_detection.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLossDetectionRetransmitFrames(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_SENT_PACKET_METADATA* Packet,
    _In_ BOOLEAN ReleasePacket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionOnPacketDiscarded(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_SENT_PACKET_METADATA* Packet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionInitializeInternalState(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    LossDetection->PacketsInFlight = 0;
    LossDetection->ProbeCount = 0;
}

#if DEBUG
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossValidate(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    uint32_t AckElicitingPackets = 0;
    QUIC_SENT_PACKET_METADATA** Tail = &LossDetection->SentPackets;
    while (*Tail) {
        QUIC_DBG_ASSERT(!(*Tail)->Flags.Freed);
        if ((*Tail)->Flags.IsAckEliciting) {
            AckElicitingPackets++;
        }
        Tail = &((*Tail)->Next);
    }
    QUIC_DBG_ASSERT(Tail == LossDetection->SentPacketsTail);
    QUIC_DBG_ASSERT(LossDetection->PacketsInFlight == AckElicitingPackets);

    Tail = &LossDetection->LostPackets;
    while (*Tail) {
        QUIC_DBG_ASSERT(!(*Tail)->Flags.Freed);
        Tail = &((*Tail)->Next);
    }
    QUIC_DBG_ASSERT(Tail == LossDetection->LostPacketsTail);
}
#else
#define QuicLossValidate(LossDetection)
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionInitialize(
    _Inout_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    LossDetection->SentPackets = NULL;
    LossDetection->SentPacketsTail = &LossDetection->SentPackets;
    LossDetection->LostPackets = NULL;
    LossDetection->LostPacketsTail = &LossDetection->LostPackets;
    QuicLossDetectionInitializeInternalState(LossDetection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionUninitialize(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    while (LossDetection->SentPackets != NULL) {
        QUIC_SENT_PACKET_METADATA* Packet = LossDetection->SentPackets;
        LossDetection->SentPackets = LossDetection->SentPackets->Next;

        if (Packet->Flags.IsAckEliciting) {
            QuicTraceLogVerbose(
                PacketTxDiscarded,
                "[%c][TX][%llu] Thrown away on shutdown",
                PtkConnPre(Connection),
                Packet->PacketNumber);

        }

        QuicLossDetectionOnPacketDiscarded(LossDetection, Packet);
    }
    while (LossDetection->LostPackets != NULL) {
        QUIC_SENT_PACKET_METADATA* Packet = LossDetection->LostPackets;
        LossDetection->LostPackets = LossDetection->LostPackets->Next;

        QuicTraceLogVerbose(
            PacketTxLostDiscarded,
            "[%c][TX][%llu] Thrown away on shutdown (lost packet)",
            PtkConnPre(Connection),
            Packet->PacketNumber);

        QuicLossDetectionOnPacketDiscarded(LossDetection, Packet);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionReset(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_LOSS_DETECTION);

    //
    // Reset internal variables.
    //
    QuicLossDetectionInitializeInternalState(LossDetection);

    //
    // Throw away any outstanding packets.
    //

    while (LossDetection->SentPackets != NULL) {
        QUIC_SENT_PACKET_METADATA* Packet = LossDetection->SentPackets;
        LossDetection->SentPackets = LossDetection->SentPackets->Next;
        QuicLossDetectionRetransmitFrames(LossDetection, Packet, TRUE);
    }
    LossDetection->SentPacketsTail = &LossDetection->SentPackets;

    while (LossDetection->LostPackets != NULL) {
        QUIC_SENT_PACKET_METADATA* Packet = LossDetection->LostPackets;
        LossDetection->LostPackets = LossDetection->LostPackets->Next;
        QuicLossDetectionRetransmitFrames(LossDetection, Packet, TRUE);
    }
    LossDetection->LostPacketsTail = &LossDetection->LostPackets;

    QuicLossValidate(LossDetection);
}

//
// Returns the oldest outstanding retransmittable packet's sent tracking
// data structure. Returns NULL if there are no oustanding retransmittable
// packets.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SENT_PACKET_METADATA*
QuicLossDetectionOldestOutstandingPacket(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_SENT_PACKET_METADATA* Packet = LossDetection->SentPackets;
    while (Packet != NULL && !Packet->Flags.IsAckEliciting) {
        Packet = Packet->Next;
    }
    return Packet;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
uint32_t
QuicLossDetectionComputeProbeTimeout(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ const QUIC_PATH* Path,
    _In_ uint32_t Count
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    QUIC_DBG_ASSERT(Path->SmoothedRtt != 0);

    //
    // Microseconds.
    //
    uint32_t Pto =
        Path->SmoothedRtt +
        4 * Path->RttVariance +
        (uint32_t)MS_TO_US(Connection->PeerTransportParams.MaxAckDelay);
    Pto *= Count;
    if (Pto < MsQuicLib.Settings.MaxWorkerQueueDelayUs) {
        Pto = MsQuicLib.Settings.MaxWorkerQueueDelayUs;
    }
    return Pto;
}

typedef enum QUIC_LOSS_TIMER_TYPE {
    LOSS_TIMER_INITIAL,
    LOSS_TIMER_RACK,
    LOSS_TIMER_PROBE
} QUIC_LOSS_TIMER_TYPE;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionUpdateTimer(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    if (Connection->State.ClosedLocally || Connection->State.ClosedRemotely) {
        //
        // No retransmission timer runs after the connection has been shut down.
        //
        QuicTraceEvent(
            ConnLossDetectionTimerCancel,
            "[conn][%p] Cancelling loss detection timer.",
            Connection);
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_LOSS_DETECTION);
        return;
    }

    const QUIC_SENT_PACKET_METADATA* OldestPacket = // Oldest retransmittable packet.
        QuicLossDetectionOldestOutstandingPacket(LossDetection);

    if (OldestPacket == NULL &&
        (QuicConnIsServer(Connection) ||
         Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT)) {
        //
        // Only run the timer when there are outstanding packets, unless this
        // is a client without 1-RTT keys, in which case the server might be
        // doing amplification protection, which means more data might need to
        // be sent to unblock it.
        //
        QuicTraceEvent(
            ConnLossDetectionTimerCancel,
            "[conn][%p] Cancelling loss detection timer.",
            Connection);
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_LOSS_DETECTION);
        return;
    }

    QUIC_PATH* Path = &Connection->Paths[0]; // TODO - Is this right?

    if (!Path->IsPeerValidated && Path->Allowance < QUIC_MIN_SEND_ALLOWANCE) {
        //
        // Sending is restricted for amplification protection.
        // Don't run the timer, because nothing can be sent when it fires.
        //
        QuicTraceEvent(
            ConnLossDetectionTimerCancel,
            "[conn][%p] Cancelling loss detection timer.",
            Connection);
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_LOSS_DETECTION);
        return;
    }

    uint32_t TimeNow = QuicTimeUs32();

    QUIC_DBG_ASSERT(Path->SmoothedRtt != 0);

    uint32_t TimeFires;
    QUIC_LOSS_TIMER_TYPE TimeoutType;
    if (OldestPacket != NULL &&
        OldestPacket->PacketNumber < LossDetection->LargestAck &&
        QuicKeyTypeToEncryptLevel(OldestPacket->Flags.KeyType) <= LossDetection->LargestAckEncryptLevel) {
        //
        // RACK timer.
        // There is an outstanding packet with a later packet acknowledged.
        // Set a timeout for the remainder of QUIC_TIME_REORDER_THRESHOLD.
        // If it expires, we'll consider the packet lost.
        //
        TimeoutType = LOSS_TIMER_RACK;
        uint32_t RttUs = max(Path->SmoothedRtt, Path->LatestRttSample);
        TimeFires = OldestPacket->SentTime + QUIC_TIME_REORDER_THRESHOLD(RttUs);

    } else if (!Path->GotFirstRttSample) {

        //
        // We don't have an RTT sample yet, so SmoothedRtt = InitialRtt.
        //
        TimeoutType = LOSS_TIMER_INITIAL;
        TimeFires =
            LossDetection->TimeOfLastPacketSent +
            ((2 * Path->SmoothedRtt) << LossDetection->ProbeCount);

    } else {
        TimeoutType = LOSS_TIMER_PROBE;
        TimeFires =
            LossDetection->TimeOfLastPacketSent +
            QuicLossDetectionComputeProbeTimeout(
                LossDetection, Path, 1 << LossDetection->ProbeCount);
    }

    //
    // The units for the delay values start in microseconds. Before being passed
    // to QuicConnTimerSet, Delay is converted to milliseconds. To account for
    // any rounding errors, 1 extra millisecond is added to the timer, so it
    // doesn't end up firing early.
    //

    uint32_t Delay = QuicTimeDiff32(TimeNow, TimeFires);

    //
    // Limit the timeout to the remainder of the disconnect timeout if there is
    // an outstanding packet.
    //
    uint32_t MaxDelay;
    if (OldestPacket != NULL) {
        MaxDelay =
            QuicTimeDiff32(
                TimeNow,
                OldestPacket->SentTime + Connection->DisconnectTimeoutUs);
    } else {
        MaxDelay = (UINT32_MAX >> 1) - 1;
    }

    if (Delay >= (UINT32_MAX >> 1) || MaxDelay >= (UINT32_MAX >> 1)) {
        //
        // We treat a difference of half or more of the max integer space as a
        // negative value and just set the delay back to zero to fire
        // immediately. N.B. This breaks down if an expected timeout value ever
        // exceeds ~35.7 minutes.
        //
        Delay = 0;
    } else if (Delay > MaxDelay) {
        //
        // The disconnect timeout is now the limiting factor for the timer.
        //
        Delay = US_TO_MS(MaxDelay) + 1;
    } else {
        Delay = US_TO_MS(Delay) + 1;
    }

    QuicTraceEvent(
        ConnLossDetectionTimerSet,
        "[conn][%p] Setting loss detection %hhu timer for %u ms. (ProbeCount=%hu)",
        Connection,
        TimeoutType,
        Delay,
        LossDetection->ProbeCount);
    UNREFERENCED_PARAMETER(TimeoutType);
    QuicConnTimerSet(Connection, QUIC_CONN_TIMER_LOSS_DETECTION, Delay);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLossDetectionOnPacketSent(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_SENT_PACKET_METADATA* TempSentPacket
    )
{
    QUIC_SENT_PACKET_METADATA* SentPacket;
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    QUIC_DBG_ASSERT(TempSentPacket->FrameCount != 0);

    //
    // Allocate a copy of the packet metadata.
    //
    SentPacket =
        QuicSentPacketPoolGetPacketMetadata(
            &Connection->Worker->SentPacketPool, TempSentPacket->FrameCount);
    if (SentPacket == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QuicCopyMemory(
        SentPacket,
        TempSentPacket,
        sizeof(QUIC_SENT_PACKET_METADATA) +
        sizeof(QUIC_SENT_FRAME_METADATA) * TempSentPacket->FrameCount);

    LossDetection->LargestSentPacketNumber = TempSentPacket->PacketNumber;

    //
    // Add to the outstanding-packet queue.
    //
    SentPacket->Next = NULL;
    *LossDetection->SentPacketsTail = SentPacket;
    LossDetection->SentPacketsTail = &SentPacket->Next;

    QUIC_DBG_ASSERT(
        SentPacket->Flags.KeyType != QUIC_PACKET_KEY_0_RTT ||
        SentPacket->Flags.IsAckEliciting);

    Connection->Stats.Send.TotalPackets++;
    Connection->Stats.Send.TotalBytes += TempSentPacket->PacketLength;
    if (SentPacket->Flags.IsAckEliciting) {

        if (LossDetection->PacketsInFlight == 0) {
            QuicConnResetIdleTimeout(Connection);
        }

        Connection->Stats.Send.RetransmittablePackets++;
        LossDetection->PacketsInFlight++;
        LossDetection->TimeOfLastPacketSent = SentPacket->SentTime;

        if (!Path->IsPeerValidated) {
            QuicPathDecrementAllowance(
                Connection, Path, SentPacket->PacketLength);
        }

        QuicCongestionControlOnDataSent(
            &Connection->CongestionControl, SentPacket->PacketLength);
    }

    QuicLossValidate(LossDetection);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionOnPacketAcknowledged(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _In_ QUIC_SENT_PACKET_METADATA* Packet
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);
    QUIC_PATH* Path = QuicConnGetPathByID(Connection, Packet->PathId);

    _Analysis_assume_(
        EncryptLevel >= QUIC_ENCRYPT_LEVEL_INITIAL &&
        EncryptLevel < QUIC_ENCRYPT_LEVEL_COUNT);

    if (!QuicConnIsServer(Connection) &&
        !Connection->State.HandshakeConfirmed &&
        Packet->Flags.KeyType == QUIC_PACKET_KEY_1_RTT) {
        QuicTraceLogConnInfo(
            HandshakeConfirmedAck,
            Connection,
            "Handshake confirmed (ack)");
        QuicCryptoHandshakeConfirmed(&Connection->Crypto);
    }

    QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    if (EncryptLevel == QUIC_ENCRYPT_LEVEL_1_RTT &&
        PacketSpace->AwaitingKeyPhaseConfirmation &&
        Packet->Flags.KeyPhase == PacketSpace->CurrentKeyPhase &&
        Packet->PacketNumber >= PacketSpace->WriteKeyPhaseStartPacketNumber) {
        QuicTraceLogConnVerbose(
            KeyChangeConfirmed,
            Connection,
            "Key change confirmed by peer");
        PacketSpace->AwaitingKeyPhaseConfirmation = FALSE;
    }

    for (uint8_t i = 0; i < Packet->FrameCount; i++) {
        switch (Packet->Frames[i].Type) {

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_1:
            QuicAckTrackerOnAckFrameAcked(
                &Connection->Packets[EncryptLevel]->AckTracker,
                Packet->Frames[i].ACK.LargestAckedPacketNumber);
            break;

        case QUIC_FRAME_RESET_STREAM:
            QuicStreamOnResetAck(Packet->Frames[i].RESET_STREAM.Stream);
            break;

        case QUIC_FRAME_CRYPTO:
            QuicCryptoOnAck(&Connection->Crypto, &Packet->Frames[i]);
            break;

        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
            QuicStreamOnAck(
                Packet->Frames[i].STREAM.Stream,
                Packet->Flags,
                &Packet->Frames[i]);
            break;

        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            if (Packet->Frames[i].STREAM_DATA_BLOCKED.Stream->OutFlowBlockedReasons &
                QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL) {
                //
                // Stream is still blocked, so queue the blocked frame up again.
                //
                // N.B. If this design of immediate resending after ACK ever
                // gets too chatty, then we can reuse the existing loss
                // detection timer to add exponential backoff.
                //
                QuicSendSetStreamSendFlag(
                    &Connection->Send,
                    Packet->Frames[i].STREAM_DATA_BLOCKED.Stream,
                    QUIC_STREAM_SEND_FLAG_DATA_BLOCKED);
            }
            break;

        case QUIC_FRAME_NEW_CONNECTION_ID: {
            BOOLEAN IsLastCid;
            QUIC_CID_HASH_ENTRY* SourceCid =
                QuicConnGetSourceCidFromSeq(
                    Connection,
                    Packet->Frames[i].NEW_CONNECTION_ID.Sequence,
                    FALSE,
                    &IsLastCid);
            if (SourceCid != NULL) {
                SourceCid->CID.Acknowledged = TRUE;
            }
            break;
        }

        case QUIC_FRAME_RETIRE_CONNECTION_ID: {
            QUIC_CID_QUIC_LIST_ENTRY* DestCid =
                QuicConnGetDestCidFromSeq(
                    Connection,
                    Packet->Frames[i].RETIRE_CONNECTION_ID.Sequence,
                    TRUE);
            if (DestCid != NULL) {
                QUIC_FREE(DestCid);
            }
            break;
        }

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1:
            QuicDatagramIndicateSendStateChange(
                Connection,
                &Packet->Frames[i].DATAGRAM.ClientContext,
                Packet->Flags.SuspectedLost ?
                    QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS :
                    QUIC_DATAGRAM_SEND_ACKNOWLEDGED);
            break;
        }
    }

    if (Path != NULL && Packet->Flags.IsPMTUD) {
        QuicSendOnMtuProbePacketAcked(&Connection->Send, Path, Packet);
    }

    QuicSentPacketPoolReturnPacketMetadata(&Connection->Worker->SentPacketPool, Packet);
}

//
// Marks all the frames in the packet that can be retransmitted as needing to be
// retransmitted. Returns TRUE if some new data was queued up to be sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLossDetectionRetransmitFrames(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_SENT_PACKET_METADATA* Packet,
    _In_ BOOLEAN ReleasePacket
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);
    BOOLEAN NewDataQueued = FALSE;

    for (uint8_t i = 0; i < Packet->FrameCount; i++) {
        switch (Packet->Frames[i].Type) {
        case QUIC_FRAME_PING:
            if (!Packet->Flags.IsPMTUD) {
                NewDataQueued |=
                    QuicSendSetSendFlag(
                        &Connection->Send,
                        QUIC_CONN_SEND_FLAG_PING);
            }
            break;

        case QUIC_FRAME_RESET_STREAM:
            NewDataQueued |=
                QuicSendSetStreamSendFlag(
                    &Connection->Send,
                    Packet->Frames[i].RESET_STREAM.Stream,
                    QUIC_STREAM_SEND_FLAG_SEND_ABORT);
            break;

        case QUIC_FRAME_STOP_SENDING:
            NewDataQueued |=
                QuicSendSetStreamSendFlag(
                    &Connection->Send,
                    Packet->Frames[i].STOP_SENDING.Stream,
                    QUIC_STREAM_SEND_FLAG_RECV_ABORT);
            break;

        case QUIC_FRAME_CRYPTO:
            NewDataQueued |=
                QuicCryptoOnLoss(
                    &Connection->Crypto,
                    &Packet->Frames[i]);
            break;

        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
            NewDataQueued |=
                QuicStreamOnLoss(
                    Packet->Frames[i].STREAM.Stream,
                    &Packet->Frames[i]);
            break;

        case QUIC_FRAME_MAX_DATA:
            NewDataQueued |=
                QuicSendSetSendFlag(
                    &Connection->Send,
                    QUIC_CONN_SEND_FLAG_MAX_DATA);
            break;

        case QUIC_FRAME_MAX_STREAM_DATA:
            NewDataQueued |=
                QuicSendSetStreamSendFlag(
                    &Connection->Send,
                    Packet->Frames[i].MAX_STREAM_DATA.Stream,
                    QUIC_STREAM_SEND_FLAG_MAX_DATA);
            break;

        case QUIC_FRAME_MAX_STREAMS:
            NewDataQueued |=
                QuicSendSetSendFlag(
                    &Connection->Send,
                    QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI);
            break;

        case QUIC_FRAME_MAX_STREAMS_1:
            NewDataQueued |=
                QuicSendSetSendFlag(
                    &Connection->Send,
                    QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI);
            break;

        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            NewDataQueued |=
                QuicSendSetStreamSendFlag(
                    &Connection->Send,
                    Packet->Frames[i].STREAM_DATA_BLOCKED.Stream,
                    QUIC_STREAM_SEND_FLAG_DATA_BLOCKED);
            break;

        case QUIC_FRAME_NEW_CONNECTION_ID: {
            BOOLEAN IsLastCid;
            QUIC_CID_HASH_ENTRY* SourceCid =
                QuicConnGetSourceCidFromSeq(
                    Connection,
                    Packet->Frames[i].NEW_CONNECTION_ID.Sequence,
                    FALSE,
                    &IsLastCid);
            if (SourceCid != NULL &&
                !SourceCid->CID.Acknowledged) {
                SourceCid->CID.NeedsToSend = TRUE;
                NewDataQueued |=
                    QuicSendSetSendFlag(
                        &Connection->Send,
                        QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID);
            }
            break;
        }

        case QUIC_FRAME_RETIRE_CONNECTION_ID: {
            QUIC_CID_QUIC_LIST_ENTRY* DestCid =
                QuicConnGetDestCidFromSeq(
                    Connection,
                    Packet->Frames[i].RETIRE_CONNECTION_ID.Sequence,
                    FALSE);
            if (DestCid != NULL) {
                QUIC_DBG_ASSERT(DestCid->CID.Retired);
                DestCid->CID.NeedsToSend = TRUE;
                NewDataQueued |=
                    QuicSendSetSendFlag(
                        &Connection->Send,
                        QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID);
            }
            break;
        }

        case QUIC_FRAME_PATH_CHALLENGE: {
            QUIC_PATH* Path = QuicConnGetPathByID(Connection, Packet->PathId);
            if (Path != NULL && !Path->IsPeerValidated) {
                uint32_t TimeNow = QuicTimeUs32();
                QUIC_DBG_ASSERT(Connection->Session != NULL);
                uint32_t ValidationTimeout =
                    max(QuicLossDetectionComputeProbeTimeout(LossDetection, Path, 3),
                        6 * MS_TO_US(Connection->Session->Settings.InitialRttMs));
                if (QuicTimeDiff32(Path->PathValidationStartTime, TimeNow) > ValidationTimeout) {
                    QuicTraceLogConnInfo(
                        PathValidationTimeout,
                        Connection,
                        "Path[%hhu] validation timed out",
                        Path->ID);
                    QuicPathRemove(Connection, Packet->PathId);
                } else {
                    Path->SendChallenge = TRUE;
                    QuicSendSetSendFlag(
                        &Connection->Send,
                        QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
                }
            }
            break;
        }

        case QUIC_FRAME_HANDSHAKE_DONE:
            NewDataQueued |=
                QuicSendSetSendFlag(
                    &Connection->Send,
                    QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE);
            break;

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1:
            if (!Packet->Flags.SuspectedLost) {
                QuicDatagramIndicateSendStateChange(
                    Connection,
                    &Packet->Frames[i].DATAGRAM.ClientContext,
                    QUIC_DATAGRAM_SEND_LOST_SUSPECT);
            }
            break;
        }
    }

    Packet->Flags.SuspectedLost = TRUE;

    if (ReleasePacket) {
        QuicSentPacketPoolReturnPacketMetadata(&Connection->Worker->SentPacketPool, Packet);
    }

    return NewDataQueued;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionOnPacketDiscarded(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_SENT_PACKET_METADATA* Packet
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    for (uint8_t i = 0; i < Packet->FrameCount; i++) {
        switch (Packet->Frames[i].Type) {

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1:
            QuicDatagramIndicateSendStateChange(
                Connection,
                &Packet->Frames[i].DATAGRAM.ClientContext,
                QUIC_DATAGRAM_SEND_LOST_DISCARDED);
            break;
        }
    }

    QuicSentPacketPoolReturnPacketMetadata(&Connection->Worker->SentPacketPool, Packet);
}

//
// Returns TRUE if any lost retransmittable bytes were detected.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLossDetectionDetectAndHandleLostPackets(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ uint32_t TimeNow
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);
    uint32_t LostRetransmittableBytes = 0;
    QUIC_SENT_PACKET_METADATA* Packet;

    if (LossDetection->LostPackets != NULL) {
        //
        // Clean out any packets in the LostPackets list that we are pretty
        // confident will never be acknowledged.
        //
        uint32_t TwoPto =
            QuicLossDetectionComputeProbeTimeout(
                LossDetection,
                &Connection->Paths[0], // TODO - Is this right?
                2);
        while ((Packet = LossDetection->LostPackets) != NULL &&
                Packet->PacketNumber < LossDetection->LargestAck &&
                QuicTimeDiff32(Packet->SentTime, TimeNow) > TwoPto) {
            QuicTraceLogVerbose(
                PacketTxForget,
                "[%c][TX][%llu] Forgetting",
                PtkConnPre(Connection),
                Packet->PacketNumber);
            LossDetection->LostPackets = Packet->Next;
            QuicLossDetectionOnPacketDiscarded(LossDetection, Packet);
        }
        if (LossDetection->LostPackets == NULL) {
            LossDetection->LostPacketsTail = &LossDetection->LostPackets;
        }

        QuicLossValidate(LossDetection);
    }

    if (LossDetection->SentPackets != NULL) {
        //
        // Remove "suspect" packets inferred lost from out-of-order ACKs.
        // The spec has:
        // kTimeThreshold * max(SRTT, latest_RTT, kGranularity),
        // where kGranularity is the system timer granularity.
        // This implementation excludes kGranularity from the calculation,
        // because it is not needed to keep timers from firing early.
        //
        const QUIC_PATH* Path = &Connection->Paths[0]; // TODO - Correct?
        uint32_t Rtt = max(Path->SmoothedRtt, Path->LatestRttSample);
        uint32_t TimeReorderThreshold = QUIC_TIME_REORDER_THRESHOLD(Rtt);
        uint64_t LargestLostPacketNumber = 0;
        QUIC_SENT_PACKET_METADATA* PrevPacket = NULL;
        Packet = LossDetection->SentPackets;
        while (Packet != NULL) {

            BOOLEAN NonretransmittableHandshakePacket =
                !Packet->Flags.IsAckEliciting &&
                Packet->Flags.KeyType < QUIC_PACKET_KEY_1_RTT;
            QUIC_ENCRYPT_LEVEL EncryptLevel =
                QuicKeyTypeToEncryptLevel(Packet->Flags.KeyType);

            if (EncryptLevel > LossDetection->LargestAckEncryptLevel) {
                PrevPacket = Packet;
                Packet = Packet->Next;
                continue;
            } else if (Packet->PacketNumber + QUIC_PACKET_REORDER_THRESHOLD < LossDetection->LargestAck) {
                if (!NonretransmittableHandshakePacket) {
                    QuicTraceLogVerbose(
                        PacketTxLostFack,
                        "[%c][TX][%llu] Lost: FACK %llu packets",
                        PtkConnPre(Connection),
                        Packet->PacketNumber,
                        LossDetection->LargestAck - Packet->PacketNumber);
                    QuicTraceEvent(
                        ConnPacketLost,
                        "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                        Connection,
                        Packet->PacketNumber,
                        QuicPacketTraceType(Packet),
                        QUIC_TRACE_PACKET_LOSS_FACK);
                }
            } else if (Packet->PacketNumber < LossDetection->LargestAck &&
                        QuicTimeAtOrBefore32(Packet->SentTime + TimeReorderThreshold, TimeNow)) {
                if (!NonretransmittableHandshakePacket) {
                    QuicTraceLogVerbose(
                        PacketTxLostRack,
                        "[%c][TX][%llu] Lost: RACK %lu ms",
                        PtkConnPre(Connection),
                        Packet->PacketNumber,
                        QuicTimeDiff32(Packet->SentTime, TimeNow));
                    QuicTraceEvent(
                        ConnPacketLost,
                        "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                        Connection,
                        Packet->PacketNumber,
                        QuicPacketTraceType(Packet),
                        QUIC_TRACE_PACKET_LOSS_RACK);
                }
            } else {
                break;
            }

            Connection->Stats.Send.SuspectedLostPackets++;
            if (Packet->Flags.IsAckEliciting) {
                LossDetection->PacketsInFlight--;
                LostRetransmittableBytes += Packet->PacketLength;
                QuicLossDetectionRetransmitFrames(LossDetection, Packet, FALSE);
            }

            LargestLostPacketNumber = Packet->PacketNumber;
            if (PrevPacket == NULL) {
                LossDetection->SentPackets = Packet->Next;
                if (Packet->Next == NULL) {
                    LossDetection->SentPacketsTail = &LossDetection->SentPackets;
                }
            } else {
                PrevPacket->Next = Packet->Next;
                if (Packet->Next == NULL) {
                    LossDetection->SentPacketsTail = &PrevPacket->Next;
                }
            }

            *LossDetection->LostPacketsTail = Packet;
            LossDetection->LostPacketsTail = &Packet->Next;
            Packet = Packet->Next;
            *LossDetection->LostPacketsTail = NULL;
        }

        QuicLossValidate(LossDetection);

        if (LostRetransmittableBytes > 0) {
            QuicCongestionControlOnDataLost(
                &Connection->CongestionControl,
                LargestLostPacketNumber,
                LossDetection->LargestSentPacketNumber,
                LostRetransmittableBytes,
                LossDetection->ProbeCount > QUIC_PERSISTENT_CONGESTION_THRESHOLD);
            //
            // Send packets from any previously blocked streams.
            //
            QuicSendQueueFlush(&Connection->Send, REASON_LOSS);
        }
    }

    QuicLossValidate(LossDetection);

    return LostRetransmittableBytes > 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionDiscardPackets(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PACKET_KEY_TYPE KeyType
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(KeyType);
    QUIC_SENT_PACKET_METADATA* PrevPacket;
    QUIC_SENT_PACKET_METADATA* Packet;
    uint32_t AckedRetransmittableBytes = 0;
    uint32_t TimeNow = QuicTimeUs32();

    QUIC_DBG_ASSERT(KeyType == QUIC_PACKET_KEY_INITIAL || KeyType == QUIC_PACKET_KEY_HANDSHAKE);

    //
    // Implicitly ACK all outstanding packets.
    //

    PrevPacket = NULL;
    Packet = LossDetection->LostPackets;
    while (Packet != NULL) {
        QUIC_SENT_PACKET_METADATA* NextPacket = Packet->Next;

        if (Packet->Flags.KeyType == KeyType) {
            if (PrevPacket != NULL) {
                PrevPacket->Next = NextPacket;
                if (NextPacket == NULL) {
                    LossDetection->LostPacketsTail = &PrevPacket->Next;
                }
            } else {
                LossDetection->LostPackets = NextPacket;
                if (NextPacket == NULL) {
                    LossDetection->LostPacketsTail = &LossDetection->LostPackets;
                }
            }

            QuicTraceLogVerbose(
                PacketTxAckedImplicit,
                "[%c][TX][%llu] ACKed (implicit)",
                PtkConnPre(Connection),
                Packet->PacketNumber);
            QuicTraceEvent(
                ConnPacketACKed,
                "[conn][%p][TX][%llu] %hhu ACKed",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet));
            QuicLossDetectionOnPacketAcknowledged(LossDetection, EncryptLevel, Packet);

            Packet = NextPacket;

        } else {
            PrevPacket = Packet;
            Packet = NextPacket;
        }
    }

    QuicLossValidate(LossDetection);

    PrevPacket = NULL;
    Packet = LossDetection->SentPackets;
    while (Packet != NULL) {
        QUIC_SENT_PACKET_METADATA* NextPacket = Packet->Next;

        if (Packet->Flags.KeyType == KeyType) {
            if (PrevPacket != NULL) {
                PrevPacket->Next = NextPacket;
                if (NextPacket == NULL) {
                    LossDetection->SentPacketsTail = &PrevPacket->Next;
                }
            } else {
                LossDetection->SentPackets = NextPacket;
                if (NextPacket == NULL) {
                    LossDetection->SentPacketsTail = &LossDetection->SentPackets;
                }
            }

            QuicTraceLogVerbose(
                PacketTxAckedImplicit,
                "[%c][TX][%llu] ACKed (implicit)",
                PtkConnPre(Connection),
                Packet->PacketNumber);
            QuicTraceEvent(
                ConnPacketACKed,
                "[conn][%p][TX][%llu] %hhu ACKed",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet));

            if (Packet->Flags.IsAckEliciting) {
                LossDetection->PacketsInFlight--;
                AckedRetransmittableBytes += Packet->PacketLength;
            }

            QuicLossDetectionOnPacketAcknowledged(LossDetection, EncryptLevel, Packet);

            Packet = NextPacket;

        } else {
            PrevPacket = Packet;
            Packet = NextPacket;
        }
    }

    QuicLossValidate(LossDetection);

    if (AckedRetransmittableBytes > 0) {
        const QUIC_PATH* Path = &Connection->Paths[0]; // TODO - Correct?
        if (QuicCongestionControlOnDataAcknowledged(
                &Connection->CongestionControl,
                US_TO_MS(TimeNow),
                LossDetection->LargestAck,
                AckedRetransmittableBytes,
                Path->SmoothedRtt)) {
            //
            // We were previously blocked and are now unblocked.
            //
            QuicSendQueueFlush(&Connection->Send, REASON_CONGESTION_CONTROL);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionOnZeroRttRejected(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);
    QUIC_SENT_PACKET_METADATA* PrevPacket;
    QUIC_SENT_PACKET_METADATA* Packet;
    uint32_t CountRetransmittableBytes = 0;

    //
    // Marks all the packets as lost so they can be retransmitted immediately.
    //

    PrevPacket = NULL;
    Packet = LossDetection->SentPackets;
    while (Packet != NULL) {
        QUIC_SENT_PACKET_METADATA* NextPacket = Packet->Next;

        if (Packet->Flags.KeyType == QUIC_PACKET_KEY_0_RTT) {
            if (PrevPacket != NULL) {
                PrevPacket->Next = NextPacket;
                if (NextPacket == NULL) {
                    LossDetection->SentPacketsTail = &PrevPacket->Next;
                }
            } else {
                LossDetection->SentPackets = NextPacket;
                if (NextPacket == NULL) {
                    LossDetection->SentPacketsTail = &LossDetection->SentPackets;
                }
            }

            QuicTraceLogVerbose(
                PacketTx0RttRejected,
                "[%c][TX][%llu] Rejected",
                PtkConnPre(Connection),
                Packet->PacketNumber);

            QUIC_DBG_ASSERT(Packet->Flags.IsAckEliciting);

            LossDetection->PacketsInFlight--;
            CountRetransmittableBytes += Packet->PacketLength;

            QuicLossDetectionRetransmitFrames(LossDetection, Packet, TRUE);

            Packet = NextPacket;

        } else {
            PrevPacket = Packet;
            Packet = NextPacket;
        }
    }

    QuicLossValidate(LossDetection);

    if (CountRetransmittableBytes > 0) {
        if (QuicCongestionControlOnDataInvalidated(
                &Connection->CongestionControl,
                CountRetransmittableBytes)) {
            //
            // We were previously blocked and are now unblocked.
            //
            QuicSendQueueFlush(&Connection->Send, REASON_CONGESTION_CONTROL);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionProcessAckBlocks(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _In_ uint64_t AckDelay,
    _In_ QUIC_RANGE* AckBlocks,
    _Out_ BOOLEAN* InvalidAckBlock
    )
{
    QUIC_SENT_PACKET_METADATA* AckedPackets = NULL;
    QUIC_SENT_PACKET_METADATA** AckedPacketsTail = &AckedPackets;

    uint32_t AckedRetransmittableBytes = 0;
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);
    uint32_t TimeNow = QuicTimeUs32();
    uint32_t SmallestRtt = (uint32_t)(-1);
    BOOLEAN NewLargestAck = FALSE;
    BOOLEAN NewLargestAckRetransmittable = FALSE;
    BOOLEAN NewLargestAckDifferentPath = FALSE;

    *InvalidAckBlock = FALSE;

    QUIC_SENT_PACKET_METADATA** LostPacketsStart = &LossDetection->LostPackets;
    QUIC_SENT_PACKET_METADATA** SentPacketsStart = &LossDetection->SentPackets;
    QUIC_SENT_PACKET_METADATA* LargestAckedPacket = NULL;

    uint32_t i = 0;
    QUIC_SUBRANGE* AckBlock;
    while ((AckBlock = QuicRangeGetSafe(AckBlocks, i++)) != NULL) {

        //
        // Check to see if any packets in the LostPackets list are acknowledged,
        // which would mean we mistakenly classified those packets as lost.
        //
        if (*LostPacketsStart != NULL) {
            while (*LostPacketsStart && (*LostPacketsStart)->PacketNumber < AckBlock->Low) {
                LostPacketsStart = &((*LostPacketsStart)->Next);
            }

            QUIC_SENT_PACKET_METADATA** End = LostPacketsStart;
            while (*End && (*End)->PacketNumber <= QuicRangeGetHigh(AckBlock)) {
                QuicTraceLogVerbose(
                    PacketTxSpuriousLoss,
                    "[%c][TX][%llu] Spurious loss detected",
                    PtkConnPre(Connection),
                    (*End)->PacketNumber);
                Connection->Stats.Send.SpuriousLostPackets++;
                //
                // NOTE: we don't increment AckedRetransmittableBytes here
                // because we already told the congestion control module that
                // this packet left the network.
                //
                End = &((*End)->Next);
            }

            if (LostPacketsStart != End) {
                *AckedPacketsTail = *LostPacketsStart;
                AckedPacketsTail = End;
                *LostPacketsStart = *End;
                *End = NULL;
                if (End == LossDetection->LostPacketsTail) {
                    LossDetection->LostPacketsTail = LostPacketsStart;
                }

                QuicLossValidate(LossDetection);
            }
        }

        //
        // Now find all the acknowledged packets in the SentPackets list.
        //
        if (*SentPacketsStart != NULL) {
            while (*SentPacketsStart && (*SentPacketsStart)->PacketNumber < AckBlock->Low) {
                SentPacketsStart = &((*SentPacketsStart)->Next);
            }

            QUIC_SENT_PACKET_METADATA** End = SentPacketsStart;
            while (*End && (*End)->PacketNumber <= QuicRangeGetHigh(AckBlock)) {

                if ((*End)->Flags.IsAckEliciting) {
                    LossDetection->PacketsInFlight--;
                    AckedRetransmittableBytes += (*End)->PacketLength;
                }
                LargestAckedPacket = *End;
                End = &((*End)->Next);
            }

            if (SentPacketsStart != End) {
                //
                // Remove the ACKed packets from the outstanding packet list.
                //
                *AckedPacketsTail = *SentPacketsStart;
                AckedPacketsTail = End;
                *SentPacketsStart = *End;
                *End = NULL;
                if (End == LossDetection->SentPacketsTail) {
                    LossDetection->SentPacketsTail = SentPacketsStart;
                }

                QuicLossValidate(LossDetection);
            }
        }

        if (LargestAckedPacket != NULL &&
            LossDetection->LargestAck <= LargestAckedPacket->PacketNumber) {
            LossDetection->LargestAck = LargestAckedPacket->PacketNumber;
            if (EncryptLevel > LossDetection->LargestAckEncryptLevel) {
                LossDetection->LargestAckEncryptLevel = EncryptLevel;
            }
            NewLargestAck = TRUE;
            NewLargestAckRetransmittable = LargestAckedPacket->Flags.IsAckEliciting;
            NewLargestAckDifferentPath = Path->ID != LargestAckedPacket->PathId;
        }
    }

    if (AckedPackets == NULL) {
        //
        // Nothing was acknowledged, so we can exit now.
        //
        return;
    }

    while (AckedPackets != NULL) {

        QUIC_SENT_PACKET_METADATA* Packet = AckedPackets;
        AckedPackets = AckedPackets->Next;

        if (QuicKeyTypeToEncryptLevel(Packet->Flags.KeyType) != EncryptLevel) {
            //
            // The packet was not acknowledged with the same encryption level.
            //
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Incorrect ACK encryption level");
            *InvalidAckBlock = TRUE;
            return;
        }

        uint32_t PacketRtt = QuicTimeDiff32(Packet->SentTime, TimeNow);
        QuicTraceLogVerbose(
            PacketTxAcked,
            "[%c][TX][%llu] ACKed (%u.%03u ms)",
            PtkConnPre(Connection),
            Packet->PacketNumber,
            PacketRtt / 1000,
            PacketRtt % 1000);
        QuicTraceEvent(
            ConnPacketACKed,
            "[conn][%p][TX][%llu] %hhu ACKed",
            Connection,
            Packet->PacketNumber,
            QuicPacketTraceType(Packet));

        SmallestRtt = min(SmallestRtt, PacketRtt);

        QuicLossDetectionOnPacketAcknowledged(LossDetection, EncryptLevel, Packet);
    }

    QuicLossValidate(LossDetection);

    if (NewLargestAckRetransmittable && !NewLargestAckDifferentPath) {
        //
        // Update the current RTT with the smallest RTT calculated, which
        // should be for the most acknowledged retransmittable packet.
        //
        QUIC_DBG_ASSERT(SmallestRtt != (uint32_t)(-1));
        if ((uint64_t)SmallestRtt >= AckDelay) {
            //
            // The ACK delay looks reasonable.
            //
            SmallestRtt -= (uint32_t)AckDelay;
        }
        QuicConnUpdateRtt(Connection, Path, SmallestRtt);
    }

    if (NewLargestAck) {
        //
        // Handle packet loss (and any possible congestion events) before
        // data acknowledgement so that we have an accurate bytes in flight
        // calculation for congestion events.
        //
        QuicLossDetectionDetectAndHandleLostPackets(LossDetection, TimeNow);
    }

    if (NewLargestAck || AckedRetransmittableBytes > 0) {
        if (QuicCongestionControlOnDataAcknowledged(
                &Connection->CongestionControl,
                US_TO_MS(TimeNow),
                LossDetection->LargestAck,
                AckedRetransmittableBytes,
                Connection->Paths[0].SmoothedRtt)) {
            //
            // We were previously blocked and are now unblocked.
            //
            QuicSendQueueFlush(&Connection->Send, REASON_CONGESTION_CONTROL);
        }
    }

    LossDetection->ProbeCount = 0;

    //
    // At least one packet was ACKed. If all packets were ACKed then we'll
    // cancel the timer; otherwise we'll reset the timer.
    //
    QuicLossDetectionUpdateTimer(LossDetection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLossDetectionProcessAckFrame(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ BOOLEAN* InvalidFrame
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    //
    // Called for each received ACK frame. An ACK frame consists of one or more
    // ACK blocks, each of which acknowledges a contiguous range of packets.
    //

    uint64_t AckDelay; // microsec
    QUIC_ACK_ECN_EX Ecn;

    BOOLEAN Result =
        QuicAckFrameDecode(
            FrameType,
            BufferLength,
            Buffer,
            Offset,
            InvalidFrame,
            &Connection->DecodedAckRanges,
            &Ecn,
            &AckDelay);

    if (Result) {

        uint64_t Largest;
        if (!QuicRangeGetMaxSafe(&Connection->DecodedAckRanges, &Largest) ||
            LossDetection->LargestSentPacketNumber < Largest) {

            //
            // The ACK frame should never acknowledge a packet number we haven't
            // sent.
            //
            *InvalidFrame = TRUE;
            Result = FALSE;

        } else {

            // TODO - Use ECN information.
            AckDelay <<= Connection->PeerTransportParams.AckDelayExponent;

            QuicLossDetectionProcessAckBlocks(
                LossDetection,
                Path,
                EncryptLevel,
                AckDelay,
                &Connection->DecodedAckRanges,
                InvalidFrame);
        }
    }

    QuicRangeReset(&Connection->DecodedAckRanges);

    return Result;
}

//
// Schedules a fixed number of (ACK-eliciting) probe packets to be sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionScheduleProbe(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    LossDetection->ProbeCount++;
    QuicTraceLogConnInfo(
        ScheduleProbe,
        Connection,
        "probe round %lu",
        LossDetection->ProbeCount);

    //
    // Below, we will schedule a fixed number packets to be retransmitted. What
    // we'd like to do here send only that number of packets' worth of fresh
    // data we have available. That's complicated. Instead, just decrement
    // for each stream that can send data. Then, if we still have more to send,
    // retransmit the data in the oldest packets. Finally, if we still haven't
    // reached the number desired, queue up a PING frame to ensure at least
    // something is sent.
    //

    //
    // The spec says that 1 probe packet is a MUST but 2 is a MAY. Based on
    // GQUIC's previous experience, we go with 2.
    //
    uint8_t NumPackets = 2;
    QuicCongestionControlSetExemption(&Connection->CongestionControl, NumPackets);
    QuicSendQueueFlush(&Connection->Send, REASON_PROBE);
    Connection->Send.TailLossProbeNeeded = TRUE;

    if (Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
        //
        // Check to see if any streams have fresh data to send out.
        //
        for (QUIC_LIST_ENTRY* Entry = Connection->Send.SendStreams.Flink;
            Entry != &Connection->Send.SendStreams;
            Entry = Entry->Flink) {

            QUIC_STREAM* Stream =
                QUIC_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink);
            if (QuicStreamCanSendNow(Stream, FALSE)) {
                if (--NumPackets == 0) {
                    return;
                }
            }
        }
    }

    //
    // Not enough new stream data exists to fill the probing packets. Schedule
    // retransmits if possible.
    //
    QUIC_SENT_PACKET_METADATA* Packet = LossDetection->SentPackets;
    while (Packet != NULL) {
        if (Packet->Flags.IsAckEliciting) {
            QuicTraceLogVerbose(
                PacketTxProbeRetransmit,
                "[%c][TX][%llu] Probe Retransmit",
                PtkConnPre(Connection),
                Packet->PacketNumber);
            QuicTraceEvent(
                ConnPacketLost,
                "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet),
                QUIC_TRACE_PACKET_LOSS_PROBE);
            if (QuicLossDetectionRetransmitFrames(LossDetection, Packet, FALSE) &&
                --NumPackets == 0) {
                return;
            }
        }
        Packet = Packet->Next;
    }

    //
    // No other (or not enough) data was available to fill the probing packets
    // with. Schedule a PING frame to be sent at the very least to ensure an ACK
    // will be sent in response.
    //
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionProcessTimerOperation(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    QUIC_CONNECTION* Connection = QuicLossDetectionGetConnection(LossDetection);

    const QUIC_SENT_PACKET_METADATA* OldestPacket = // Oldest retransmittable packet.
        QuicLossDetectionOldestOutstandingPacket(LossDetection);

    if (OldestPacket == NULL &&
        (QuicConnIsServer(Connection) ||
         Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT)) {
        //
        // No outstanding packets, and this isn't a client without 1-RTT keys.
        //
        // Most likely the timer fired (and the operation queued) but then the
        // outstanding packets were acknowledged before the timer operation was
        // processed.
        //
        // Note: it's also possible that the timed-out packets were ACKed but
        // some other non-timed-out retransmittable packets are still
        // outstanding. There isn't an easy way to handle that corner case
        // (for instance, if we recalculated the timeout period here and
        // compared it to the oldest outstanding packet's SentTime, we might
        // calculate the timeout differently than it was calculated originally,
        // which could lead to weird bugs). So we just take the hit and assume
        // that at least one of our outstanding packets did time out.
        //
        return;
    }

    uint32_t TimeNow = QuicTimeUs32();

    if (OldestPacket != NULL &&
        QuicTimeDiff32(OldestPacket->SentTime, TimeNow) >=
            Connection->DisconnectTimeoutUs) {
        //
        // OldestPacket has been in the SentPackets list for at least
        // DisconnectTimeoutUs without an ACK for either OldestPacket or for any
        // packets sent more than the reordering threshold after it. Assume the
        // path is dead and close the connection.
        //
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_CONNECTION_TIMEOUT,
            NULL);

    } else {

        //
        // Probe or RACK timeout. If no packets can be inferred lost right now,
        // send probes.
        //
        if (!QuicLossDetectionDetectAndHandleLostPackets(LossDetection, TimeNow)) {
            QuicLossDetectionScheduleProbe(LossDetection);
        }

        QuicLossDetectionUpdateTimer(LossDetection);
    }
}
