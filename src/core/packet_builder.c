/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Packet builder abstracts the logic to build up a chain of UDP datagrams each
    of which may consist of multiple QUIC packets. As necessary, it allocates
    additional datagrams, adds QUIC packet headers, finalizes the QUIC packet
    encryption and sends the packets off.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "packet_builder.c.clog.h"
#endif

#ifdef QUIC_FUZZER

__declspec(noinline)
void
QuicFuzzInjectHook(
    _Inout_ QUIC_PACKET_BUILDER *Builder
    );

#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderSendBatch(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

#if DEBUG
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderValidate(
    _In_ const QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN ShouldHaveData
    )
{
    if (ShouldHaveData) {
        CXPLAT_DBG_ASSERT(Builder->Key != NULL);
        CXPLAT_DBG_ASSERT(Builder->SendData != NULL);
        CXPLAT_DBG_ASSERT(Builder->Datagram != NULL);
        CXPLAT_DBG_ASSERT(Builder->DatagramLength != 0);
        CXPLAT_DBG_ASSERT(Builder->HeaderLength != 0);
        CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount != 0);
    }

    CXPLAT_DBG_ASSERT(Builder->Path != NULL);
    CXPLAT_DBG_ASSERT(Builder->Path->DestCid != NULL);
    CXPLAT_DBG_ASSERT(Builder->BatchCount <= QUIC_MAX_CRYPTO_BATCH_COUNT);

    if (Builder->Key != NULL) {
        CXPLAT_DBG_ASSERT(Builder->Key->PacketKey != NULL);
        CXPLAT_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
    }

    CXPLAT_DBG_ASSERT(Builder->EncryptionOverhead <= 16);
    if (Builder->SendData == NULL) {
        CXPLAT_DBG_ASSERT(Builder->Datagram == NULL);
    }

    if (Builder->Datagram) {
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length != 0);
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length <= UINT16_MAX);
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length >= Builder->MinimumDatagramLength);
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length >= (uint32_t)(Builder->DatagramLength + Builder->EncryptionOverhead));
        CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->PacketStart);
        CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->HeaderLength);
        CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->PacketStart + Builder->HeaderLength);
        if (Builder->PacketType != SEND_PACKET_SHORT_HEADER_TYPE) {
            CXPLAT_DBG_ASSERT(Builder->PayloadLengthOffset != 0);
            if (ShouldHaveData) {
                CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->PacketStart + Builder->PayloadLengthOffset);
            }
        }
    } else {
        CXPLAT_DBG_ASSERT(Builder->DatagramLength == 0);
        CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount == 0);
    }
}
#else
#define QuicPacketBuilderValidate(Builder, ShouldHaveData) // no-op
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderInitialize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
    Builder->Connection = Connection;
    Builder->Path = Path;
    Builder->PacketBatchSent = FALSE;
    Builder->PacketBatchRetransmittable = FALSE;
    Builder->Metadata = &Builder->MetadataStorage.Metadata;
    Builder->EncryptionOverhead = CXPLAT_ENCRYPTION_OVERHEAD;
    Builder->TotalDatagramsLength = 0;

    if (Connection->SourceCids.Next == NULL) {
        QuicTraceLogConnWarning(
            NoSrcCidAvailable,
            Connection,
            "No src CID to send with");
        return FALSE;
    }

    Builder->SourceCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->SourceCids.Next,
            QUIC_CID_HASH_ENTRY,
            Link);

    uint64_t TimeNow = CxPlatTimeUs64();
    uint64_t TimeSinceLastSend;
    if (Connection->Send.LastFlushTimeValid) {
        TimeSinceLastSend =
            CxPlatTimeDiff64(Connection->Send.LastFlushTime, TimeNow);
    } else {
        TimeSinceLastSend = 0;
    }
    Builder->SendAllowance =
        QuicCongestionControlGetSendAllowance(
            &Connection->CongestionControl,
            TimeSinceLastSend,
            Connection->Send.LastFlushTimeValid);
    if (Builder->SendAllowance > Path->Allowance) {
        Builder->SendAllowance = Path->Allowance;
    }
    Connection->Send.LastFlushTime = TimeNow;
    Connection->Send.LastFlushTimeValid = TRUE;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderCleanup(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(Builder->SendData == NULL);

    if (Builder->PacketBatchSent && Builder->PacketBatchRetransmittable) {
        QuicLossDetectionUpdateTimer(&Builder->Connection->LossDetection, FALSE);
    }

    QuicSentPacketMetadataReleaseFrames(Builder->Metadata);

    CxPlatSecureZeroMemory(Builder->HpMask, sizeof(Builder->HpMask));
}

//
// This function makes sure the current send buffer and other related data is
// prepared for writing the requested data. If there was already a QUIC packet
// in the process of being built, it will try to reuse it if possible. If not,
// it will finalize the current one and start a new one.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepare(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_PACKET_KEY_TYPE NewPacketKeyType,
    _In_ BOOLEAN IsTailLossProbe,
    _In_ BOOLEAN IsPathMtuDiscovery
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;
    if (Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType] == NULL) {
        //
        // A NULL key here usually means the connection had a fatal error in
        // such a way that resulted in the key not getting created. The
        // connection is most likely trying to send a connection close frame,
        // but without the key, nothing can be done. Just silently kill the
        // connection.
        //
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "NULL key in builder prepare");
        QuicConnSilentlyAbort(Connection);
        return FALSE;
    }

    BOOLEAN Result = FALSE;
    uint8_t NewPacketType =
        Connection->Stats.QuicVersion == QUIC_VERSION_2 ?
            QuicKeyTypeToPacketTypeV2(NewPacketKeyType) :
            QuicKeyTypeToPacketTypeV1(NewPacketKeyType);
    uint16_t DatagramSize = Builder->Path->Mtu;
    if ((uint32_t)DatagramSize > Builder->Path->Allowance) {
        CXPLAT_DBG_ASSERT(!IsPathMtuDiscovery); // PMTUD always happens after source addr validation.
        DatagramSize = (uint16_t)Builder->Path->Allowance;
    }
    CXPLAT_DBG_ASSERT(!IsPathMtuDiscovery || !IsTailLossProbe); // Never both.
    QuicPacketBuilderValidate(Builder, FALSE);

    //
    // Next, make sure the current QUIC packet matches the new packet type. If
    // the current one doesn't match, finalize it and then start a new one.
    //

    uint32_t Proc = CxPlatProcCurrentNumber();
    uint64_t ProcShifted = ((uint64_t)Proc + 1) << 40;

    BOOLEAN NewQuicPacket = FALSE;
    if (Builder->PacketType != NewPacketType || IsPathMtuDiscovery ||
        (Builder->Datagram != NULL && (Builder->Datagram->Length - Builder->DatagramLength) < QUIC_MIN_PACKET_SPARE_SPACE)) {
        //
        // The current data cannot go in the current QUIC packet. Finalize the
        // current QUIC packet up so we can create another.
        //
        if (Builder->SendData != NULL) {
            BOOLEAN FlushDatagrams = IsPathMtuDiscovery;
            if (Builder->PacketType != NewPacketType &&
                Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
                FlushDatagrams = TRUE;
            }
            QuicPacketBuilderFinalize(Builder, FlushDatagrams);
        }
        if (Builder->SendData == NULL &&
            Builder->TotalCountDatagrams >= QUIC_MAX_DATAGRAMS_PER_SEND) {
            goto Error;
        }
        NewQuicPacket = TRUE;

    } else if (Builder->Datagram == NULL) {
        NewQuicPacket = TRUE;
    }

    if (Builder->Datagram == NULL) {

        //
        // Allocate and initialize a new send buffer (UDP packet/payload).
        //
        BOOLEAN SendDataAllocated = FALSE;
        if (Builder->SendData == NULL) {
            Builder->BatchId =
                ProcShifted | InterlockedIncrement64((int64_t*)&MsQuicLib.PerProc[Proc].SendBatchId);
            Builder->SendData =
                CxPlatSendDataAlloc(
                    Builder->Path->Binding->Socket,
                    CXPLAT_ECN_NON_ECT,
                    IsPathMtuDiscovery ?
                        0 :
                        MaxUdpPayloadSizeForFamily(
                            QuicAddrGetFamily(&Builder->Path->Route.RemoteAddress),
                            DatagramSize),
                    &Builder->Path->Route);
            if (Builder->SendData == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "packet send context",
                    0);
                goto Error;
            }
            SendDataAllocated = TRUE;
        }

        uint16_t NewDatagramLength =
            MaxUdpPayloadSizeForFamily(
                QuicAddrGetFamily(&Builder->Path->Route.RemoteAddress),
                IsPathMtuDiscovery ? Builder->Path->MtuDiscovery.ProbeSize : DatagramSize);
        if ((Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE) &&
            NewDatagramLength > Connection->PeerTransportParams.MaxUdpPayloadSize) {
            NewDatagramLength = (uint16_t)Connection->PeerTransportParams.MaxUdpPayloadSize;
        }

        Builder->Datagram =
            CxPlatSendDataAllocBuffer(
                Builder->SendData,
                NewDatagramLength);
        if (Builder->Datagram == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "packet datagram",
                NewDatagramLength);
            if (SendDataAllocated) {
                CxPlatSendDataFree(Builder->SendData);
                Builder->SendData = NULL;
            }
            goto Error;
        }

        Builder->DatagramLength = 0;
        Builder->MinimumDatagramLength = 0;

        if (IsTailLossProbe && QuicConnIsClient(Connection)) {
            if (NewPacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
                //
                // Short header (1-RTT) packets need to be padded enough to
                // elicit stateless resets from the server.
                //
                Builder->MinimumDatagramLength =
                    QUIC_RECOMMENDED_STATELESS_RESET_PACKET_LENGTH +
                    8 /* a little fudge factor */;
            } else {
                //
                // Initial/Handshake packets need to be padded to unblock a
                // server (possibly) blocked on source address validation.
                //
                Builder->MinimumDatagramLength = NewDatagramLength;
            }

        } else if ((Connection->Stats.QuicVersion == QUIC_VERSION_2 && NewPacketType == QUIC_INITIAL_V2) ||
            (Connection->Stats.QuicVersion != QUIC_VERSION_2 && NewPacketType == QUIC_INITIAL_V1)) {

            //
            // Make sure to pad Initial packets.
            //
            Builder->MinimumDatagramLength =
                MaxUdpPayloadSizeForFamily(
                    QuicAddrGetFamily(&Builder->Path->Route.RemoteAddress),
                    Builder->Path->Mtu);

            if ((uint32_t)Builder->MinimumDatagramLength > Builder->Datagram->Length) {
                //
                // On server, if we're limited by amplification protection, just
                // pad up to that limit instead.
                //
                Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
            }

        } else if (IsPathMtuDiscovery) {
            Builder->MinimumDatagramLength = NewDatagramLength;
        }
    }

    if (NewQuicPacket) {

        //
        // Initialize the new QUIC packet state.
        //

        Builder->PacketType = NewPacketType;
        Builder->EncryptLevel =
            Connection->Stats.QuicVersion == QUIC_VERSION_2 ?
                QuicPacketTypeToEncryptLevelV2(NewPacketType) :
                QuicPacketTypeToEncryptLevelV1(NewPacketType);
        Builder->Key = Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType];
        CXPLAT_DBG_ASSERT(Builder->Key != NULL);
        CXPLAT_DBG_ASSERT(Builder->Key->PacketKey != NULL);
        CXPLAT_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
        if (NewPacketKeyType == QUIC_PACKET_KEY_1_RTT &&
            Connection->State.Disable1RttEncrytion) {
            Builder->EncryptionOverhead = 0;
        }

        Builder->Metadata->PacketId =
            ProcShifted | InterlockedIncrement64((int64_t*)&MsQuicLib.PerProc[Proc].SendPacketId);
        QuicTraceEvent(
            PacketCreated,
            "[pack][%llu] Created in batch %llu",
            Builder->Metadata->PacketId,
            Builder->BatchId);

        Builder->Metadata->FrameCount = 0;
        Builder->Metadata->PacketNumber = Connection->Send.NextPacketNumber++;
        Builder->Metadata->Flags.KeyType = NewPacketKeyType;
        Builder->Metadata->Flags.IsAckEliciting = FALSE;
        Builder->Metadata->Flags.IsMtuProbe = IsPathMtuDiscovery;
        Builder->Metadata->Flags.SuspectedLost = FALSE;
#if DEBUG
        Builder->Metadata->Flags.Freed = FALSE;
#endif

        Builder->PacketStart = Builder->DatagramLength;
        Builder->HeaderLength = 0;

        uint8_t* Header =
            Builder->Datagram->Buffer + Builder->DatagramLength;
        uint16_t BufferSpaceAvailable =
            (uint16_t)Builder->Datagram->Length - Builder->DatagramLength;

        if (NewPacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
            QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[Builder->EncryptLevel];

            Builder->PacketNumberLength = 4; // TODO - Determine correct length based on BDP.

            switch (Connection->Stats.QuicVersion) {
            case QUIC_VERSION_1:
            case QUIC_VERSION_DRAFT_29:
            case QUIC_VERSION_MS_1:
            case QUIC_VERSION_2:
                Builder->HeaderLength =
                    QuicPacketEncodeShortHeaderV1(
                        &Builder->Path->DestCid->CID,
                        Builder->Metadata->PacketNumber,
                        Builder->PacketNumberLength,
                        Builder->Path->SpinBit,
                        PacketSpace->CurrentKeyPhase,
                        BufferSpaceAvailable,
                        Header);
                Builder->Metadata->Flags.KeyPhase = PacketSpace->CurrentKeyPhase;
                break;
            default:
                CXPLAT_FRE_ASSERT(FALSE);
                Builder->HeaderLength = 0; // For build warning.
                break;
            }

        } else { // Long Header

            switch (Connection->Stats.QuicVersion) {
            case QUIC_VERSION_1:
            case QUIC_VERSION_DRAFT_29:
            case QUIC_VERSION_MS_1:
            case QUIC_VERSION_2:
            default:
                Builder->HeaderLength =
                    QuicPacketEncodeLongHeaderV1(
                        Connection->Stats.QuicVersion,
                        NewPacketType,
                        &Builder->Path->DestCid->CID,
                        &Builder->SourceCid->CID,
                        Connection->Send.InitialTokenLength,
                        Connection->Send.InitialToken,
                        (uint32_t)Builder->Metadata->PacketNumber,
                        BufferSpaceAvailable,
                        Header,
                        &Builder->PayloadLengthOffset,
                        &Builder->PacketNumberLength);
                break;
            }
        }

        Builder->DatagramLength += Builder->HeaderLength;
    }

    CXPLAT_DBG_ASSERT(Builder->PacketType == NewPacketType);
    CXPLAT_DBG_ASSERT(Builder->Key == Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType]);
    CXPLAT_DBG_ASSERT(Builder->BatchCount == 0 || Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE);

    Result = TRUE;

Error:

    QuicPacketBuilderValidate(Builder, FALSE);

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderGetPacketTypeAndKeyForControlFrames(
    _In_ const QUIC_PACKET_BUILDER* Builder,
    _In_ uint32_t SendFlags,
    _Out_ QUIC_PACKET_KEY_TYPE* PacketKeyType
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;

    CXPLAT_DBG_ASSERT(SendFlags != 0);
    QuicSendValidate(&Builder->Connection->Send);

    for (QUIC_PACKET_KEY_TYPE KeyType = 0;
         KeyType <= Connection->Crypto.TlsState.WriteKey;
         ++KeyType) {

        if (KeyType == QUIC_PACKET_KEY_0_RTT) {
            continue; // Crypto is never written with 0-RTT key.
        }

        QUIC_PACKET_KEY* PacketsKey =
            Connection->Crypto.TlsState.WriteKeys[KeyType];
        if (PacketsKey == NULL) {
            continue; // Key has been discarded.
        }

        QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(KeyType);
        if (EncryptLevel == QUIC_ENCRYPT_LEVEL_1_RTT) {
            //
            // Always allowed to send with 1-RTT.
            //
            *PacketKeyType = QUIC_PACKET_KEY_1_RTT;
            return TRUE;
        }

        QUIC_PACKET_SPACE* Packets = Connection->Packets[EncryptLevel];
        CXPLAT_DBG_ASSERT(Packets != NULL);

        if (SendFlags & QUIC_CONN_SEND_FLAG_ACK &&
            Packets->AckTracker.AckElicitingPacketsToAcknowledge) {
            //
            // ACK frames have the highest send priority; but they only
            // determine a packet type if they can be sent as ACK-only.
            //
            *PacketKeyType = KeyType;
            return TRUE;
        }

        if (SendFlags & QUIC_CONN_SEND_FLAG_CRYPTO &&
            QuicCryptoHasPendingCryptoFrame(&Connection->Crypto) &&
            EncryptLevel == QuicCryptoGetNextEncryptLevel(&Connection->Crypto)) {
            //
            // Crypto handshake data is ready to be sent.
            //
            *PacketKeyType = KeyType;
            return TRUE;
        }
    }

    if (SendFlags & (QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | QUIC_CONN_SEND_FLAG_PING)) {
        //
        // CLOSE or PING is ready to be sent. This is always sent with the
        // current write key.
        //
        // TODO - This logic isn't correct. The peer might not be able to read
        // this key, so the CLOSE frame should be sent at the current and
        // previous encryption level if the handshake hasn't been confirmed.
        //
        if (Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_0_RTT) {
            *PacketKeyType = QUIC_PACKET_KEY_INITIAL;
        } else {
            *PacketKeyType = Connection->Crypto.TlsState.WriteKey;
        }
        return TRUE;
    }

    if (Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL) {
        *PacketKeyType = QUIC_PACKET_KEY_1_RTT;
        return TRUE;
    }

    QuicTraceLogConnWarning(
        GetPacketTypeFailure,
        Builder->Connection,
        "Failed to get packet type for control frames, 0x%x",
        SendFlags);
    CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled()); // This shouldn't have been called then!

    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForControlFrames(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN IsTailLossProbe,
    _In_ uint32_t SendFlags
    )
{
    CXPLAT_DBG_ASSERT(!(SendFlags & QUIC_CONN_SEND_FLAG_DPLPMTUD));
    QUIC_PACKET_KEY_TYPE PacketKeyType;
    return
        QuicPacketBuilderGetPacketTypeAndKeyForControlFrames(
            Builder,
            SendFlags,
            &PacketKeyType) &&
        QuicPacketBuilderPrepare(
            Builder,
            PacketKeyType,
            IsTailLossProbe,
            FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForPathMtuDiscovery(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    return
        QuicPacketBuilderPrepare(
            Builder,
            QUIC_PACKET_KEY_1_RTT,
            FALSE,
            TRUE);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForStreamFrames(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN IsTailLossProbe
    )
{
    QUIC_PACKET_KEY_TYPE PacketKeyType;

    if (Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_0_RTT] != NULL &&
        Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        //
        // Application stream data can only be sent with the 0-RTT key if the
        // 1-RTT key is unavailable.
        //
        PacketKeyType = QUIC_PACKET_KEY_0_RTT;

    } else {
        CXPLAT_DBG_ASSERT(Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
        PacketKeyType = QUIC_PACKET_KEY_1_RTT;
    }

    return QuicPacketBuilderPrepare(Builder, PacketKeyType, IsTailLossProbe, FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderFinalizeHeaderProtection(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(Builder->Key != NULL);

    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
        CxPlatHpComputeMask(
            Builder->Key->HeaderKey,
            Builder->BatchCount,
            Builder->CipherBatch,
            Builder->HpMask))) {
        CXPLAT_TEL_ASSERT(FALSE);
        QuicConnFatalError(Builder->Connection, Status, "HP failure");
        return;
    }

    for (uint8_t i = 0; i < Builder->BatchCount; ++i) {
        uint16_t Offset = i * CXPLAT_HP_SAMPLE_LENGTH;
        uint8_t* Header = Builder->HeaderBatch[i];
        Header[0] ^= (Builder->HpMask[Offset] & 0x1f); // Bottom 5 bits for SH
        Header += 1 + Builder->Path->DestCid->CID.Length;
        for (uint8_t j = 0; j < Builder->PacketNumberLength; ++j) {
            Header[j] ^= Builder->HpMask[Offset + 1 + j];
        }
    }

    Builder->BatchCount = 0;
}

//
// This function completes the current QUIC packet. It updates the header if
// necessary and encrypts the payload. If there isn't enough space for another
// QUIC packet, it also completes the send buffer (i.e. UDP payload) and sets
// the current send buffer pointer to NULL. If that send buffer was the last
// in the current send batch, then the send context is also completed and sent
// off.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPacketBuilderFinalize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN FlushBatchedDatagrams
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;
    BOOLEAN FinalQuicPacket = FALSE;
    BOOLEAN CanKeepSending = TRUE;

    QuicPacketBuilderValidate(Builder, FALSE);

    if (Builder->Datagram == NULL || Builder->Metadata->FrameCount == 0) {
        //
        // Nothing got framed into this packet. Undo the header of this
        // packet.
        //
        if (Builder->Datagram != NULL) {
            --Connection->Send.NextPacketNumber;
            Builder->DatagramLength -= Builder->HeaderLength;
            Builder->HeaderLength = 0;
            CanKeepSending = FALSE;

            if (Builder->DatagramLength == 0) {
                CxPlatSendDataFreeBuffer(Builder->SendData, Builder->Datagram);
                Builder->Datagram = NULL;
            }
        }
        if (Builder->Path->Allowance != UINT32_MAX) {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
        }
        FinalQuicPacket = FlushBatchedDatagrams && (Builder->TotalCountDatagrams != 0);
        goto Exit;
    }

    QuicPacketBuilderValidate(Builder, TRUE);

    //
    // Calculate some of the packet buffer parameters (mostly used for encryption).
    //
    uint8_t* Header =
        Builder->Datagram->Buffer + Builder->PacketStart;
    uint16_t PayloadLength =
        Builder->DatagramLength - (Builder->PacketStart + Builder->HeaderLength);
    uint16_t ExpectedFinalDatagramLength =
        Builder->DatagramLength + Builder->EncryptionOverhead;

    if (FlushBatchedDatagrams ||
        Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE ||
        (uint16_t)Builder->Datagram->Length - ExpectedFinalDatagramLength < QUIC_MIN_PACKET_SPARE_SPACE) {

        FinalQuicPacket = TRUE;

        if (!FlushBatchedDatagrams && CxPlatDataPathIsPaddingPreferred(MsQuicLib.Datapath)) {
            //
            // When buffering multiple datagrams in a single contiguous buffer
            // (at the datapath layer), all but the last datagram needs to be
            // fully padded.
            //
            Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
        }
    }

    uint16_t PaddingLength;
    if (FinalQuicPacket && ExpectedFinalDatagramLength < Builder->MinimumDatagramLength) {
        PaddingLength = Builder->MinimumDatagramLength - ExpectedFinalDatagramLength;
    } else if (Builder->PacketNumberLength + PayloadLength < sizeof(uint32_t)) {
        //
        // For packet protection to work, there must always be at least 4 bytes
        // of payload and/or packet number.
        //
        PaddingLength = sizeof(uint32_t) - Builder->PacketNumberLength - PayloadLength;
    } else {
        PaddingLength = 0;
    }

    if (PaddingLength != 0) {
        CxPlatZeroMemory(
            Builder->Datagram->Buffer + Builder->DatagramLength,
            PaddingLength);
        PayloadLength += PaddingLength;
        Builder->DatagramLength += PaddingLength;
    }

    if (Builder->PacketType != SEND_PACKET_SHORT_HEADER_TYPE) {
        switch (Connection->Stats.QuicVersion) {
        case QUIC_VERSION_1:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1:
        case QUIC_VERSION_2:
        default:
            QuicVarIntEncode2Bytes(
                (uint16_t)Builder->PacketNumberLength +
                    PayloadLength +
                    Builder->EncryptionOverhead,
                Header + Builder->PayloadLengthOffset);
            break;
        }
    }

#ifdef QUIC_FUZZER
    QuicFuzzInjectHook(Builder);
#endif

    if (QuicTraceLogVerboseEnabled()) {
        QuicPacketLogHeader(
            Connection,
            FALSE,
            Builder->Path->DestCid->CID.Length,
            Builder->Metadata->PacketNumber,
            Builder->HeaderLength + PayloadLength,
            Header,
            Connection->Stats.QuicVersion);
        QuicFrameLogAll(
            Connection,
            FALSE,
            Builder->Metadata->PacketNumber,
            Builder->HeaderLength + PayloadLength,
            Header,
            Builder->HeaderLength);
    }

    if (Builder->EncryptionOverhead != 0) {

        //
        // Encrypt the data.
        //

        QuicTraceEvent(
            PacketEncrypt,
            "[pack][%llu] Encrypting",
            Builder->Metadata->PacketId);

        PayloadLength += Builder->EncryptionOverhead;
        Builder->DatagramLength += Builder->EncryptionOverhead;

        uint8_t* Payload = Header + Builder->HeaderLength;

        uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(Builder->Key->Iv, (uint8_t*) &Builder->Metadata->PacketNumber, Iv);

        QUIC_STATUS Status;
        if (QUIC_FAILED(
            Status =
            CxPlatEncrypt(
                Builder->Key->PacketKey,
                Iv,
                Builder->HeaderLength,
                Header,
                PayloadLength,
                Payload))) {
            QuicConnFatalError(Connection, Status, "Encryption failure");
            goto Exit;
        }

        if (Connection->State.HeaderProtectionEnabled) {

            uint8_t* PnStart = Payload - Builder->PacketNumberLength;

            if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
                CXPLAT_DBG_ASSERT(Builder->BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT);

                //
                // Batch the header protection for short header packets.
                //

                CxPlatCopyMemory(
                    Builder->CipherBatch + Builder->BatchCount * CXPLAT_HP_SAMPLE_LENGTH,
                    PnStart + 4,
                    CXPLAT_HP_SAMPLE_LENGTH);
                Builder->HeaderBatch[Builder->BatchCount] = Header;

                if (++Builder->BatchCount == QUIC_MAX_CRYPTO_BATCH_COUNT) {
                    QuicPacketBuilderFinalizeHeaderProtection(Builder);
                }

            } else {
                CXPLAT_DBG_ASSERT(Builder->BatchCount == 0);

                //
                // Individually do header protection for long header packets as
                // they generally use different keys.
                //

                if (QUIC_FAILED(
                    Status =
                    CxPlatHpComputeMask(
                        Builder->Key->HeaderKey,
                        1,
                        PnStart + 4,
                        Builder->HpMask))) {
                    CXPLAT_TEL_ASSERT(FALSE);
                    QuicConnFatalError(Connection, Status, "HP failure");
                    goto Exit;
                }

                Header[0] ^= (Builder->HpMask[0] & 0x0f); // Bottom 4 bits for LH
                for (uint8_t i = 0; i < Builder->PacketNumberLength; ++i) {
                    PnStart[i] ^= Builder->HpMask[1 + i];
                }
            }
        }

        //
        // Increment the key phase sent bytes count.
        //
        QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[Builder->EncryptLevel];
        PacketSpace->CurrentKeyPhaseBytesSent += (PayloadLength - Builder->EncryptionOverhead);

        //
        // Check if the next packet sent will exceed the limit of bytes per
        // key phase, and update the keys. Only for 1-RTT keys.
        //
        if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE &&
            PacketSpace->CurrentKeyPhaseBytesSent + CXPLAT_MAX_MTU >=
                Connection->Settings.MaxBytesPerKey &&
            !PacketSpace->AwaitingKeyPhaseConfirmation &&
            Connection->State.HandshakeConfirmed) {

            Status = QuicCryptoGenerateNewKeys(Connection);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Send-triggered key update");
                QuicConnFatalError(Connection, Status, "Send-triggered key update");
                goto Exit;
            }

            QuicCryptoUpdateKeyPhase(Connection, TRUE);

            //
            // Update the packet key in use by the send builder.
            //
            Builder->Key = Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT];
            CXPLAT_DBG_ASSERT(Builder->Key != NULL);
            CXPLAT_DBG_ASSERT(Builder->Key->PacketKey != NULL);
            CXPLAT_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
        }
    }

    //
    // Track the sent packet.
    //
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount != 0);

    Builder->Metadata->SentTime = CxPlatTimeUs32();
    Builder->Metadata->PacketLength =
        Builder->HeaderLength + PayloadLength;
    QuicTraceEvent(
        PacketFinalize,
        "[pack][%llu] Finalizing",
        Builder->Metadata->PacketId);

    QuicTraceEvent(
        ConnPacketSent,
        "[conn][%p][TX][%llu] %hhu (%hu bytes)",
        Connection,
        Builder->Metadata->PacketNumber,
        QuicPacketTraceType(Builder->Metadata),
        Builder->Metadata->PacketLength);
    QuicLossDetectionOnPacketSent(
        &Connection->LossDetection,
        Builder->Path,
        Builder->Metadata);

    Builder->Metadata->FrameCount = 0;

    if (Builder->Metadata->Flags.IsAckEliciting) {
        Builder->PacketBatchRetransmittable = TRUE;

        //
        // Remove the bytes from the allowance.
        //
        if ((uint32_t)Builder->Metadata->PacketLength > Builder->SendAllowance) {
            Builder->SendAllowance = 0;
        } else {
            Builder->SendAllowance -= Builder->Metadata->PacketLength;
        }
    }

Exit:

    //
    // Send the packet out if necessary.
    //

    if (FinalQuicPacket) {
        if (Builder->Datagram != NULL) {
            Builder->Datagram->Length = Builder->DatagramLength;
            Builder->Datagram = NULL;
            ++Builder->TotalCountDatagrams;
            Builder->TotalDatagramsLength += Builder->DatagramLength;
            Builder->DatagramLength = 0;
        }

        if (FlushBatchedDatagrams || CxPlatSendDataIsFull(Builder->SendData)) {
            if (Builder->BatchCount != 0) {
                QuicPacketBuilderFinalizeHeaderProtection(Builder);
            }
            CXPLAT_DBG_ASSERT(Builder->TotalCountDatagrams > 0);
            QuicPacketBuilderSendBatch(Builder);
            CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount == 0);
            QuicTraceEvent(
                PacketBatchSent,
                "[pack][%llu] Batch sent",
                Builder->BatchId);
        }

        if ((Connection->Stats.QuicVersion != QUIC_VERSION_2 && Builder->PacketType == QUIC_RETRY_V1) ||
            (Connection->Stats.QuicVersion == QUIC_VERSION_2 && Builder->PacketType == QUIC_RETRY_V2)) {
            CXPLAT_DBG_ASSERT(Builder->Metadata->PacketNumber == 0);
            QuicConnCloseLocally(
                Connection,
                QUIC_CLOSE_SILENT,
                QUIC_ERROR_NO_ERROR,
                NULL);
        }

    } else if (FlushBatchedDatagrams) {
        if (Builder->Datagram != NULL) {
            CxPlatSendDataFreeBuffer(Builder->SendData, Builder->Datagram);
            Builder->Datagram = NULL;
            Builder->DatagramLength = 0;
        }
        if (Builder->SendData != NULL) {
            CxPlatSendDataFree(Builder->SendData);
            Builder->SendData = NULL;
        }
    }

    QuicPacketBuilderValidate(Builder, FALSE);

    CXPLAT_DBG_ASSERT(!FlushBatchedDatagrams || Builder->SendData == NULL);

    return CanKeepSending;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderSendBatch(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    QuicTraceLogConnVerbose(
        PacketBuilderSendBatch,
        Builder->Connection,
        "Sending batch. %hu datagrams",
        (uint16_t)Builder->TotalCountDatagrams);

    QuicBindingSend(
        Builder->Path->Binding,
        &Builder->Path->Route,
        Builder->SendData,
        Builder->TotalDatagramsLength,
        Builder->TotalCountDatagrams,
        Builder->Connection->Worker->IdealProcessor);

    Builder->PacketBatchSent = TRUE;
    Builder->SendData = NULL;
    Builder->TotalDatagramsLength = 0;
    Builder->Metadata->FrameCount = 0;
}
