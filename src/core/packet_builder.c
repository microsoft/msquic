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

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderInitialize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    QUIC_DBG_ASSERT(Path->DestCid != NULL);
    Builder->Connection = Connection;
    Builder->Path = Path;
    Builder->PacketBatchSent = FALSE;
    Builder->PacketBatchRetransmittable = FALSE;
    Builder->Metadata = &Builder->MetadataStorage.Metadata;
    Builder->EncryptionOverhead =
        Connection->State.EncryptionEnabled ?
            QUIC_ENCRYPTION_OVERHEAD : 0;

    if (Connection->SourceCids.Next == NULL) {
        QuicTraceLogConnWarning(
            NoSrcCidAvailable,
            Connection,
            "No src CID to send with");
        return FALSE;
    }

    Builder->SourceCid =
        QUIC_CONTAINING_RECORD(
            Connection->SourceCids.Next,
            QUIC_CID_HASH_ENTRY,
            Link);

    uint64_t TimeNow = QuicTimeUs64();
    uint64_t TimeSinceLastSend;
    if (Connection->Send.LastFlushTimeValid) {
        TimeSinceLastSend =
            QuicTimeDiff64(Connection->Send.LastFlushTime, TimeNow);
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
    QUIC_DBG_ASSERT(Builder->SendContext == NULL);

    if (Builder->PacketBatchSent && Builder->PacketBatchRetransmittable) {
        QuicLossDetectionUpdateTimer(&Builder->Connection->LossDetection);
    }

    QuicSentPacketMetadataReleaseFrames(Builder->Metadata);

    QuicSecureZeroMemory(Builder->HpMask, sizeof(Builder->HpMask));
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
    uint8_t NewPacketType = QuicKeyTypeToPacketType(NewPacketKeyType);
    uint16_t DatagramSize = Builder->Path->Mtu;
    if ((uint32_t)DatagramSize > Builder->Path->Allowance) {
        QUIC_DBG_ASSERT(!IsPathMtuDiscovery); // PMTUD always happens after source addr validation.
        DatagramSize = (uint16_t)Builder->Path->Allowance;
    }
    QUIC_DBG_ASSERT(!IsPathMtuDiscovery || !IsTailLossProbe); // Never both.


    //
    // Next, make sure the current QUIC packet matches the new packet type. If
    // the current one doesn't match, finalize it and then start a new one.
    //

    BOOLEAN NewQuicPacket = FALSE;
    if (Builder->PacketType != NewPacketType || IsPathMtuDiscovery) {
        //
        // The current data cannot go in the current QUIC packet. Finalize the
        // current QUIC packet up so we can create another.
        //
        if (Builder->SendContext != NULL) {
            QuicPacketBuilderFinalize(Builder, IsPathMtuDiscovery);
        }
        if (Builder->SendContext == NULL &&
            Builder->TotalCountDatagrams >= QUIC_MAX_DATAGRAMS_PER_SEND) {
            goto Error;
        }
        NewQuicPacket = TRUE;

    } else if (Builder->Datagram == NULL) {
        NewQuicPacket = TRUE;

    } else {
        QUIC_DBG_ASSERT(Builder->Datagram->Length - Builder->DatagramLength >= QUIC_MIN_PACKET_SPARE_SPACE);
    }

    if (Builder->Datagram == NULL) {

        //
        // Allocate and initialize a new send buffer (UDP packet/payload).
        //

        if (Builder->SendContext == NULL) {
            Builder->SendContext =
                QuicDataPathBindingAllocSendContext(
                    Builder->Path->Binding->DatapathBinding,
                    IsPathMtuDiscovery ?
                        0 :
                        MaxUdpPayloadSizeForFamily(
                            QuicAddrGetFamily(&Builder->Path->RemoteAddress),
                            DatagramSize));
            if (Builder->SendContext == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "packet send context",
                    0);
                goto Error;
            }
        }

        uint16_t NewDatagramLength =
            MaxUdpPayloadSizeForFamily(
                QuicAddrGetFamily(&Builder->Path->RemoteAddress),
                IsPathMtuDiscovery ? QUIC_MAX_MTU : DatagramSize);
        if ((Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE) &&
            NewDatagramLength > Connection->PeerTransportParams.MaxUdpPayloadSize) {
            NewDatagramLength = (uint16_t)Connection->PeerTransportParams.MaxUdpPayloadSize;
        }

        Builder->Datagram =
            QuicDataPathBindingAllocSendDatagram(
                Builder->SendContext,
                NewDatagramLength);
        if (Builder->Datagram == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "packet datagram",
                NewDatagramLength);
            goto Error;
        }

        Builder->DatagramLength = 0;
        Builder->MinimumDatagramLength = 0;

        if (IsTailLossProbe && !QuicConnIsServer(Connection)) {
            if (Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
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

        } else if (NewPacketType == QUIC_INITIAL &&
            !QuicConnIsServer(Connection)) {

            //
            // Make sure to pad the packet if client Initial packets.
            //
            Builder->MinimumDatagramLength =
                MaxUdpPayloadSizeForFamily(
                    QuicAddrGetFamily(&Builder->Path->RemoteAddress),
                    QUIC_INITIAL_PACKET_LENGTH);

        } else if (IsPathMtuDiscovery) {
            Builder->MinimumDatagramLength = NewDatagramLength;
        }

        QuicTraceLogConnVerbose(
            PacketBuilderNewDatagram,
            Connection,
            "New UDP datagram. Space: %u",
            Builder->Datagram->Length);
    }

    if (NewQuicPacket) {

        //
        // Initialize the new QUIC packet state.
        //

        Builder->PacketType = NewPacketType;
        Builder->EncryptLevel = QuicPacketTypeToEncryptLevel(NewPacketType);
        Builder->Key = Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType];
        QUIC_DBG_ASSERT(Builder->Key != NULL);
        QUIC_DBG_ASSERT(Builder->Key->PacketKey != NULL);
        QUIC_DBG_ASSERT(Builder->Key->HeaderKey != NULL);

        Builder->Metadata->FrameCount = 0;
        Builder->Metadata->PacketNumber = Connection->Send.NextPacketNumber++;
        Builder->Metadata->Flags.KeyType = NewPacketKeyType;
        Builder->Metadata->Flags.IsAckEliciting = FALSE;
        Builder->Metadata->Flags.IsPMTUD = IsPathMtuDiscovery;
        Builder->Metadata->Flags.SuspectedLost = FALSE;
#if DEBUG
        Builder->Metadata->Flags.Freed = FALSE;
#endif

        Builder->PacketStart = Builder->DatagramLength;
        Builder->HeaderLength = 0;

        uint8_t* Header =
            (uint8_t*)Builder->Datagram->Buffer + Builder->DatagramLength;
        uint16_t BufferSpaceAvailable =
            (uint16_t)Builder->Datagram->Length - Builder->DatagramLength;

        if (NewPacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
            QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[Builder->EncryptLevel];

            Builder->PacketNumberLength = 4; // TODO - Determine correct length based on BDP.

            switch (Connection->Stats.QuicVersion) {
            case QUIC_VERSION_DRAFT_27:
            case QUIC_VERSION_DRAFT_28:
            case QUIC_VERSION_DRAFT_29:
            case QUIC_VERSION_MS_1:
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
                QUIC_FRE_ASSERT(FALSE);
                Builder->HeaderLength = 0; // For build warning.
                break;
            }

        } else { // Long Header

            switch (Connection->Stats.QuicVersion) {
            case QUIC_VERSION_DRAFT_27:
            case QUIC_VERSION_DRAFT_28:
            case QUIC_VERSION_DRAFT_29:
            case QUIC_VERSION_MS_1:
            default:
                Builder->HeaderLength =
                    QuicPacketEncodeLongHeaderV1(
                        Connection->Stats.QuicVersion,
                        (QUIC_LONG_HEADER_TYPE_V1)NewPacketType,
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

        QuicTraceLogConnVerbose(
            PacketBuilderNewPacket,
            Connection,
            "New QUIC packet. Space: %hu. Type: %hx",
            BufferSpaceAvailable,
            NewPacketType);
    }

    QUIC_DBG_ASSERT(Builder->PacketType == NewPacketType);
    QUIC_DBG_ASSERT(Builder->Key == Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType]);

    Result = TRUE;

Error:

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

    QUIC_DBG_ASSERT(SendFlags != 0);
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
        QUIC_DBG_ASSERT(Packets != NULL);

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
    QUIC_DBG_ASSERT(FALSE); // This shouldn't have been called then!

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
    QUIC_DBG_ASSERT(!(SendFlags & QUIC_CONN_SEND_FLAG_PMTUD));
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
        QUIC_DBG_ASSERT(Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
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
    QUIC_DBG_ASSERT(Builder->Key != NULL);

    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
        QuicHpComputeMask(
            Builder->Key->HeaderKey,
            Builder->BatchCount,
            Builder->CipherBatch,
            Builder->HpMask))) {
        QUIC_TEL_ASSERT(FALSE);
        QuicConnFatalError(Builder->Connection, Status, "HP failure");
        return;
    }

    for (uint8_t i = 0; i < Builder->BatchCount; ++i) {
        uint16_t Offset = i * QUIC_HP_SAMPLE_LENGTH;
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
void
QuicPacketBuilderFinalize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN FlushBatchedDatagrams
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;
    BOOLEAN FinalQuicPacket = FALSE;

    if (Builder->Datagram == NULL ||
        Builder->Metadata->FrameCount == 0) {
        //
        // Nothing got framed into this packet. Undo the header of this
        // packet.
        //
        if (Builder->Datagram != NULL) {
            --Connection->Send.NextPacketNumber;
            Builder->DatagramLength -= Builder->HeaderLength;

            if (Builder->DatagramLength == 0) {
                QuicDataPathBindingFreeSendDatagram(Builder->SendContext, Builder->Datagram);
                Builder->Datagram = NULL;
            }
        }
        FinalQuicPacket = FlushBatchedDatagrams;
        goto Exit;
    }

    //
    // Calculate some of the packet buffer parameters (mostly used for encryption).
    //

    _Analysis_assume_(Builder->EncryptionOverhead <= 16);
    _Analysis_assume_(Builder->Datagram->Length < 0x10000);
    _Analysis_assume_(Builder->Datagram->Length >= (uint32_t)(Builder->DatagramLength + Builder->EncryptionOverhead));
    _Analysis_assume_(Builder->DatagramLength >= Builder->PacketStart + Builder->HeaderLength);
    _Analysis_assume_(Builder->DatagramLength >= Builder->PacketStart + Builder->PayloadLengthOffset);

    QUIC_DBG_ASSERT(Builder->Datagram->Length >= Builder->MinimumDatagramLength);
    QUIC_DBG_ASSERT(Builder->Datagram->Length >= (uint32_t)(Builder->DatagramLength + Builder->EncryptionOverhead));
    QUIC_DBG_ASSERT(Builder->Metadata->FrameCount != 0);
    QUIC_DBG_ASSERT(Builder->Key != NULL);
    QUIC_DBG_ASSERT(Builder->Key->PacketKey != NULL);
    QUIC_DBG_ASSERT(Builder->Key->HeaderKey != NULL);

    uint8_t* Header =
        (uint8_t*)Builder->Datagram->Buffer + Builder->PacketStart;
    uint16_t PayloadLength =
        Builder->DatagramLength - (Builder->PacketStart + Builder->HeaderLength);
    uint16_t ExpectedFinalDatagramLength =
        Builder->DatagramLength + Builder->EncryptionOverhead;

    if (FlushBatchedDatagrams ||
        Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE ||
        (uint16_t)Builder->Datagram->Length - ExpectedFinalDatagramLength < QUIC_MIN_PACKET_SPARE_SPACE) {

        FinalQuicPacket = TRUE;

        if (!FlushBatchedDatagrams && QuicDataPathIsPaddingPreferred(MsQuicLib.Datapath)) {
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
        QuicZeroMemory(
            Builder->Datagram->Buffer + Builder->DatagramLength,
            PaddingLength);
        PayloadLength += PaddingLength;
        Builder->DatagramLength += PaddingLength;
    }

    if (Builder->PacketType != SEND_PACKET_SHORT_HEADER_TYPE) {
        switch (Connection->Stats.QuicVersion) {
        case QUIC_VERSION_DRAFT_27:
        case QUIC_VERSION_DRAFT_28:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1:
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

    if (Connection->State.EncryptionEnabled) {

        //
        // Encrypt the data.
        //

        PayloadLength += Builder->EncryptionOverhead;
        Builder->DatagramLength += Builder->EncryptionOverhead;

        uint8_t* Payload = Header + Builder->HeaderLength;

        uint8_t Iv[QUIC_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(Builder->Key->Iv, (uint8_t*) &Builder->Metadata->PacketNumber, Iv);

        QUIC_STATUS Status;
        if (QUIC_FAILED(
            Status =
            QuicEncrypt(
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
                QUIC_DBG_ASSERT(Builder->BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT);

                //
                // Batch the header protection for short header packets.
                //

                QuicCopyMemory(
                    Builder->CipherBatch + Builder->BatchCount * QUIC_HP_SAMPLE_LENGTH,
                    PnStart + 4,
                    QUIC_HP_SAMPLE_LENGTH);
                Builder->HeaderBatch[Builder->BatchCount] = Header;

                if (++Builder->BatchCount == QUIC_MAX_CRYPTO_BATCH_COUNT) {
                    QuicPacketBuilderFinalizeHeaderProtection(Builder);
                }

            } else {
                QUIC_DBG_ASSERT(Builder->BatchCount == 0);

                //
                // Individually do header protection for long header packets as
                // they generally use different keys.
                //

                if (QUIC_FAILED(
                    Status =
                    QuicHpComputeMask(
                        Builder->Key->HeaderKey,
                        1,
                        PnStart + 4,
                        Builder->HpMask))) {
                    QUIC_TEL_ASSERT(FALSE);
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
            PacketSpace->CurrentKeyPhaseBytesSent + QUIC_MAX_MTU >=
                Connection->Session->Settings.MaxBytesPerKey &&
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
            QUIC_DBG_ASSERT(Builder->Key != NULL);
            QUIC_DBG_ASSERT(Builder->Key->PacketKey != NULL);
            QUIC_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
        }
    }

    //
    // Track the sent packet.
    //

    Builder->Metadata->SentTime = QuicTimeUs32();
    Builder->Metadata->PacketLength =
        Builder->HeaderLength + PayloadLength;

    QuicTraceEvent(
        ConnPacketSent,
        "[conn][%p][TX][%llu] %hhu (%hu bytes)",
        Connection,
        Builder->Metadata->PacketNumber,
        QuicPacketTraceType(Builder->Metadata),
        Builder->Metadata->PacketLength);
    if (QUIC_FAILED(
        QuicLossDetectionOnPacketSent(
            &Connection->LossDetection,
            Builder->Path,
            Builder->Metadata))) {
        goto Exit;
    }

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
        }

        if (FlushBatchedDatagrams || QuicDataPathBindingIsSendContextFull(Builder->SendContext)) {
            if (Builder->BatchCount != 0) {
                QuicPacketBuilderFinalizeHeaderProtection(Builder);
            }
            QuicPacketBuilderSendBatch(Builder);
        }

        if (Builder->PacketType == QUIC_RETRY) {
            QUIC_DBG_ASSERT(Builder->Metadata->PacketNumber == 0);
            QuicConnCloseLocally(
                Connection,
                QUIC_CLOSE_SILENT,
                QUIC_ERROR_NO_ERROR,
                NULL);
        }
    }
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

    if (QuicAddrIsBoundExplicitly(&Builder->Path->LocalAddress)) {
        QuicBindingSendTo(
            Builder->Path->Binding,
            &Builder->Path->RemoteAddress,
            Builder->SendContext);

    } else {
        QuicBindingSendFromTo(
            Builder->Path->Binding,
            &Builder->Path->LocalAddress,
            &Builder->Path->RemoteAddress,
            Builder->SendContext);
    }

    Builder->PacketBatchSent = TRUE;
    Builder->SendContext = NULL;
}
