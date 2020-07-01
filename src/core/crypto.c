/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains all the state and logic for the cryptographic handshake.
    This abstracts dealing with TLS 1.3 messages, as a multiple, serial streams
    of bytes. Each stream of bytes is secured with a different encryption key.

    QUIC_CRYPTO represents the multiple streams as a single contiguous buffer
    internally, and keeps tracks of the offsets at which each different stream
    starts (and therefore where the previous stream ends).

    Many of the internals of QUIC_CRYPTO are similar to QUIC_STREAM. This
    includes ACK tracking and receive buffer reassembly.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "crypto.c.clog.h"
#endif

QUIC_TLS_PROCESS_COMPLETE_CALLBACK QuicTlsProcessDataCompleteCallback;
QUIC_TLS_RECEIVE_TP_CALLBACK QuicConnReceiveTP;
QUIC_TLS_RECEIVE_RESUMPTION_CALLBACK QuicConnRecvResumptionTicket;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoDumpSendState(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    if (QuicTraceLogVerboseEnabled()) {

        QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

        QuicTraceLogConnVerbose(
            CryptoDump,
            Connection,
            "QS:%u MAX:%u UNA:%u NXT:%u RECOV:%u-%u",
            Crypto->TlsState.BufferTotalLength,
            Crypto->MaxSentLength,
            Crypto->UnAckedOffset,
            Crypto->NextSendOffset,
            Crypto->InRecovery ? Crypto->RecoveryNextOffset : 0,
            Crypto->InRecovery ? Crypto->RecoveryEndOffset : 0);

        uint64_t UnAcked = Crypto->UnAckedOffset;
        uint32_t i = 0;
        QUIC_SUBRANGE* Sack;
        while ((Sack = QuicRangeGetSafe(&Crypto->SparseAckRanges, i++)) != NULL) {
            QuicTraceLogConnVerbose(
                CryptoDumpUnacked,
                Connection,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Sack->Low);
            UnAcked = Sack->Low + Sack->Count;
        }
        if (UnAcked < (uint64_t)Crypto->MaxSentLength) {
            QuicTraceLogConnVerbose(
                CryptoDumpUnacked2,
                Connection,
                "  unACKed: [%llu, %u]",
                UnAcked,
                Crypto->MaxSentLength);
        }

        QUIC_DBG_ASSERT(Crypto->UnAckedOffset <= Crypto->NextSendOffset);
    }
}

#if DEBUG
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoValidate(
    _In_ const QUIC_CRYPTO* Crypto
    )
{
    QUIC_DBG_ASSERT(Crypto->TlsState.BufferTotalLength >= Crypto->MaxSentLength);
    QUIC_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->UnAckedOffset);
    QUIC_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->NextSendOffset);
    QUIC_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->RecoveryNextOffset);
    QUIC_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->RecoveryEndOffset);
    QUIC_DBG_ASSERT(Crypto->NextSendOffset >= Crypto->UnAckedOffset);
    QUIC_DBG_ASSERT(Crypto->TlsState.BufferLength + Crypto->UnAckedOffset == Crypto->TlsState.BufferTotalLength);
}
#else
#define QuicCryptoValidate(Crypto)
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoInitialize(
    _Inout_ QUIC_CRYPTO* Crypto
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    uint16_t SendBufferLength =
        QuicConnIsServer(Connection) ?
            QUIC_MAX_TLS_SERVER_SEND_BUFFER : QUIC_MAX_TLS_CLIENT_SEND_BUFFER;
    uint16_t InitialRecvBufferLength =
        QuicConnIsServer(Connection) ?
            QUIC_MAX_TLS_CLIENT_SEND_BUFFER : QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE;
    const uint8_t* HandshakeCid;
    uint8_t HandshakeCidLength;
    BOOLEAN SparseAckRangesInitialized = FALSE;
    BOOLEAN RecvBufferInitialized = FALSE;

    const uint8_t* Salt = QuicSupportedVersionList[0].Salt; // Default to latest
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Connection->Stats.QuicVersion) {
            Salt = QuicSupportedVersionList[i].Salt;
            break;
        }
    }

    QUIC_PASSIVE_CODE();

    QuicZeroMemory(Crypto, sizeof(QUIC_CRYPTO));

    Crypto->TlsState.BufferAllocLength = SendBufferLength;
    Crypto->TlsState.Buffer = QUIC_ALLOC_NONPAGED(SendBufferLength);
    if (Crypto->TlsState.Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "crypto send buffer",
            SendBufferLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Status =
        QuicRangeInitialize(
            QUIC_MAX_RANGE_ALLOC_SIZE,
            &Crypto->SparseAckRanges);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    SparseAckRangesInitialized = TRUE;

    Status =
        QuicRecvBufferInitialize(
            &Crypto->RecvBuffer,
            InitialRecvBufferLength,
            QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE / 2,
            TRUE);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    RecvBufferInitialized = TRUE;

    if (QuicConnIsServer(Connection)) {
        QUIC_DBG_ASSERT(Connection->SourceCids.Next != NULL);
        QUIC_CID_HASH_ENTRY* SourceCid =
            QUIC_CONTAINING_RECORD(
                Connection->SourceCids.Next,
                QUIC_CID_HASH_ENTRY,
                Link);

        HandshakeCid = SourceCid->CID.Data;
        HandshakeCidLength = SourceCid->CID.Length;

    } else {
        QUIC_DBG_ASSERT(!QuicListIsEmpty(&Connection->DestCids));
        QUIC_CID_QUIC_LIST_ENTRY* DestCid =
            QUIC_CONTAINING_RECORD(
                Connection->DestCids.Flink,
                QUIC_CID_QUIC_LIST_ENTRY,
                Link);

        HandshakeCid = DestCid->CID.Data;
        HandshakeCidLength = DestCid->CID.Length;
    }

    Status =
        QuicPacketKeyCreateInitial(
            QuicConnIsServer(Connection),
            Salt,
            HandshakeCidLength,
            HandshakeCid,
            &Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
            &Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL]);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "Creating initial keys");
        goto Exit;
    }
    QUIC_DBG_ASSERT(Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] != NULL);
    QUIC_DBG_ASSERT(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] != NULL);

    Crypto->Initialized = TRUE;
    QuicCryptoValidate(Crypto);

Exit:

    if (QUIC_FAILED(Status)) {
        for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(Crypto->TlsState.ReadKeys[i]);
            Crypto->TlsState.ReadKeys[i] = NULL;
            QuicPacketKeyFree(Crypto->TlsState.WriteKeys[i]);
            Crypto->TlsState.WriteKeys[i] = NULL;
        }
        if (RecvBufferInitialized) {
            QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
        }
        if (SparseAckRangesInitialized) {
            QuicRangeUninitialize(&Crypto->SparseAckRanges);
        }
        if (Crypto->TlsState.Buffer != NULL) {
            QUIC_FREE(Crypto->TlsState.Buffer);
            Crypto->TlsState.Buffer = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoUninitialize(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
        QuicPacketKeyFree(Crypto->TlsState.ReadKeys[i]);
        Crypto->TlsState.ReadKeys[i] = NULL;
        QuicPacketKeyFree(Crypto->TlsState.WriteKeys[i]);
        Crypto->TlsState.WriteKeys[i] = NULL;
    }
    if (Crypto->TLS != NULL) {
        QuicTlsUninitialize(Crypto->TLS);
        Crypto->TLS = NULL;
    }
    if (Crypto->Initialized) {
        QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
        QuicRangeUninitialize(&Crypto->SparseAckRanges);
        QUIC_FREE(Crypto->TlsState.Buffer);
        Crypto->TlsState.Buffer = NULL;
        Crypto->Initialized = FALSE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoInitializeTls(
    _Inout_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_SEC_CONFIG* SecConfig,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Params
    )
{
    QUIC_STATUS Status;
    QUIC_TLS_CONFIG TlsConfig = { 0 };
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    BOOLEAN IsServer = QuicConnIsServer(Connection);

    QUIC_DBG_ASSERT(Params != NULL);
    QUIC_DBG_ASSERT(SecConfig != NULL);
    QUIC_DBG_ASSERT(Connection->Session != NULL);
    QUIC_DBG_ASSERT(Connection->Session->TlsSession != NULL);

    TlsConfig.IsServer = IsServer;
    TlsConfig.TlsSession = Connection->Session->TlsSession;
    if (IsServer) {
        TlsConfig.AlpnBuffer = Crypto->TlsState.NegotiatedAlpn;
        TlsConfig.AlpnBufferLength = 1 + Crypto->TlsState.NegotiatedAlpn[0];
    } else {
        TlsConfig.AlpnBuffer = Connection->Session->AlpnList;
        TlsConfig.AlpnBufferLength = Connection->Session->AlpnListLength;
    }
    TlsConfig.SecConfig = SecConfig;
    TlsConfig.Connection = Connection;
    TlsConfig.ProcessCompleteCallback = QuicTlsProcessDataCompleteCallback;
    TlsConfig.ReceiveTPCallback = QuicConnReceiveTP;
    TlsConfig.ReceiveResumptionCallback = QuicConnRecvResumptionTicket;
    if (!QuicConnIsServer(Connection)) {
        TlsConfig.ServerName = Connection->RemoteServerName;
    }

    TlsConfig.LocalTPBuffer =
        QuicCryptoTlsEncodeTransportParameters(
            Connection,
            Params,
            &TlsConfig.LocalTPLength);
    if (TlsConfig.LocalTPBuffer == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status = QuicTlsInitialize(&TlsConfig, &Crypto->TlsState, &Crypto->TLS);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "QuicTlsInitialize");
        QUIC_FREE(TlsConfig.LocalTPBuffer);
        goto Error;
    }

    if (!IsServer) {
        QuicCryptoProcessData(Crypto, TRUE);
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoReset(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN ResetTls
    )
{
    QUIC_DBG_ASSERT(!QuicConnIsServer(QuicCryptoGetConnection(Crypto)));
    QUIC_TEL_ASSERT(!Crypto->TlsDataPending);
    QUIC_TEL_ASSERT(!Crypto->TlsCallPending);
    QUIC_TEL_ASSERT(Crypto->RecvTotalConsumed == 0);

    Crypto->MaxSentLength = 0;
    Crypto->UnAckedOffset = 0;
    Crypto->NextSendOffset = 0;
    Crypto->RecoveryNextOffset = 0;
    Crypto->RecoveryEndOffset = 0;
    Crypto->InRecovery = FALSE;

    if (ResetTls) {
        Crypto->TlsState.BufferLength = 0;
        Crypto->TlsState.BufferTotalLength = 0;

        QuicTlsReset(Crypto->TLS);
        QuicCryptoProcessData(Crypto, TRUE);

    } else {
        QuicSendSetSendFlag(
            &QuicCryptoGetConnection(Crypto)->Send,
            QUIC_CONN_SEND_FLAG_CRYPTO);
    }

    QuicCryptoValidate(Crypto);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoHandshakeConfirmed(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    Connection->State.HandshakeConfirmed = TRUE;

    QUIC_PATH* Path = &Connection->Paths[0];
    QUIC_DBG_ASSERT(Path->Binding != NULL);
    QuicBindingOnConnectionHandshakeConfirmed(Path->Binding, Connection);

    QuicCryptoDiscardKeys(Crypto, QUIC_PACKET_KEY_HANDSHAKE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicCryptoDiscardKeys(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_PACKET_KEY_TYPE KeyType
    )
{
    if (Crypto->TlsState.WriteKeys[KeyType] == NULL &&
        Crypto->TlsState.ReadKeys[KeyType] == NULL) {
        //
        // The keys have already been discarded.
        //
        return FALSE;
    }

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    QuicTraceLogConnInfo(
        DiscardKeyType,
        Connection,
        "Discarding key type = %hhu",
        KeyType);

    QuicPacketKeyFree(Crypto->TlsState.WriteKeys[KeyType]);
    QuicPacketKeyFree(Crypto->TlsState.ReadKeys[KeyType]);
    Crypto->TlsState.WriteKeys[KeyType] = NULL;
    Crypto->TlsState.ReadKeys[KeyType] = NULL;

    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(KeyType);
    _Analysis_assume_(EncryptLevel >= 0);
    if (EncryptLevel >= QUIC_ENCRYPT_LEVEL_1_RTT) {
        //
        // No additional state clean up required for 1-RTT encrytion level.
        //
        return TRUE;
    }

    //
    // Clean up send/recv tracking state for the encryption level.
    //

    QUIC_DBG_ASSERT(Connection->Packets[EncryptLevel] != NULL);
    BOOLEAN HasAckElicitingPacketsToAcknowledge =
        Connection->Packets[EncryptLevel]->AckTracker.AckElicitingPacketsToAcknowledge != 0;
    QuicLossDetectionDiscardPackets(&Connection->LossDetection, KeyType);
    QuicPacketSpaceUninitialize(Connection->Packets[EncryptLevel]);
    Connection->Packets[EncryptLevel] = NULL;

    //
    // Clean up any possible left over recovery state.
    //
    uint32_t BufferOffset =
        KeyType == QUIC_PACKET_KEY_INITIAL ?
            Crypto->TlsState.BufferOffsetHandshake :
            Crypto->TlsState.BufferOffset1Rtt;
    QUIC_DBG_ASSERT(BufferOffset != 0);
    QUIC_DBG_ASSERT(Crypto->MaxSentLength >= BufferOffset);
    if (Crypto->NextSendOffset < BufferOffset) {
        Crypto->NextSendOffset = BufferOffset;
    }
    if (Crypto->UnAckedOffset < BufferOffset) {
        Crypto->UnAckedOffset = BufferOffset;
        QuicRangeSetMin(&Crypto->SparseAckRanges, Crypto->UnAckedOffset);
    }

    if (HasAckElicitingPacketsToAcknowledge) {
        QuicSendUpdateAckState(&Connection->Send);
    }

    QuicCryptoValidate(Crypto);

    return TRUE;
}

//
// Send Interfaces
//

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_ENCRYPT_LEVEL
QuicCryptoGetNextEncryptLevel(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    uint64_t SendOffset =
        RECOV_WINDOW_OPEN(Crypto) ?
            Crypto->RecoveryNextOffset : Crypto->NextSendOffset;

    if (Crypto->TlsState.BufferOffset1Rtt != 0 &&
        SendOffset >= Crypto->TlsState.BufferOffset1Rtt) {
        return QUIC_ENCRYPT_LEVEL_1_RTT;
    } else if (Crypto->TlsState.BufferOffsetHandshake != 0 &&
        SendOffset >= Crypto->TlsState.BufferOffsetHandshake) {
        return QUIC_ENCRYPT_LEVEL_HANDSHAKE;
    } else {
        return QUIC_ENCRYPT_LEVEL_INITIAL;
    }
}

//
// Writes data at the requested stream offset to a stream frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoWriteOneFrame(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ uint32_t EncryptLevelStart,
    _In_ uint32_t CryptoOffset,
    _Inout_ uint16_t* FramePayloadBytes,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer,
    _Inout_ QUIC_SENT_PACKET_METADATA* PacketMetadata
    )
{
    QuicCryptoValidate(Crypto);
    QUIC_DBG_ASSERT(*FramePayloadBytes > 0);
    QUIC_DBG_ASSERT(CryptoOffset >= EncryptLevelStart);
    QUIC_DBG_ASSERT(CryptoOffset <= Crypto->TlsState.BufferTotalLength);
    QUIC_DBG_ASSERT(CryptoOffset >= (Crypto->TlsState.BufferTotalLength - Crypto->TlsState.BufferLength));

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    QUIC_CRYPTO_EX Frame = { CryptoOffset - EncryptLevelStart, 0, 0 };
    Frame.Data =
        Crypto->TlsState.Buffer +
        (CryptoOffset - (Crypto->TlsState.BufferTotalLength - Crypto->TlsState.BufferLength));

    //
    // From the remaining amount of space in the packet, calculate the size of
    // the CRYPTO frame header to then determine how much room is left for
    // payload.
    //

    uint16_t HeaderLength = sizeof(uint8_t) + QuicVarIntSize(CryptoOffset);
    if (BufferLength < *Offset + HeaderLength + 4) {
        QuicTraceLogConnVerbose(
            NoMoreRoomForCrypto,
            Connection,
            "No room for CRYPTO frame");
        return FALSE;
    }

    Frame.Length = BufferLength - *Offset - HeaderLength;
    uint16_t LengthFieldByteCount = QuicVarIntSize(Frame.Length);
    HeaderLength += LengthFieldByteCount;
    Frame.Length -= LengthFieldByteCount;

    //
    // Even if there is room in the buffer, we can't write more data than is
    // currently queued.
    //
    if (Frame.Length > *FramePayloadBytes) {
        Frame.Length = *FramePayloadBytes;
    }

    QUIC_DBG_ASSERT(Frame.Length > 0);
    *FramePayloadBytes = (uint16_t)Frame.Length;

    QuicTraceLogConnVerbose(
        AddCryptoFrame,
        Connection,
        "Sending %hu crypto bytes, offset=%u",
        (uint16_t)Frame.Length,
        CryptoOffset);

    //
    // We're definitely writing a frame and we know how many bytes it contains,
    // so do the real call to QuicFrameEncodeStreamHeader to write the header.
    //
    QUIC_FRE_ASSERT(
        QuicCryptoFrameEncode(&Frame, Offset, BufferLength, Buffer));

    PacketMetadata->Flags.IsAckEliciting = TRUE;
    PacketMetadata->Frames[PacketMetadata->FrameCount].Type = QUIC_FRAME_CRYPTO;
    PacketMetadata->Frames[PacketMetadata->FrameCount].CRYPTO.Offset = CryptoOffset;
    PacketMetadata->Frames[PacketMetadata->FrameCount].CRYPTO.Length = (uint16_t)Frame.Length;
    PacketMetadata->Frames[PacketMetadata->FrameCount].Flags = 0;
    PacketMetadata->FrameCount++;

    return TRUE;
}

//
// Writes CRYPTO frames into a packet buffer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoWriteCryptoFrames(
    _In_ QUIC_CRYPTO* Crypto,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    QuicCryptoValidate(Crypto);

    //
    // Write frames until we've filled the provided space.
    //

    while (*Offset < BufferLength &&
        Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET) {

        //
        // Find the bounds of this frame. Left is the offset of the
        // first byte in the frame, and Right is the offset of the
        // first byte AFTER the frame.
        //
        uint32_t Left;
        uint32_t Right;

        BOOLEAN Recovery;
        if (RECOV_WINDOW_OPEN(Crypto)) {
            Left = Crypto->RecoveryNextOffset;
            Recovery = TRUE;
        } else {
            Left = Crypto->NextSendOffset;
            Recovery = FALSE;
        }

        if (Left == Crypto->TlsState.BufferTotalLength) {
            //
            // No more data left to send.
            //
            break;
        }

        Right = Left + BufferLength - *Offset;

        if (Recovery &&
            Right > Crypto->RecoveryEndOffset &&
            Crypto->RecoveryEndOffset != Crypto->NextSendOffset) {
            Right = Crypto->RecoveryEndOffset;
        }

        //
        // Find the first SACK after the selected offset.
        //
        uint32_t i = 0;
        QUIC_SUBRANGE* Sack;
        if (Left == Crypto->MaxSentLength) {
            //
            // Transmitting new bytes; no such SACK can exist.
            //
            Sack = NULL;
        } else {
            while ((Sack = QuicRangeGetSafe(&Crypto->SparseAckRanges, i++)) != NULL &&
                Sack->Low < (uint64_t)Left) {
                QUIC_DBG_ASSERT(Sack->Low + Sack->Count <= (uint64_t)Left);
            }
        }

        if (Sack) {
            if ((uint64_t)Right > Sack->Low) {
                Right = (uint32_t)Sack->Low;
            }
        } else {
            if (Right > Crypto->TlsState.BufferTotalLength) {
                Right = Crypto->TlsState.BufferTotalLength;
            }
        }

        QUIC_DBG_ASSERT(Right >= Left);

        uint32_t EncryptLevelStart;
        uint32_t PacketTypeRight;
        switch (Builder->PacketType) {
        case QUIC_INITIAL:
            EncryptLevelStart = 0;
            if (Crypto->TlsState.BufferOffsetHandshake != 0) {
                PacketTypeRight = Crypto->TlsState.BufferOffsetHandshake;
            } else {
                PacketTypeRight = Crypto->TlsState.BufferTotalLength;
            }
            break;
        case QUIC_0_RTT_PROTECTED:
            QUIC_FRE_ASSERT(FALSE);
            EncryptLevelStart = 0;
            PacketTypeRight = 0; // To get build to stop complaining.
            break;
        case QUIC_HANDSHAKE:
            QUIC_DBG_ASSERT(Crypto->TlsState.BufferOffsetHandshake != 0);
            QUIC_DBG_ASSERT(Left >= Crypto->TlsState.BufferOffsetHandshake);
            EncryptLevelStart = Crypto->TlsState.BufferOffsetHandshake;
            PacketTypeRight =
                Crypto->TlsState.BufferOffset1Rtt == 0 ?
                    Crypto->TlsState.BufferTotalLength : Crypto->TlsState.BufferOffset1Rtt;
            break;
        default:
            QUIC_DBG_ASSERT(Crypto->TlsState.BufferOffset1Rtt != 0);
            QUIC_DBG_ASSERT(Left >= Crypto->TlsState.BufferOffset1Rtt);
            EncryptLevelStart = Crypto->TlsState.BufferOffset1Rtt;
            PacketTypeRight = Crypto->TlsState.BufferTotalLength;
            break;
        }

        if (Right > PacketTypeRight) {
            Right = PacketTypeRight;
        }

        if (Left >= Right) {
            //
            // No more data to write at this encryption level, though we should
            // have at least written something. If not, then the logic that
            // decided to call this function in the first place is wrong.
            //
            break;
        }

        QUIC_DBG_ASSERT(Right > Left);

        uint16_t FramePayloadBytes = (uint16_t)(Right - Left);

        if (!QuicCryptoWriteOneFrame(
                Crypto,
                EncryptLevelStart,
                Left,
                &FramePayloadBytes,
                Offset,
                BufferLength,
                Buffer,
                Builder->Metadata)) {
            //
            // No more data could be written.
            //
            break;
        }

        //
        // FramePayloadBytes may have been reduced.
        //
        Right = Left + FramePayloadBytes;

        //
        // Move the "next" offset (RecoveryNextOffset if we are sending
        // recovery bytes or NextSendOffset otherwise) forward by the
        // number of bytes we've written. If we wrote up to the edge
        // of a SACK, skip past the SACK.
        //

        if (Recovery) {
            QUIC_DBG_ASSERT(Crypto->RecoveryNextOffset <= Right);
            Crypto->RecoveryNextOffset = Right;
            if (Sack && (uint64_t)Crypto->RecoveryNextOffset == Sack->Low) {
                Crypto->RecoveryNextOffset += (uint32_t)Sack->Count;
            }
        }

        if (Crypto->NextSendOffset < Right) {
            Crypto->NextSendOffset = Right;
            if (Sack && (uint64_t)Crypto->NextSendOffset == Sack->Low) {
                Crypto->NextSendOffset += (uint32_t)Sack->Count;
            }
        }

        if (Crypto->MaxSentLength < Right) {
            Crypto->MaxSentLength = Right;
        }

        QuicCryptoValidate(Crypto);
    }

    QuicCryptoDumpSendState(Crypto);
    QuicCryptoValidate(Crypto);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicCryptoWriteFrames(
    _In_ QUIC_CRYPTO* Crypto,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    QUIC_DBG_ASSERT(Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET);

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    uint8_t PrevFrameCount = Builder->Metadata->FrameCount;

    uint16_t AvailableBufferLength =
        (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;

    if (QuicCryptoHasPendingCryptoFrame(Crypto)) {
        QuicCryptoWriteCryptoFrames(
            Crypto,
            Builder,
            &Builder->DatagramLength,
            AvailableBufferLength,
            Builder->Datagram->Buffer);

        if (!QuicCryptoHasPendingCryptoFrame(Crypto)) {
            Connection->Send.SendFlags &= ~QUIC_CONN_SEND_FLAG_CRYPTO;
        }

    } else {
        //
        // If it doesn't have anything to send, it shouldn't have been queued in
        // the first place.
        //
        QUIC_DBG_ASSERT(FALSE);
    }

    return Builder->Metadata->FrameCount > PrevFrameCount;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicCryptoOnLoss(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    )
{
    uint64_t Start = FrameMetadata->CRYPTO.Offset;
    uint64_t End = Start + FrameMetadata->CRYPTO.Length;

    //
    // First check to make sure this data wasn't already acknowledged in a
    // different packet.
    //

    if (End <= Crypto->UnAckedOffset) {
        //
        // Already completely acknowledged.
        //
        return FALSE;
    } else if (Start < Crypto->UnAckedOffset) {
        //
        // The 'lost' range overlaps with UNA. Move Start forward.
        //
        Start = Crypto->UnAckedOffset;
    }

    QUIC_SUBRANGE* Sack;
    uint32_t i = 0;
    while ((Sack = QuicRangeGetSafe(&Crypto->SparseAckRanges, i++)) != NULL &&
        Sack->Low < End) {
        if (Start < Sack->Low + Sack->Count) {
            //
            // This SACK overlaps with the 'lost' range.
            //
            if (Start >= Sack->Low) {
                //
                // The SACK fully covers the Start of the 'lost' range.
                //
                if (End <= Sack->Low + Sack->Count) {
                    //
                    // The SACK fully covers the whole 'lost' range.
                    //
                    return FALSE;

                } else {
                    //
                    // The SACK only covers the beginning of the 'lost'
                    // range. Move Start forward to the end of the SACK.
                    //
                    Start = Sack->Low + Sack->Count;
                }

            } else if (End <= Sack->Low + Sack->Count) {
                //
                // The SACK fully covers the End of the 'lost' range. Move
                // the End backward to right before the SACK.
                //
                End = Sack->Low;

            } else {
                //
                // The SACK is fully covered by the 'lost' range. Don't do
                // anything special in this case, because we still have stuff
                // that needs to be retransmitted in that case.
                //
            }
        }
    }

    BOOLEAN UpdatedRecoveryWindow = FALSE;

    //
    // Expand the recovery window to encompass the crypto frame that was lost.
    //

    if (Start < Crypto->RecoveryNextOffset) {
        Crypto->RecoveryNextOffset = (uint32_t)Start;
        UpdatedRecoveryWindow = TRUE;
    }

    if (Crypto->RecoveryEndOffset < End) {
        Crypto->RecoveryEndOffset = (uint32_t)End;
        UpdatedRecoveryWindow = TRUE;
    }

    if (UpdatedRecoveryWindow) {

        QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

        QuicTraceLogConnVerbose(
            RecoverCrypto,
            Connection,
            "Recovering crypto from %llu up to %llu",
            Start,
            End);

        if (!Crypto->InRecovery) {
            Crypto->InRecovery = TRUE;
        }

        BOOLEAN DataQueued =
            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_CRYPTO);

        QuicCryptoDumpSendState(Crypto);
        QuicCryptoValidate(Crypto);

        return DataQueued;
    }

    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoOnAck(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    )
{
    uint32_t Offset = FrameMetadata->CRYPTO.Offset;
    uint32_t Length = FrameMetadata->CRYPTO.Length;

    //
    // The offset directly following this frame.
    //
    uint32_t FollowingOffset = Offset + Length;

    QUIC_DBG_ASSERT(FollowingOffset <= Crypto->TlsState.BufferTotalLength);

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

    QuicTraceLogConnVerbose(
        AckCrypto,
        Connection,
        "Received ack for %u crypto bytes, offset=%u",
        Length,
        Offset);

    if (Offset <= Crypto->UnAckedOffset) {

        //
        // No unacknowledged bytes before this ACK. If any new
        // bytes are acknowledged then we'll advance UnAckedOffset.
        //

        if (Crypto->UnAckedOffset < FollowingOffset) {

            uint32_t OldUnAckedOffset = Crypto->UnAckedOffset;
            Crypto->UnAckedOffset = FollowingOffset;

            //
            // Delete any SACKs that UnAckedOffset caught up to.
            //
            QuicRangeSetMin(&Crypto->SparseAckRanges, Crypto->UnAckedOffset);
            QUIC_SUBRANGE* Sack = QuicRangeGetSafe(&Crypto->SparseAckRanges, 0);
            if (Sack && Sack->Low == (uint64_t)Crypto->UnAckedOffset) {
                Crypto->UnAckedOffset = (uint32_t)(Sack->Low + Sack->Count);
                QuicRangeRemoveSubranges(&Crypto->SparseAckRanges, 0, 1);
            }

            //
            // Drain the front of the send buffer.
            //
            uint32_t DrainLength = Crypto->UnAckedOffset - OldUnAckedOffset;
            QUIC_DBG_ASSERT(DrainLength <= (uint32_t)Crypto->TlsState.BufferLength);
            if ((uint32_t)Crypto->TlsState.BufferLength > DrainLength) {
                Crypto->TlsState.BufferLength -= (uint16_t)DrainLength;
                QuicMoveMemory(
                    Crypto->TlsState.Buffer,
                    Crypto->TlsState.Buffer + DrainLength,
                    Crypto->TlsState.BufferLength);
            } else {
                Crypto->TlsState.BufferLength = 0;
            }

            if (Crypto->NextSendOffset < Crypto->UnAckedOffset) {
                Crypto->NextSendOffset = Crypto->UnAckedOffset;
            }
            if (Crypto->RecoveryNextOffset < Crypto->UnAckedOffset) {
                Crypto->RecoveryNextOffset = Crypto->UnAckedOffset;
            }
            if (Crypto->RecoveryEndOffset < Crypto->UnAckedOffset) {
                Crypto->InRecovery = FALSE;
            }
            if (Connection->State.Connected && QuicConnIsServer(Connection) &&
                Crypto->TlsState.BufferOffset1Rtt != 0 &&
                Crypto->UnAckedOffset == Crypto->TlsState.BufferTotalLength) {
                QuicConnCleanupServerResumptionState(Connection);
            }
        }

    } else {

        BOOLEAN SacksUpdated;
        QUIC_SUBRANGE* Sack =
            QuicRangeAddRange(
                &Crypto->SparseAckRanges,
                Offset,
                Length,
                &SacksUpdated);
        if (Sack == NULL) {

            QuicConnFatalError(Connection, QUIC_STATUS_OUT_OF_MEMORY, "Out of memory");
            return;

        } else if (SacksUpdated) {

            //
            // Sack points to a new or expanded SACK, and any bytes that are
            // newly ACKed are covered by this SACK.
            //

            //
            // In QuicCryptoWriteFrames we assume that the starting offset
            // (NextSendOffset or RecoveryNextOffset) is not acknowledged, so
            // fix up these two offsets.
            //
            if ((uint64_t)Crypto->NextSendOffset >= Sack->Low &&
                (uint64_t)Crypto->NextSendOffset < Sack->Low + Sack->Count) {
                Crypto->NextSendOffset = (uint32_t)(Sack->Low + Sack->Count);
            }
            if ((uint64_t)Crypto->RecoveryNextOffset >= Sack->Low &&
                (uint64_t)Crypto->RecoveryNextOffset < Sack->Low + Sack->Count) {
                Crypto->RecoveryNextOffset = (uint32_t)(Sack->Low + Sack->Count);
            }
        }
    }

    if (!QuicCryptoHasPendingCryptoFrame(Crypto)) {
        //
        // Make the crypto stream isn't queued to send.
        //
        QuicSendClearSendFlag(
            &Connection->Send,
            QUIC_CONN_SEND_FLAG_CRYPTO);
    }

    QuicCryptoDumpSendState(Crypto);
    QuicCryptoValidate(Crypto);
}

//
// Receive Interfaces
//

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessDataFrame(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_CRYPTO_EX* Frame,
    _Out_ BOOLEAN* DataReady
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    uint64_t FlowControlLimit = UINT16_MAX;

    *DataReady = FALSE;

    if (Frame->Length == 0) {

        Status = QUIC_STATUS_SUCCESS;

    } else if (!Crypto->Initialized) {

        Status = QUIC_STATUS_SUCCESS;
        QuicTraceLogConnWarning(
            IgnoreCryptoFrame,
            Connection,
            "Ignoring received crypto after cleanup");

    } else {

        if (KeyType == QUIC_PACKET_KEY_1_RTT_OLD ||
            KeyType == QUIC_PACKET_KEY_1_RTT_NEW) {
            KeyType = QUIC_PACKET_KEY_1_RTT; // Treat them all as the same
        }

        QUIC_DBG_ASSERT(KeyType <= Crypto->TlsState.ReadKey);
        if (KeyType < Crypto->TlsState.ReadKey) {
            Status = QUIC_STATUS_SUCCESS; // Old, likely retransmitted data.
            goto Error;
        }

        //
        // Write the received data (could be duplicate) to the stream buffer. The
        // stream buffer will indicate if there is data to process.
        //
        Status =
            QuicRecvBufferWrite(
                &Crypto->RecvBuffer,
                Crypto->RecvEncryptLevelStartOffset + Frame->Offset,
                (uint16_t)Frame->Length,
                Frame->Data,
                &FlowControlLimit,
                DataReady);
        if (QUIC_FAILED(Status)) {
            if (Status == QUIC_STATUS_BUFFER_TOO_SMALL) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Tried to write beyond crypto flow control limit.");
                QuicConnTransportError(Connection, QUIC_ERROR_CRYPTO_BUFFER_EXCEEDED);
            }
            goto Error;
        }
    }

    QuicTraceLogConnVerbose(
        RecvCrypto,
        Connection,
        "Received %hu crypto bytes, offset=%llu Ready=%hhu",
        (uint16_t)Frame->Length,
        Frame->Offset,
        *DataReady);

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessFrame(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_CRYPTO_EX* const Frame
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN DataReady;

    Status =
        QuicCryptoProcessDataFrame(
            Crypto, KeyType, Frame, &DataReady);

    if (QUIC_SUCCEEDED(Status) && DataReady) {
        if (!Crypto->TlsCallPending) {
            QuicCryptoProcessData(Crypto, FALSE);

            QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
            if (Connection->State.ClosedLocally) {
                //
                // If processing the received frame caused us to close the
                // connection, make sure to stop processing anything else in the
                // packet.
                //
                Status = QUIC_STATUS_INVALID_STATE;
            }
        } else {
            //
            // Can't call TLS yet (either hasn't been initialized or already
            // working) so just indicate we have data pending ready for delivery.
            //
            Crypto->TlsDataPending = TRUE;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnReceiveTP(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TPLength,
    _In_reads_(TPLength) const uint8_t* TPBuffer
    )
{
    if (!QuicCryptoTlsDecodeTransportParameters(
            Connection,
            TPBuffer,
            TPLength,
            &Connection->PeerTransportParams)) {
        return FALSE;
    }

    QuicConnProcessPeerTransportParameters(Connection, FALSE);

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoProcessTlsCompletion(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_TLS_RESULT_FLAGS ResultFlags
    )
{
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

    if (ResultFlags & QUIC_TLS_RESULT_ERROR) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Crypto->TlsState.AlertCode,
            "Received alert from TLS.");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_CRYPTO_ERROR(0xFF & Crypto->TlsState.AlertCode));
        return;
    }

    QuicCryptoValidate(Crypto);

    if (ResultFlags & QUIC_TLS_RESULT_EARLY_DATA_ACCEPT) {
        QuicTraceLogConnInfo(
            ZeroRttAccepted,
            Connection,
            "0-RTT accepted");
        QUIC_TEL_ASSERT(Crypto->TlsState.EarlyDataState == QUIC_TLS_EARLY_DATA_ACCEPTED);
    }

    if (ResultFlags & QUIC_TLS_RESULT_EARLY_DATA_REJECT) {
        QuicTraceLogConnInfo(
            ZeroRttRejected,
            Connection,
            "0-RTT rejected");
        QUIC_TEL_ASSERT(Crypto->TlsState.EarlyDataState != QUIC_TLS_EARLY_DATA_ACCEPTED);
        if (!QuicConnIsServer(Connection)) {
            QuicCryptoDiscardKeys(Crypto, QUIC_PACKET_KEY_0_RTT);
            QuicLossDetectionOnZeroRttRejected(&Connection->LossDetection);
        } else {
            QuicConnDiscardDeferred0Rtt(Connection);
        }
    }

    if (ResultFlags & QUIC_TLS_RESULT_WRITE_KEY_UPDATED) {
        QuicTraceEvent(
            ConnWriteKeyUpdated,
            "[conn][%p] Write Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.WriteKey);
        QUIC_DBG_ASSERT(Crypto->TlsState.WriteKey <= QUIC_PACKET_KEY_1_RTT);
        _Analysis_assume_(Crypto->TlsState.WriteKey >= 0);
        QUIC_TEL_ASSERT(Crypto->TlsState.WriteKeys[Crypto->TlsState.WriteKey] != NULL);
        if (Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_HANDSHAKE &&
            !QuicConnIsServer(Connection)) {
            //
            // Per spec, client MUST discard Initial keys when it starts
            // encrypting packets with handshake keys.
            //
            QuicCryptoDiscardKeys(Crypto, QUIC_PACKET_KEY_INITIAL);
        }
        if (Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
            if (!QuicConnIsServer(Connection)) {
                //
                // The client has the 1-RTT keys so we can get rid of 0-RTT
                // keys.
                //
                QuicCryptoDiscardKeys(Crypto, QUIC_PACKET_KEY_0_RTT);
            }
            //
            // We have the 1-RTT key so we can start sending application data.
            //
            QuicSendQueueFlush(&Connection->Send, REASON_NEW_KEY);
        }

        if (QuicConnIsServer(Connection)) {
            if (Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
                //
                // Done with the server's flight.
                //
                Connection->Stats.Handshake.ServerFlight1Bytes = Crypto->TlsState.BufferOffset1Rtt;
            }
        } else {
            if (Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_HANDSHAKE) {
                //
                // Done with the client's Initial flight.
                //
                Connection->Stats.Handshake.ClientFlight1Bytes = Crypto->TlsState.BufferOffsetHandshake;
            }

            if (Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
                //
                // Done with the client's second flight, consisting of Handshake packets.
                //
                Connection->Stats.Handshake.ClientFlight2Bytes =
                    Crypto->TlsState.BufferOffset1Rtt - Crypto->TlsState.BufferOffsetHandshake;
            }
        }
    }

    if (ResultFlags & QUIC_TLS_RESULT_READ_KEY_UPDATED) {
        //
        // Make sure there isn't any data received past the current Recv offset
        // at the previous encryption level.
        //
        if (QuicRecvBufferHasUnreadData(&Crypto->RecvBuffer)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Leftover crypto data in previous encryption level.");
            QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
            return;
        }

        Crypto->RecvEncryptLevelStartOffset = Crypto->RecvTotalConsumed;
        QuicTraceEvent(
            ConnReadKeyUpdated,
            "[conn][%p] Read Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.ReadKey);

        //
        // If we have the read key, we must also have the write key.
        //
        QUIC_DBG_ASSERT(Crypto->TlsState.ReadKey <= QUIC_PACKET_KEY_1_RTT);
        _Analysis_assume_(Crypto->TlsState.ReadKey >= 0);
        QUIC_TEL_ASSERT(Crypto->TlsState.WriteKey >= Crypto->TlsState.ReadKey);
        QUIC_TEL_ASSERT(Crypto->TlsState.ReadKeys[Crypto->TlsState.ReadKey] != NULL);

        if (QuicConnIsServer(Connection)) {
            if (Crypto->TlsState.ReadKey == QUIC_PACKET_KEY_HANDSHAKE) {
                //
                // Done with the client's Initial flight.
                //
                Connection->Stats.Handshake.ClientFlight1Bytes = Crypto->RecvTotalConsumed;
            }

            if (Crypto->TlsState.ReadKey == QUIC_PACKET_KEY_1_RTT) {
                //
                // Done with the client's second flight, consisting of Handshake packets.
                //
                Connection->Stats.Handshake.ClientFlight2Bytes =
                    Crypto->RecvTotalConsumed - Connection->Stats.Handshake.ClientFlight1Bytes;
            }
        } else {
            if (Crypto->TlsState.ReadKey == QUIC_PACKET_KEY_1_RTT) {
                //
                // Done with the server's flight.
                //
                Connection->Stats.Handshake.ServerFlight1Bytes = Crypto->RecvTotalConsumed;
            }
        }

        if (Connection->Stats.Timing.InitialFlightEnd == 0) {
            //
            // Any read key change means we are done with the initial flight.
            //
            Connection->Stats.Timing.InitialFlightEnd = QuicTimeUs64();
        }

        if (Crypto->TlsState.ReadKey == QUIC_PACKET_KEY_1_RTT) {
            //
            // Once TLS is consuming 1-RTT data, we are done with the Handshake
            // flight.
            //
            Connection->Stats.Timing.HandshakeFlightEnd = QuicTimeUs64();
        }
    }

    if (ResultFlags & QUIC_TLS_RESULT_DATA) {
        QuicSendSetSendFlag(
            &QuicCryptoGetConnection(Crypto)->Send,
            QUIC_CONN_SEND_FLAG_CRYPTO);
        QuicCryptoDumpSendState(Crypto);
        QuicCryptoValidate(Crypto);
    }

    if (ResultFlags & QUIC_TLS_RESULT_COMPLETE) {
        QUIC_DBG_ASSERT(!(ResultFlags & QUIC_TLS_RESULT_ERROR));
        QUIC_TEL_ASSERT(!Connection->State.Connected);

        QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);

        //
        // We should have the 1-RTT keys by connection complete time.
        //
        QUIC_TEL_ASSERT(Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT] != NULL);
        QUIC_TEL_ASSERT(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL);

        if (QuicConnIsServer(Connection)) {
            //
            // Handshake is confirmed on the server side as soon as it completes.
            //
            QuicTraceLogConnInfo(
                HandshakeConfirmedServer,
                Connection,
                "Handshake confirmed (server)");
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE);
            QuicCryptoHandshakeConfirmed(&Connection->Crypto);
        }

        //
        // Only set the connected flag after we do the confirmation code path
        // above so that TLS state isn't prematurely destroyed (before the
        // CONNECTED event is indicated to the app).
        //
        Connection->State.Connected = TRUE;

        QuicConnGenerateNewSourceCids(Connection, FALSE);

        if (!QuicConnIsServer(Connection) &&
            Connection->RemoteServerName != NULL) {

            QUIC_SEC_CONFIG* SecConfig = QuicTlsGetSecConfig(Crypto->TLS);

            //
            // Cache this information for future connections in this
            // session to make use of.
            //
            QUIC_TEL_ASSERT(Connection->Session != NULL);
            QuicSessionServerCacheSetState(
                Connection->Session,
                Connection->RemoteServerName,
                Connection->Stats.QuicVersion,
                &Connection->PeerTransportParams,
                SecConfig);

            QuicTlsSecConfigRelease(SecConfig);
        }

        QUIC_DBG_ASSERT(Crypto->TlsState.NegotiatedAlpn != NULL);
        if (!QuicConnIsServer(Connection)) {
            //
            // Currently, NegotiatedAlpn points into TLS state memory, which
            // doesn't live as long as the connection. Update it to point to the
            // session state memory instead.
            //
            Crypto->TlsState.NegotiatedAlpn =
                QuicTlsAlpnFindInList(
                    Connection->Session->AlpnListLength,
                    Connection->Session->AlpnList,
                    Crypto->TlsState.NegotiatedAlpn[0],
                    Crypto->TlsState.NegotiatedAlpn + 1);
            QUIC_TEL_ASSERT(Crypto->TlsState.NegotiatedAlpn != NULL);
        }

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_CONNECTED;
        Event.CONNECTED.SessionResumed = Crypto->TlsState.SessionResumed;
        Event.CONNECTED.NegotiatedAlpnLength = Crypto->TlsState.NegotiatedAlpn[0];
        Event.CONNECTED.NegotiatedAlpn = Crypto->TlsState.NegotiatedAlpn + 1;
        QuicTraceLogConnVerbose(
            IndicateConnected,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)",
            Event.CONNECTED.SessionResumed);
        (void)QuicConnIndicateEvent(Connection, &Event);

        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PMTUD);

        if (QuicConnIsServer(Connection) &&
            Crypto->TlsState.BufferOffset1Rtt != 0 &&
            Crypto->UnAckedOffset == Crypto->TlsState.BufferTotalLength) {
            QuicConnCleanupServerResumptionState(Connection);
        }
    }

    if (ResultFlags & QUIC_TLS_RESULT_TICKET) {
        QuicTraceLogConnInfo(
            TicketReady,
            Connection,
            "Ticket ready");
    }

    QuicCryptoValidate(Crypto);

    if (ResultFlags & QUIC_TLS_RESULT_READ_KEY_UPDATED) {
        QuicConnFlushDeferred(Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoProcessDataComplete(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_TLS_RESULT_FLAGS ResultFlags,
    _In_ uint32_t RecvBufferConsumed
    )
{
    Crypto->TlsCallPending = FALSE;
    if (RecvBufferConsumed != 0) {
        Crypto->RecvTotalConsumed += RecvBufferConsumed;
        QuicTraceLogConnVerbose(
            DrainCrypto,
            QuicCryptoGetConnection(Crypto),
            "Draining %u crypto bytes",
            RecvBufferConsumed);
        QuicRecvBufferDrain(&Crypto->RecvBuffer, RecvBufferConsumed);
    }

    QuicCryptoValidate(Crypto);
    QuicCryptoProcessTlsCompletion(Crypto, ResultFlags);

    if (Crypto->TlsDataPending && !Crypto->TlsCallPending) {
        QuicCryptoProcessData(Crypto, FALSE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicTlsProcessDataCompleteCallback(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_OPERATION* Oper;
    if ((Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_TLS_COMPLETE)) != NULL) {
        QuicConnQueueOper(Connection, Oper);
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "TLS complete operation",
            0);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoProcessCompleteOperation(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    uint32_t BufferConsumed = 0;
    QUIC_TLS_RESULT_FLAGS ResultFlags =
        QuicTlsProcessDataComplete(Crypto->TLS, &BufferConsumed);
    QuicCryptoProcessDataComplete(Crypto, ResultFlags, BufferConsumed);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoProcessData(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN IsClientInitial
    )
{
    uint32_t BufferCount = 1;
    QUIC_BUFFER Buffer;

    QUIC_TEL_ASSERT(!Crypto->TlsCallPending);

    if (IsClientInitial) {
        Buffer.Length = 0;
        Buffer.Buffer = NULL;

    } else {
        uint64_t BufferOffset;
        BOOLEAN DataAvailable =
            QuicRecvBufferRead(
                &Crypto->RecvBuffer,
                &BufferOffset,
                &BufferCount,
                &Buffer);

        UNREFERENCED_PARAMETER(DataAvailable);
        QUIC_TEL_ASSERT(DataAvailable);
        QUIC_DBG_ASSERT(BufferCount == 1);

        QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

        Buffer.Length =
            QuicCrytpoTlsGetCompleteTlsMessagesLength(
                Buffer.Buffer, Buffer.Length);
        if (Buffer.Length == 0) {
            QuicTraceLogConnVerbose(
                CryptoNotReady,
                Connection,
                "No complete TLS messages to process");
            goto Error;
        }

        if (BufferOffset == 0 &&
            QuicConnIsServer(Connection) &&
            !Connection->State.ExternalOwner) {
            //
            // Preprocess the TLS ClientHello to find the ALPN (and optionally
            // SNI) to match the connection to a listener.
            //
            QUIC_NEW_CONNECTION_INFO Info = {0};
            QUIC_STATUS Status =
                QuicCryptoTlsReadInitial(
                    Connection,
                    Buffer.Buffer,
                    Buffer.Length,
                    &Info);
            if (QUIC_FAILED(Status)) {
                QuicConnTransportError(
                    Connection,
                    QUIC_ERROR_CRYPTO_HANDSHAKE_FAILURE);
                goto Error;
            } else if (Status == QUIC_STATUS_PENDING) {
                //
                // The full ClientHello hasn't been received yet.
                //
                goto Error;
            }

            Info.QuicVersion = Connection->Stats.QuicVersion;
            Info.LocalAddress = &Connection->Paths[0].LocalAddress;
            Info.RemoteAddress = &Connection->Paths[0].RemoteAddress;
            Info.CryptoBufferLength = Buffer.Length;
            Info.CryptoBuffer = Buffer.Buffer;

            QUIC_CONNECTION_ACCEPT_RESULT AcceptResult =
                QUIC_CONNECTION_REJECT_NO_LISTENER;

            QUIC_SEC_CONFIG* SecConfig = NULL;
            QUIC_LISTENER* Listener =
                QuicBindingGetListener(
                    Connection->Paths[0].Binding,
                    &Info);
            if (Listener != NULL) {
                AcceptResult =
                    QuicListenerAcceptConnection(
                        Listener,
                        Connection,
                        &Info,
                        &SecConfig);
                QuicRundownRelease(&Listener->Rundown);
            }

            if (AcceptResult != QUIC_CONNECTION_ACCEPT) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    AcceptResult,
                    "Connection rejected");
                if (AcceptResult == QUIC_CONNECTION_REJECT_NO_LISTENER) {
                    QuicConnTransportError(
                        Connection,
                        QUIC_ERROR_CRYPTO_NO_APPLICATION_PROTOCOL);
                } else if (AcceptResult == QUIC_CONNECTION_REJECT_BUSY) {
                    QuicConnTransportError(
                        Connection,
                        QUIC_ERROR_CONNECTION_REFUSED);
                } else {    // QUIC_CONNECTION_REJECT_APP
                    QuicConnTransportError(
                        Connection,
                        QUIC_ERROR_INTERNAL_ERROR);
                }
                goto Error;

            }

            //
            // Save the negotiated ALPN (starting with the length prefix) to be
            // used later in building up the TLS response.
            //
            Crypto->TlsState.NegotiatedAlpn = Info.NegotiatedAlpn - 1;

            if (SecConfig != NULL) {
                Status = QuicConnHandshakeConfigure(Connection, SecConfig);
                if (QUIC_FAILED(Status)) {
                    QuicConnTransportError(
                        Connection,
                        QUIC_ERROR_CRYPTO_HANDSHAKE_FAILURE);
                    goto Error;
                }
            }
        }
    }

    if (Crypto->TLS == NULL) {
        //
        // The listener still hasn't given us the security config to initialize
        // TLS with yet.
        //
        goto Error;
    }

    Crypto->TlsDataPending = FALSE;
    Crypto->TlsCallPending = TRUE;

    QuicCryptoValidate(Crypto);

    QUIC_TLS_RESULT_FLAGS ResultFlags =
        QuicTlsProcessData(Crypto->TLS, QUIC_TLS_CRYPTO_DATA, Buffer.Buffer, &Buffer.Length, &Crypto->TlsState);

    QUIC_TEL_ASSERT(!IsClientInitial || ResultFlags != QUIC_TLS_RESULT_PENDING); // TODO - Support async for client Initial?

    if (ResultFlags != QUIC_TLS_RESULT_PENDING) {
        QuicCryptoProcessDataComplete(Crypto, ResultFlags, Buffer.Length);
    }

    return;

Error:

    QuicRecvBufferDrain(&Crypto->RecvBuffer, 0);
    QuicCryptoValidate(Crypto);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessAppData(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ uint32_t DataLength,
    _In_reads_bytes_(DataLength)
        const uint8_t* AppData
    )
{
    QUIC_STATUS Status;
    if (Crypto->TlsCallPending) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    QUIC_TLS_RESULT_FLAGS ResultFlags =
        QuicTlsProcessData(Crypto->TLS, QUIC_TLS_TICKET_DATA, AppData, &DataLength, &Crypto->TlsState);
    if (ResultFlags & QUIC_TLS_RESULT_ERROR) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    if (!(ResultFlags & QUIC_TLS_RESULT_PENDING)) {
        QuicCryptoProcessDataComplete(Crypto, ResultFlags, 0);
    }

    Status = QUIC_STATUS_SUCCESS;

Error:
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoGenerateNewKeys(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY** NewReadKey = &Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT_NEW];
    QUIC_PACKET_KEY** NewWriteKey = &Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT_NEW];

    //
    // Detect torn key updates; either both keys exist, or they don't.
    //
    QUIC_DBG_ASSERT(!((*NewReadKey == NULL) ^ (*NewWriteKey == NULL)));

    if (*NewReadKey == NULL) {
        //
        // Make New packet key.
        //
        Status =
            QuicPacketKeyUpdate(
                Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT],
                NewReadKey);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "Failed to update read packet key.");
            goto Error;
        }

        Status =
            QuicPacketKeyUpdate(
                Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT],
                NewWriteKey);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "Failed to update write packet key");
            goto Error;
        }
    }

Error:

    if (QUIC_FAILED(Status)) {
        QuicPacketKeyFree(*NewReadKey);
        *NewReadKey = NULL;
    } else {
        QuicTraceEvent(
            ConnNewPacketKeys,
            "[conn][%p] New packet keys created successfully.",
            Connection);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoUpdateKeyPhase(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN LocalUpdate
    )
{
    //
    // Free the old read key state (if it exists).
    //
    QUIC_PACKET_KEY** Old = &Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT_OLD];
    QuicPacketKeyFree(*Old);

    QUIC_PACKET_KEY** Current = &Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT];
    QUIC_PACKET_KEY** New = &Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT_NEW];

    //
    // Move the header key forward.
    //
    (*New)->HeaderKey = (*Current)->HeaderKey;
    //
    // Don't copy the header key backwards.
    //
    (*Current)->HeaderKey = NULL;

    //
    // Shift the current and new read keys down.
    //
    *Old = *Current;
    *Current = *New;
    *New = NULL;

    //
    // Free the old write key state (if it exists).
    //
    Old = &Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT_OLD];
    QuicPacketKeyFree(*Old);

    Current = &Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT];
    New = &Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT_NEW];

    //
    // Move the header key forward.
    //
    (*New)->HeaderKey = (*Current)->HeaderKey;
    //
    // Don't copy the header key backwards.
    //
    (*Current)->HeaderKey = NULL;

    //
    // Shift the current and new write keys down.
    //
    *Old = *Current;
    *Current = *New;
    *New = NULL;

    if (Connection->Stats.Misc.KeyUpdateCount < UINT32_MAX ) {
        Connection->Stats.Misc.KeyUpdateCount++;
    }

    QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];

    UNREFERENCED_PARAMETER(LocalUpdate);
    QuicTraceEvent(
        ConnKeyPhaseChange,
        "[conn][%p] Key phase change (locally initiated=%hhu).",
        Connection,
        LocalUpdate);

    PacketSpace->WriteKeyPhaseStartPacketNumber = Connection->Send.NextPacketNumber;
    PacketSpace->CurrentKeyPhase = !PacketSpace->CurrentKeyPhase;

    PacketSpace->AwaitingKeyPhaseConfirmation = TRUE;

    PacketSpace->CurrentKeyPhaseBytesSent = 0;
}
