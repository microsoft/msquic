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

CXPLAT_TLS_RECEIVE_TP_CALLBACK QuicConnReceiveTP;
CXPLAT_TLS_RECEIVE_TICKET_CALLBACK QuicConnRecvResumptionTicket;
CXPLAT_TLS_PEER_CERTIFICATE_RECEIVED_CALLBACK QuicConnPeerCertReceived;

CXPLAT_TLS_CALLBACKS QuicTlsCallbacks = {
    QuicConnReceiveTP,
    QuicConnRecvResumptionTicket,
    QuicConnPeerCertReceived
};

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

        CXPLAT_DBG_ASSERT(Crypto->UnAckedOffset <= Crypto->NextSendOffset);
    }
}

#if DEBUG
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoValidate(
    _In_ const QUIC_CRYPTO* Crypto
    )
{
    CXPLAT_DBG_ASSERT(Crypto->TlsState.BufferTotalLength >= Crypto->MaxSentLength);
    CXPLAT_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->UnAckedOffset);
    CXPLAT_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->NextSendOffset);
    CXPLAT_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->RecoveryNextOffset);
    CXPLAT_DBG_ASSERT(Crypto->MaxSentLength >= Crypto->RecoveryEndOffset);
    CXPLAT_DBG_ASSERT(Crypto->NextSendOffset >= Crypto->UnAckedOffset);
    CXPLAT_DBG_ASSERT(Crypto->TlsState.BufferLength + Crypto->UnAckedOffset == Crypto->TlsState.BufferTotalLength);
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
    CXPLAT_DBG_ASSERT(Crypto->Initialized == FALSE);
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
    BOOLEAN RecvBufferInitialized = FALSE;

    const QUIC_VERSION_INFO* VersionInfo = &QuicSupportedVersionList[0]; // Default to latest
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Connection->Stats.QuicVersion) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }

    CXPLAT_PASSIVE_CODE();

    QuicRangeInitialize(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        &Crypto->SparseAckRanges);

    Crypto->TlsState.BufferAllocLength = SendBufferLength;
    Crypto->TlsState.Buffer = CXPLAT_ALLOC_NONPAGED(SendBufferLength, QUIC_POOL_TLS_BUFFER);
    if (Crypto->TlsState.Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "crypto send buffer",
            SendBufferLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicRangeInitialize(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        &Crypto->SparseAckRanges);

    Status =
        QuicRecvBufferInitialize(
            &Crypto->RecvBuffer,
            InitialRecvBufferLength,
            QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE / 2,
            TRUE,
            NULL);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    RecvBufferInitialized = TRUE;

    if (QuicConnIsServer(Connection)) {
        CXPLAT_DBG_ASSERT(Connection->SourceCids.Next != NULL);
        QUIC_CID_HASH_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                Connection->SourceCids.Next,
                QUIC_CID_HASH_ENTRY,
                Link);

        HandshakeCid = SourceCid->CID.Data;
        HandshakeCidLength = SourceCid->CID.Length;

    } else {
        CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->DestCids));
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Connection->DestCids.Flink,
                QUIC_CID_LIST_ENTRY,
                Link);

        HandshakeCid = DestCid->CID.Data;
        HandshakeCidLength = DestCid->CID.Length;
    }

    Status =
        QuicPacketKeyCreateInitial(
            QuicConnIsServer(Connection),
            &VersionInfo->HkdfLabels,
            VersionInfo->Salt,
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
    CXPLAT_DBG_ASSERT(Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] != NULL);
    CXPLAT_DBG_ASSERT(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] != NULL);

    Crypto->Initialized = TRUE;
    QuicCryptoValidate(Crypto);

Exit:

    if (QUIC_FAILED(Status)) {
        for (size_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(Crypto->TlsState.ReadKeys[i]);
            Crypto->TlsState.ReadKeys[i] = NULL;
            QuicPacketKeyFree(Crypto->TlsState.WriteKeys[i]);
            Crypto->TlsState.WriteKeys[i] = NULL;
        }
        if (RecvBufferInitialized) {
            QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
        }
        if (Crypto->TlsState.Buffer != NULL) {
            CXPLAT_FREE(Crypto->TlsState.Buffer, QUIC_POOL_TLS_BUFFER);
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
    for (size_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
        QuicPacketKeyFree(Crypto->TlsState.ReadKeys[i]);
        Crypto->TlsState.ReadKeys[i] = NULL;
        QuicPacketKeyFree(Crypto->TlsState.WriteKeys[i]);
        Crypto->TlsState.WriteKeys[i] = NULL;
    }
    if (Crypto->TLS != NULL) {
        CxPlatTlsUninitialize(Crypto->TLS);
        Crypto->TLS = NULL;
    }
    if (Crypto->ResumptionTicket != NULL) {
        CXPLAT_FREE(Crypto->ResumptionTicket, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
        Crypto->ResumptionTicket = NULL;
    }
    if (Crypto->TlsState.NegotiatedAlpn != NULL &&
        QuicConnIsServer(QuicCryptoGetConnection(Crypto))) {
        if (Crypto->TlsState.NegotiatedAlpn != Crypto->TlsState.SmallAlpnBuffer) {
            CXPLAT_FREE(Crypto->TlsState.NegotiatedAlpn, QUIC_POOL_ALPN);
        }
        Crypto->TlsState.NegotiatedAlpn = NULL;
    }
    if (Crypto->Initialized) {
        QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
        QuicRangeUninitialize(&Crypto->SparseAckRanges);
        CXPLAT_FREE(Crypto->TlsState.Buffer, QUIC_POOL_TLS_BUFFER);
        Crypto->TlsState.Buffer = NULL;
        Crypto->Initialized = FALSE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoInitializeTls(
    _Inout_ QUIC_CRYPTO* Crypto,
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Params
    )
{
    QUIC_STATUS Status;
    CXPLAT_TLS_CONFIG TlsConfig = { 0 };
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    BOOLEAN IsServer = QuicConnIsServer(Connection);

    CXPLAT_DBG_ASSERT(Params != NULL);
    CXPLAT_DBG_ASSERT(SecConfig != NULL);
    CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);

    Crypto->MaxSentLength = 0;
    Crypto->UnAckedOffset = 0;
    Crypto->NextSendOffset = 0;
    Crypto->RecoveryNextOffset = 0;
    Crypto->RecoveryEndOffset = 0;
    Crypto->InRecovery = FALSE;

    Crypto->TlsState.BufferLength = 0;
    Crypto->TlsState.BufferTotalLength = 0;

    TlsConfig.IsServer = IsServer;
    if (IsServer) {
        TlsConfig.AlpnBuffer = Crypto->TlsState.NegotiatedAlpn;
        TlsConfig.AlpnBufferLength = 1 + Crypto->TlsState.NegotiatedAlpn[0];
    } else {
        TlsConfig.AlpnBuffer = Connection->Configuration->AlpnList;
        TlsConfig.AlpnBufferLength = Connection->Configuration->AlpnListLength;
    }
    TlsConfig.SecConfig = SecConfig;
    TlsConfig.Connection = Connection;
    TlsConfig.ResumptionTicketBuffer = Crypto->ResumptionTicket;
    TlsConfig.ResumptionTicketLength = Crypto->ResumptionTicketLength;
    if (QuicConnIsClient(Connection)) {
        TlsConfig.ServerName = Connection->RemoteServerName;
    }
    TlsConfig.TlsSecrets = Connection->TlsSecrets;

    TlsConfig.HkdfLabels = &QuicSupportedVersionList[0].HkdfLabels; // Default to latest
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Connection->Stats.QuicVersion) {
            TlsConfig.HkdfLabels = &QuicSupportedVersionList[i].HkdfLabels;
            break;
        }
    }

    TlsConfig.TPType =
        Connection->Stats.QuicVersion != QUIC_VERSION_DRAFT_29 ?
            TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS :
            TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS_DRAFT;
    TlsConfig.LocalTPBuffer =
        QuicCryptoTlsEncodeTransportParameters(
            Connection,
            QuicConnIsServer(Connection),
            Params,
            (Connection->State.TestTransportParameterSet ?
                &Connection->TestTransportParameter : NULL),
            &TlsConfig.LocalTPLength);
    if (TlsConfig.LocalTPBuffer == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (Crypto->TLS != NULL) {
        CxPlatTlsUninitialize(Crypto->TLS);
        Crypto->TLS = NULL;
    }

    Status = CxPlatTlsInitialize(&TlsConfig, &Crypto->TlsState, &Crypto->TLS);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "CxPlatTlsInitialize");
        CXPLAT_FREE(TlsConfig.LocalTPBuffer, QUIC_POOL_TLS_TRANSPARAMS);
        goto Error;
    }

    Crypto->ResumptionTicket = NULL; // Owned by TLS now.
    Crypto->ResumptionTicketLength = 0;
    Status = QuicCryptoProcessData(Crypto, !IsServer);
    // This is if SetParam comes directly to this func
    // if (Crypto->TicketValidationPending) {
    //     Crypto->ResumptionTicket = TlsConfig.ResumptionTicketBuffer;
    //     Crypto->ResumptionTicketLength = TlsConfig.ResumptionTicketLength;
    // }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoReset(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    CXPLAT_DBG_ASSERT(QuicConnIsClient(QuicCryptoGetConnection(Crypto)));
    CXPLAT_TEL_ASSERT(Crypto->RecvTotalConsumed == 0);

    Crypto->MaxSentLength = 0;
    Crypto->UnAckedOffset = 0;
    Crypto->NextSendOffset = 0;
    Crypto->RecoveryNextOffset = 0;
    Crypto->RecoveryEndOffset = 0;
    Crypto->InRecovery = FALSE;

    QuicSendSetSendFlag(
        &QuicCryptoGetConnection(Crypto)->Send,
        QUIC_CONN_SEND_FLAG_CRYPTO);

    QuicCryptoValidate(Crypto);
}

QUIC_STATUS
QuicCryptoOnVersionChange(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    const uint8_t* HandshakeCid;
    uint8_t HandshakeCidLength;

    if (!Crypto->Initialized) {
        //
        // Crypto is not initialized yet, so no need to set keys.
        //
        return QUIC_STATUS_SUCCESS;
    }

    const QUIC_VERSION_INFO* VersionInfo = &QuicSupportedVersionList[0]; // Default to latest
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Connection->Stats.QuicVersion) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }

    if (Crypto->TLS) {
        //
        // If TLS has been initialized, then it needs to have HKDF
        // labels updated.
        //
        CxPlatTlsUpdateHkdfLabels(Crypto->TLS, &VersionInfo->HkdfLabels);
    }

    if (QuicConnIsServer(Connection)) {
        CXPLAT_DBG_ASSERT(Connection->SourceCids.Next != NULL);
        QUIC_CID_HASH_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                Connection->SourceCids.Next,
                QUIC_CID_HASH_ENTRY,
                Link);

        HandshakeCid = SourceCid->CID.Data;
        HandshakeCidLength = SourceCid->CID.Length;

    } else {
        CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->DestCids));
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Connection->DestCids.Flink,
                QUIC_CID_LIST_ENTRY,
                Link);

        HandshakeCid = DestCid->CID.Data;
        HandshakeCidLength = DestCid->CID.Length;
    }

    if (Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] != NULL) {
        CXPLAT_FRE_ASSERT(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] != NULL);
        QuicPacketKeyFree(Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL]);
        QuicPacketKeyFree(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL]);
        Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] = NULL;
        Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] = NULL;
    }

    Status =
        QuicPacketKeyCreateInitial(
            QuicConnIsServer(Connection),
            &VersionInfo->HkdfLabels,
            VersionInfo->Salt,
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
        QuicConnFatalError(Connection, Status, "New version key OOM");
        goto Exit;
    }
    CXPLAT_DBG_ASSERT(Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] != NULL);
    CXPLAT_DBG_ASSERT(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] != NULL);

    QuicCryptoValidate(Crypto);

Exit:

    if (QUIC_FAILED(Status)) {
        for (size_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(Crypto->TlsState.ReadKeys[i]);
            Crypto->TlsState.ReadKeys[i] = NULL;
            QuicPacketKeyFree(Crypto->TlsState.WriteKeys[i]);
            Crypto->TlsState.WriteKeys[i] = NULL;
        }
    }
    return Status;
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
    CXPLAT_DBG_ASSERT(Path->Binding != NULL);
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
        (uint8_t)KeyType);

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

    CXPLAT_DBG_ASSERT(Connection->Packets[EncryptLevel] != NULL);
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
    CXPLAT_DBG_ASSERT(BufferOffset != 0);
    CXPLAT_DBG_ASSERT(Crypto->MaxSentLength >= BufferOffset);
    if (Crypto->NextSendOffset < BufferOffset) {
        Crypto->NextSendOffset = BufferOffset;
    }
    if (Crypto->RecoveryNextOffset < BufferOffset) {
        Crypto->RecoveryNextOffset = BufferOffset;
    }
    if (Crypto->UnAckedOffset < BufferOffset) {
        uint32_t DrainLength = BufferOffset - Crypto->UnAckedOffset;
        CXPLAT_DBG_ASSERT(DrainLength <= (uint32_t)Crypto->TlsState.BufferLength);
        if ((uint32_t)Crypto->TlsState.BufferLength > DrainLength) {
            Crypto->TlsState.BufferLength -= (uint16_t)DrainLength;
            CxPlatMoveMemory(
                Crypto->TlsState.Buffer,
                Crypto->TlsState.Buffer + DrainLength,
                Crypto->TlsState.BufferLength);
        } else {
            Crypto->TlsState.BufferLength = 0;
        }
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
    }

    if (Crypto->TlsState.BufferOffsetHandshake != 0 &&
        SendOffset >= Crypto->TlsState.BufferOffsetHandshake) {
        return QUIC_ENCRYPT_LEVEL_HANDSHAKE;
    }

    return QUIC_ENCRYPT_LEVEL_INITIAL;
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
    CXPLAT_DBG_ASSERT(*FramePayloadBytes > 0);
    CXPLAT_DBG_ASSERT(CryptoOffset >= EncryptLevelStart);
    CXPLAT_DBG_ASSERT(CryptoOffset <= Crypto->TlsState.BufferTotalLength);
    CXPLAT_DBG_ASSERT(CryptoOffset >= (Crypto->TlsState.BufferTotalLength - Crypto->TlsState.BufferLength));

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
    Frame.Length -= LengthFieldByteCount;

    //
    // Even if there is room in the buffer, we can't write more data than is
    // currently queued.
    //
    if (Frame.Length > *FramePayloadBytes) {
        Frame.Length = *FramePayloadBytes;
    }

    CXPLAT_DBG_ASSERT(Frame.Length > 0);
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
    CXPLAT_FRE_ASSERT(
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
        QUIC_SUBRANGE* Sack;
        if (Left == Crypto->MaxSentLength) {
            //
            // Transmitting new bytes; no such SACK can exist.
            //
            Sack = NULL;
        } else {
            uint32_t i = 0;
            while ((Sack = QuicRangeGetSafe(&Crypto->SparseAckRanges, i++)) != NULL &&
                Sack->Low < (uint64_t)Left) {
                CXPLAT_DBG_ASSERT(Sack->Low + Sack->Count <= (uint64_t)Left);
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

        CXPLAT_DBG_ASSERT(Right >= Left);

        uint32_t EncryptLevelStart;
        uint32_t PacketTypeRight;
        if (QuicCryptoGetConnection(Crypto)->Stats.QuicVersion == QUIC_VERSION_2) {
            switch (Builder->PacketType) {
            case QUIC_INITIAL_V2:
                EncryptLevelStart = 0;
                if (Crypto->TlsState.BufferOffsetHandshake != 0) {
                    PacketTypeRight = Crypto->TlsState.BufferOffsetHandshake;
                } else {
                    PacketTypeRight = Crypto->TlsState.BufferTotalLength;
                }
                break;
            case QUIC_0_RTT_PROTECTED_V2:
                CXPLAT_FRE_ASSERT(FALSE);
                EncryptLevelStart = 0;
                PacketTypeRight = 0; // To get build to stop complaining.
                break;
            case QUIC_HANDSHAKE_V2:
                CXPLAT_DBG_ASSERT(Crypto->TlsState.BufferOffsetHandshake != 0);
                CXPLAT_DBG_ASSERT(Left >= Crypto->TlsState.BufferOffsetHandshake);
                EncryptLevelStart = Crypto->TlsState.BufferOffsetHandshake;
                PacketTypeRight =
                    Crypto->TlsState.BufferOffset1Rtt == 0 ?
                        Crypto->TlsState.BufferTotalLength : Crypto->TlsState.BufferOffset1Rtt;
                break;
            default:
                CXPLAT_DBG_ASSERT(Crypto->TlsState.BufferOffset1Rtt != 0);
                CXPLAT_DBG_ASSERT(Left >= Crypto->TlsState.BufferOffset1Rtt);
                EncryptLevelStart = Crypto->TlsState.BufferOffset1Rtt;
                PacketTypeRight = Crypto->TlsState.BufferTotalLength;
                break;
            }
        } else {
            switch (Builder->PacketType) {
            case QUIC_INITIAL_V1:
                EncryptLevelStart = 0;
                if (Crypto->TlsState.BufferOffsetHandshake != 0) {
                    PacketTypeRight = Crypto->TlsState.BufferOffsetHandshake;
                } else {
                    PacketTypeRight = Crypto->TlsState.BufferTotalLength;
                }
                break;
            case QUIC_0_RTT_PROTECTED_V1:
                CXPLAT_FRE_ASSERT(FALSE);
                EncryptLevelStart = 0;
                PacketTypeRight = 0; // To get build to stop complaining.
                break;
            case QUIC_HANDSHAKE_V1:
                CXPLAT_DBG_ASSERT(Crypto->TlsState.BufferOffsetHandshake != 0);
                CXPLAT_DBG_ASSERT(Left >= Crypto->TlsState.BufferOffsetHandshake);
                EncryptLevelStart = Crypto->TlsState.BufferOffsetHandshake;
                PacketTypeRight =
                    Crypto->TlsState.BufferOffset1Rtt == 0 ?
                        Crypto->TlsState.BufferTotalLength : Crypto->TlsState.BufferOffset1Rtt;
                break;
            default:
                CXPLAT_DBG_ASSERT(Crypto->TlsState.BufferOffset1Rtt != 0);
                CXPLAT_DBG_ASSERT(Left >= Crypto->TlsState.BufferOffset1Rtt);
                EncryptLevelStart = Crypto->TlsState.BufferOffset1Rtt;
                PacketTypeRight = Crypto->TlsState.BufferTotalLength;
                break;
            }
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

        CXPLAT_DBG_ASSERT(Right > Left);

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
            CXPLAT_DBG_ASSERT(Crypto->RecoveryNextOffset <= Right);
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
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET);

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

    if (!QuicCryptoHasPendingCryptoFrame(Crypto)) {
        //
        // Likely an ACK after retransmission got us into this state. Just
        // remove the send flag and continue on.
        //
        Connection->Send.SendFlags &= ~QUIC_CONN_SEND_FLAG_CRYPTO;
        return TRUE;
    }

    if ((Connection->Stats.QuicVersion != QUIC_VERSION_2 && Builder->PacketType !=
            QuicEncryptLevelToPacketTypeV1(QuicCryptoGetNextEncryptLevel(Crypto))) ||
        (Connection->Stats.QuicVersion == QUIC_VERSION_2 && Builder->PacketType !=
            QuicEncryptLevelToPacketTypeV2(QuicCryptoGetNextEncryptLevel(Crypto)))) {
        //
        // Nothing to send in this packet / encryption level, just continue on.
        //
        return TRUE;
    }

    if (QuicConnIsClient(Connection) &&
        Builder->Key == Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_HANDSHAKE]) {
        CXPLAT_DBG_ASSERT(Builder->Key);
        //
        // Per spec, client MUST discard Initial keys when it starts
        // encrypting packets with handshake keys.
        //
        QuicCryptoDiscardKeys(Crypto, QUIC_PACKET_KEY_INITIAL);
    }

    uint8_t PrevFrameCount = Builder->Metadata->FrameCount;

    uint16_t AvailableBufferLength =
        (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;

    QuicCryptoWriteCryptoFrames(
        Crypto,
        Builder,
        &Builder->DatagramLength,
        AvailableBufferLength,
        Builder->Datagram->Buffer);

    if (!QuicCryptoHasPendingCryptoFrame(Crypto)) {
        Connection->Send.SendFlags &= ~QUIC_CONN_SEND_FLAG_CRYPTO;
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
    }

    if (Start < Crypto->UnAckedOffset) {
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

                }
                //
                // The SACK only covers the beginning of the 'lost'
                // range. Move Start forward to the end of the SACK.
                //
                Start = Sack->Low + Sack->Count;

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

    CXPLAT_DBG_ASSERT(FollowingOffset <= Crypto->TlsState.BufferTotalLength);

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
            CXPLAT_DBG_ASSERT(DrainLength <= (uint32_t)Crypto->TlsState.BufferLength);
            if ((uint32_t)Crypto->TlsState.BufferLength > DrainLength) {
                Crypto->TlsState.BufferLength -= (uint16_t)DrainLength;
                CxPlatMoveMemory(
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
        }

        if (SacksUpdated) {

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

        CXPLAT_DBG_ASSERT(KeyType <= Crypto->TlsState.ReadKey);
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
    if (QUIC_FAILED(Status) || !DataReady) {
        goto Error;
    }

    Status = QuicCryptoProcessData(Crypto, FALSE);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    if (Connection->State.ClosedLocally) {
        //
        // If processing the received frame caused us to close the
        // connection, make sure to stop processing anything else in the
        // packet.
        //
        Status = QUIC_STATUS_INVALID_STATE;
    }

Error:

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
    CXPLAT_DBG_ASSERT(QuicConnIsClient(Connection));

    if (!QuicCryptoTlsDecodeTransportParameters(
            Connection,
            TRUE,
            TPBuffer,
            TPLength,
            &Connection->PeerTransportParams)) {
        return FALSE;
    }

    if (QUIC_FAILED(QuicConnProcessPeerTransportParameters(Connection, FALSE))) {
        return FALSE;
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoProcessTlsCompletion(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_ERROR) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Crypto->TlsState.AlertCode,
            "Received alert from TLS");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_CRYPTO_ERROR(0xFF & Crypto->TlsState.AlertCode));
        return;
    }

    QuicCryptoValidate(Crypto);

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT) {
        QuicTraceLogConnInfo(
            ZeroRttAccepted,
            Connection,
            "0-RTT accepted");
        CXPLAT_TEL_ASSERT(Crypto->TlsState.EarlyDataState == CXPLAT_TLS_EARLY_DATA_ACCEPTED);
    }

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_EARLY_DATA_REJECT) {
        QuicTraceLogConnInfo(
            ZeroRttRejected,
            Connection,
            "0-RTT rejected");
        CXPLAT_TEL_ASSERT(Crypto->TlsState.EarlyDataState != CXPLAT_TLS_EARLY_DATA_ACCEPTED);
        if (QuicConnIsClient(Connection)) {
            QuicCryptoDiscardKeys(Crypto, QUIC_PACKET_KEY_0_RTT);
            QuicLossDetectionOnZeroRttRejected(&Connection->LossDetection);
        } else {
            QuicConnDiscardDeferred0Rtt(Connection);
        }
    }

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED) {
        QuicTraceEvent(
            ConnWriteKeyUpdated,
            "[conn][%p] Write Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.WriteKey);
        CXPLAT_DBG_ASSERT(Crypto->TlsState.WriteKey <= QUIC_PACKET_KEY_1_RTT);
        _Analysis_assume_(Crypto->TlsState.WriteKey >= 0);
        CXPLAT_TEL_ASSERT(Crypto->TlsState.WriteKeys[Crypto->TlsState.WriteKey] != NULL);
        if (Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
            if (QuicConnIsClient(Connection)) {
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

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_READ_KEY_UPDATED) {
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
        CXPLAT_DBG_ASSERT(Crypto->TlsState.ReadKey <= QUIC_PACKET_KEY_1_RTT);
        _Analysis_assume_(Crypto->TlsState.ReadKey >= 0);
        CXPLAT_TEL_ASSERT(Crypto->TlsState.WriteKey >= Crypto->TlsState.ReadKey);
        CXPLAT_TEL_ASSERT(Crypto->TlsState.ReadKeys[Crypto->TlsState.ReadKey] != NULL);

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
            Connection->Stats.Timing.InitialFlightEnd = CxPlatTimeUs64();
        }

        if (Crypto->TlsState.ReadKey == QUIC_PACKET_KEY_1_RTT) {
            //
            // Once TLS is consuming 1-RTT data, we are done with the Handshake
            // flight.
            //
            Connection->Stats.Timing.HandshakeFlightEnd = CxPlatTimeUs64();
        }
    }

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_DATA) {
        //
        // Parse the client initial to populate the TlsSecrets with the
        // ClientRandom
        //
        if (Connection->TlsSecrets != NULL &&
            QuicConnIsClient(Connection) &&
            Crypto->TlsState.WriteKey == QUIC_PACKET_KEY_INITIAL &&
            Crypto->TlsState.BufferLength > 0) {
            QUIC_NEW_CONNECTION_INFO Info = { 0 };
            QuicCryptoTlsReadInitial(
                Connection,
                Crypto->TlsState.Buffer,
                Crypto->TlsState.BufferLength,
                &Info,
                Connection->TlsSecrets);
            //
            // Connection is done with TlsSecrets, clean up.
            //
            Connection->TlsSecrets = NULL;
        }
        QuicSendSetSendFlag(
            &QuicCryptoGetConnection(Crypto)->Send,
            QUIC_CONN_SEND_FLAG_CRYPTO);
        QuicCryptoDumpSendState(Crypto);
        QuicCryptoValidate(Crypto);
    }

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE) {
        CXPLAT_DBG_ASSERT(!(Crypto->ResultFlags & CXPLAT_TLS_RESULT_ERROR));
        CXPLAT_TEL_ASSERT(!Connection->State.Connected);

        QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);

        //
        // We should have the 1-RTT keys by connection complete time.
        //
        CXPLAT_TEL_ASSERT(Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT] != NULL);
        CXPLAT_TEL_ASSERT(Crypto->TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL);

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

            //
            // Take this opportinuty to clean up the client chosen initial CID.
            // It will be the second one in the list.
            //
            CXPLAT_DBG_ASSERT(Connection->SourceCids.Next != NULL);
            CXPLAT_DBG_ASSERT(Connection->SourceCids.Next->Next != NULL);
            CXPLAT_DBG_ASSERT(Connection->SourceCids.Next->Next != NULL);
            CXPLAT_DBG_ASSERT(Connection->SourceCids.Next->Next->Next == NULL);
            QUIC_CID_HASH_ENTRY* InitialSourceCid =
                CXPLAT_CONTAINING_RECORD(
                    Connection->SourceCids.Next->Next,
                    QUIC_CID_HASH_ENTRY,
                    Link);
            CXPLAT_DBG_ASSERT(InitialSourceCid->CID.IsInitial);
            Connection->SourceCids.Next->Next = Connection->SourceCids.Next->Next->Next;
            CXPLAT_DBG_ASSERT(!InitialSourceCid->CID.IsInLookupTable);
            QuicTraceEvent(
                ConnSourceCidRemoved,
                "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                Connection,
                InitialSourceCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(InitialSourceCid->CID.Length, InitialSourceCid->CID.Data));
            CXPLAT_FREE(InitialSourceCid, QUIC_POOL_CIDHASH);
        }

        //
        // Only set the connected flag after we do the confirmation code path
        // above so that TLS state isn't prematurely destroyed (before the
        // CONNECTED event is indicated to the app).
        //
        Connection->State.Connected = TRUE;
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_CONNECTED);

        QuicConnGenerateNewSourceCids(Connection, FALSE);

        CXPLAT_DBG_ASSERT(Crypto->TlsState.NegotiatedAlpn != NULL);
        if (QuicConnIsClient(Connection)) {
            //
            // Currently, NegotiatedAlpn points into TLS state memory, which
            // doesn't live as long as the connection. Update it to point to the
            // configuration state memory instead.
            //
            Crypto->TlsState.NegotiatedAlpn =
                CxPlatTlsAlpnFindInList(
                    Connection->Configuration->AlpnListLength,
                    Connection->Configuration->AlpnList,
                    Crypto->TlsState.NegotiatedAlpn[0],
                    Crypto->TlsState.NegotiatedAlpn + 1);
            CXPLAT_TEL_ASSERT(Crypto->TlsState.NegotiatedAlpn != NULL);
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
        if (Crypto->TlsState.SessionResumed) {
            QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_RESUMED);
        }
        Connection->Stats.ResumptionSucceeded = Crypto->TlsState.SessionResumed;

        //
        // A handshake complete means the peer has been validated. Trigger MTU
        // discovery on path.
        //
        CXPLAT_DBG_ASSERT(Connection->PathsCount == 1);
        QUIC_PATH* Path = &Connection->Paths[0];
        QuicMtuDiscoveryPeerValidated(&Path->MtuDiscovery, Connection);

        if (QuicConnIsServer(Connection) &&
            Crypto->TlsState.BufferOffset1Rtt != 0 &&
            Crypto->UnAckedOffset == Crypto->TlsState.BufferTotalLength) {
            QuicConnCleanupServerResumptionState(Connection);
        }
    }

    QuicCryptoValidate(Crypto);

    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_READ_KEY_UPDATED) {
        QuicConnFlushDeferred(Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoProcessDataComplete(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ uint32_t RecvBufferConsumed
    )
{
    if (RecvBufferConsumed != 0 && !Crypto->TicketValidationPending) {
        Crypto->RecvTotalConsumed += RecvBufferConsumed;
        QuicTraceLogConnVerbose(
            DrainCrypto,
            QuicCryptoGetConnection(Crypto),
            "Draining %u crypto bytes",
            RecvBufferConsumed);
        QuicRecvBufferDrain(&Crypto->RecvBuffer, RecvBufferConsumed);
    }

    QuicCryptoValidate(Crypto);

    if (!Crypto->CertValidationPending && !Crypto->TicketValidationPending) {
        QuicCryptoProcessTlsCompletion(Crypto);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoCustomCertValidationComplete(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN Result
    )
{
    if (!Crypto->CertValidationPending) {
        return;
    }

    Crypto->CertValidationPending = FALSE;
    if (Result) {
        QuicTraceLogConnInfo(
            CustomCertValidationSuccess,
            QuicCryptoGetConnection(Crypto),
            "Custom cert validation succeeded");
        QuicCryptoProcessTlsCompletion(Crypto);

    } else {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            QuicCryptoGetConnection(Crypto),
            "Custom cert validation failed.");
        QuicConnTransportError(
            QuicCryptoGetConnection(Crypto),
            QUIC_ERROR_CRYPTO_ERROR(0xFF & CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE)); //
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoCustomTicketValidationComplete(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN Result
    )
{
    if (!Crypto->TicketValidationPending) {
        return;
    }

    Crypto->TicketValidationPending = FALSE;
    if (Result) {
        //1.         
        // QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
        // QUIC_CONFIGURATION* Configuration = Connection->Configuration;
        // Connection->Configuration = NULL;
        // QuicConnSetConfiguration(Connection, Configuration);
        // ->    Connection->Crypto.TlsState.ClientAlpnList = NULL;
        //       Connection->Crypto.TlsState.ClientAlpnListLength = 0;
        //       affects processing

        //
        // 2.
        QUIC_TRANSPORT_PARAMETERS LocalTP = { 0 };
        if (Crypto->TLS != NULL) {
            CxPlatTlsUninitialize(Crypto->TLS);
            Crypto->TLS = NULL;
        }
        QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
        QUIC_CONFIGURATION* Configuration = Connection->Configuration;
        QuicConnGenerateLocalTransportParameters(Connection, &LocalTP);
        QuicCryptoInitializeTls(Crypto, Configuration->SecurityConfig, &LocalTP);
        //QuicCryptoInitializeTls(Crypto, Configuration->SecurityConfig, Connection->HandshakeTP);

        // 3.
        // QuicCryptoProcessData(Crypto, FALSE);
        // -> CxPlatTlsProcessData -> SSL_do_handshake returns error

    } else {
        // TODO: start normal handshake.
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessData(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN IsClientInitial
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t BufferCount = 1;
    QUIC_BUFFER Buffer;

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
        CXPLAT_TEL_ASSERT(DataAvailable);
        CXPLAT_DBG_ASSERT(BufferCount == 1);

        QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);

        Buffer.Length =
            QuicCryptoTlsGetCompleteTlsMessagesLength(
                Buffer.Buffer, Buffer.Length);
        if (Buffer.Length == 0) {
            QuicTraceLogConnVerbose(
                CryptoNotReady,
                Connection,
                "No complete TLS messages to process");
            goto Error;
        }

        if (QuicConnIsServer(Connection) && !Connection->State.ListenerAccepted) {
            //
            // Preprocess the TLS ClientHello to find the ALPN (and optionally
            // SNI) to match the connection to a listener.
            //
            CXPLAT_DBG_ASSERT(BufferOffset == 0);
            QUIC_NEW_CONNECTION_INFO Info = {0};
            Status =
                QuicCryptoTlsReadInitial(
                    Connection,
                    Buffer.Buffer,
                    Buffer.Length,
                    &Info,
                    //
                    // On server, TLS is initialized before the listener
                    // is told about the connection, so TlsSecrets is still
                    // NULL.
                    //
                    NULL
                    );
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

            Status =
                QuicConnProcessPeerTransportParameters(Connection, FALSE);
            if (QUIC_FAILED(Status)) {
                //
                // Communicate error up the stack to perform Incompatible
                // Version Negotiation.
                //
                goto Error;
            }

            QuicRecvBufferDrain(&Crypto->RecvBuffer, 0);
            QuicCryptoValidate(Crypto);

            Info.QuicVersion = Connection->Stats.QuicVersion;
            Info.LocalAddress = &Connection->Paths[0].Route.LocalAddress;
            Info.RemoteAddress = &Connection->Paths[0].Route.RemoteAddress;
            Info.CryptoBufferLength = Buffer.Length;
            Info.CryptoBuffer = Buffer.Buffer;

            QuicBindingAcceptConnection(
                Connection->Paths[0].Binding,
                Connection,
                &Info);
            return Status;
        }
    }

    CXPLAT_DBG_ASSERT(Crypto->TLS != NULL);
    if (Crypto->TLS == NULL) {
        //
        // The listener still hasn't given us the security config to initialize
        // TLS with yet.
        //
        goto Error;
    }

    QuicCryptoValidate(Crypto);

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    fprintf(stderr, "%p QuicCryptoProcessData -> CxPlatTlsProcessData Length: %d\n", Connection, Buffer.Length);
    Crypto->ResultFlags =
        CxPlatTlsProcessData(
            Crypto->TLS,
            CXPLAT_TLS_CRYPTO_DATA,
            Buffer.Buffer,
            &Buffer.Length,
            &Crypto->TlsState);
    fprintf(stderr, "CxPlatTlsProcessData ResultFlags:%d\n", Crypto->ResultFlags);

    QuicCryptoProcessDataComplete(Crypto, Buffer.Length);

    return Status;

Error:

    QuicRecvBufferDrain(&Crypto->RecvBuffer, 0);
    QuicCryptoValidate(Crypto);

    return Status;
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

    QUIC_CONNECTION* Connection = QuicCryptoGetConnection(Crypto);
    fprintf(stderr, "%p QuicCryptoProcessAppData (ticket) -> CxPlatTlsProcessData Length: %d\n", Connection, DataLength);
    Crypto->ResultFlags =
        CxPlatTlsProcessData(
            Crypto->TLS,
            CXPLAT_TLS_TICKET_DATA,
            AppData,
            &DataLength,
            &Crypto->TlsState);
    if (Crypto->ResultFlags & CXPLAT_TLS_RESULT_ERROR) {
        if (Crypto->TlsState.AlertCode != 0) {
            Status = QUIC_STATUS_TLS_ALERT(Crypto->TlsState.AlertCode);
        } else {
            Status = QUIC_STATUS_INTERNAL_ERROR;
        }
        goto Error;
    }

    QuicCryptoProcessDataComplete(Crypto, 0);

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

    const QUIC_VERSION_INFO* VersionInfo = &QuicSupportedVersionList[0]; // Default to latest
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Connection->Stats.QuicVersion) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }

    //
    // Detect torn key updates; either both keys exist, or they don't.
    //
    CXPLAT_DBG_ASSERT(!((*NewReadKey == NULL) ^ (*NewWriteKey == NULL)));

    if (*NewReadKey == NULL) {
        //
        // Make New packet key.
        //
        Status =
            QuicPacketKeyUpdate(
                &VersionInfo->HkdfLabels,
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
                &VersionInfo->HkdfLabels,
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

    //
    // Reset the read packet space so any new packet will be properly detected.
    //
    PacketSpace->ReadKeyPhaseStartPacketNumber = UINT64_MAX;

    PacketSpace->AwaitingKeyPhaseConfirmation = TRUE;

    PacketSpace->CurrentKeyPhaseBytesSent = 0;
}

QUIC_STATUS
QuicCryptoEncodeServerTicket(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint32_t QuicVersion,
    _In_ uint32_t AppDataLength,
    _In_reads_bytes_opt_(AppDataLength)
        const uint8_t* const AppResumptionData,
    _In_ const QUIC_TRANSPORT_PARAMETERS* HandshakeTP,
    _In_ uint8_t AlpnLength,
    _In_reads_bytes_(AlpnLength)
        const uint8_t* const NegotiatedAlpn,
    _Outptr_result_buffer_(*TicketLength)
        uint8_t** Ticket,
    _Out_ uint32_t* TicketLength
    )
{
    QUIC_STATUS Status;
    uint32_t EncodedTPLength = 0;
    uint8_t* TicketBuffer = NULL;
    const uint8_t* EncodedHSTP = NULL;

    *Ticket = NULL;
    *TicketLength = 0;

    //
    // Don't use a deep copy here because only a subset of
    // transport parameters are copied.
    //
    QUIC_TRANSPORT_PARAMETERS HSTPCopy = *HandshakeTP;
    HSTPCopy.Flags &= (
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI);

    EncodedHSTP =
        QuicCryptoTlsEncodeTransportParameters(
            Connection,
            TRUE,
            &HSTPCopy,
            NULL,
            &EncodedTPLength);
    if (EncodedHSTP == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Adjust TP buffer for TLS header, if present.
    //
    EncodedTPLength -= CxPlatTlsTPHeaderSize;

    uint32_t TotalTicketLength =
        (uint32_t)(QuicVarIntSize(CXPLAT_TLS_RESUMPTION_TICKET_VERSION) +
        sizeof(QuicVersion) +
        QuicVarIntSize(AlpnLength) +
        QuicVarIntSize(EncodedTPLength) +
        QuicVarIntSize(AppDataLength) +
        AlpnLength +
        EncodedTPLength +
        AppDataLength);

    TicketBuffer = CXPLAT_ALLOC_NONPAGED(TotalTicketLength, QUIC_POOL_SERVER_CRYPTO_TICKET);
    if (TicketBuffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Server resumption ticket",
            TotalTicketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Encoded ticket format is as follows:
    //   Ticket Version (QUIC_VAR_INT) [1..4]
    //   Quic Version (network byte order) [4]
    //   Negotiated ALPN length (QUIC_VAR_INT) [1..2]
    //   Transport Parameters length (QUIC_VAR_INT) [1..2]
    //   App Ticket length (QUIC_VAR_INT) [1..2]
    //   Negotiated ALPN [...]
    //   Transport Parameters [...]
    //   App Ticket (omitted if length is zero) [...]
    //

    _Analysis_assume_(sizeof(*TicketBuffer) >= 8);
    uint8_t* TicketCursor = QuicVarIntEncode(CXPLAT_TLS_RESUMPTION_TICKET_VERSION, TicketBuffer);
    CxPlatCopyMemory(TicketCursor, &QuicVersion, sizeof(QuicVersion));
    TicketCursor += sizeof(QuicVersion);
    TicketCursor = QuicVarIntEncode(AlpnLength, TicketCursor);
    TicketCursor = QuicVarIntEncode(EncodedTPLength, TicketCursor);
    TicketCursor = QuicVarIntEncode(AppDataLength, TicketCursor);
    CxPlatCopyMemory(TicketCursor, NegotiatedAlpn, AlpnLength);
    TicketCursor += AlpnLength;
    CxPlatCopyMemory(TicketCursor, EncodedHSTP + CxPlatTlsTPHeaderSize, EncodedTPLength);
    TicketCursor += EncodedTPLength;
    if (AppDataLength > 0) {
        CxPlatCopyMemory(TicketCursor, AppResumptionData, AppDataLength);
        TicketCursor += AppDataLength;
    }
    CXPLAT_DBG_ASSERT(TicketCursor == TicketBuffer + TotalTicketLength);

    *Ticket = TicketBuffer;
    *TicketLength = TotalTicketLength;

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (EncodedHSTP != NULL) {
        CXPLAT_FREE(EncodedHSTP, QUIC_POOL_TLS_TRANSPARAMS);
    }

    return Status;
}

QUIC_STATUS
QuicCryptoDecodeServerTicket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TicketLength,
    _In_reads_bytes_(TicketLength)
        const uint8_t* Ticket,
    _In_ const uint8_t* AlpnList,
    _In_ uint16_t AlpnListLength,
    _Out_ QUIC_TRANSPORT_PARAMETERS* DecodedTP,
    _Outptr_result_buffer_maybenull_(*AppDataLength)
        const uint8_t** AppData,
    _Out_ uint32_t* AppDataLength
    )
{
    QUIC_STATUS Status = QUIC_STATUS_INVALID_PARAMETER;
    uint16_t Offset = 0;
    QUIC_VAR_INT TicketVersion = 0, AlpnLength = 0, TPLength = 0, AppTicketLength = 0;

    *AppData = NULL;
    *AppDataLength = 0;

    if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &TicketVersion)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket version failed to decode");
        goto Error;
    }
    if (TicketVersion != CXPLAT_TLS_RESUMPTION_TICKET_VERSION) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket version unsupported");
        goto Error;
    }

    if (TicketLength < Offset + sizeof(uint32_t)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket too short to hold QUIC version");
        goto Error;
    }

    uint32_t QuicVersion;
    memcpy(&QuicVersion, Ticket + Offset, sizeof(QuicVersion));
    if (!QuicVersionNegotiationExtIsVersionClientSupported(Connection, QuicVersion)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket for different QUIC version");
        goto Error;
    }
    Offset += sizeof(QuicVersion);

    if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &AlpnLength)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket ALPN length failed to decode");
        goto Error;
    }

    if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &TPLength)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket TP length failed to decode");
        goto Error;
    }

    if (!QuicVarIntDecode(TicketLength, Ticket, &Offset, &AppTicketLength)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket app data length failed to decode");
        goto Error;
    }

    if (TicketLength < Offset + AlpnLength) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket too small for ALPN");
        goto Error;
    }

    if (CxPlatTlsAlpnFindInList(AlpnListLength, AlpnList, (uint8_t)AlpnLength, Ticket + Offset) == NULL) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket ALPN not present in ALPN list");
        goto Error;
    }
    Offset += (uint16_t)AlpnLength;

    if (TicketLength < Offset + TPLength) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket too small for Transport Parameters");
        goto Error;
    }

    if (!QuicCryptoTlsDecodeTransportParameters(
            Connection,
            TRUE,   // IsServerTP
            Ticket + Offset,
            (uint16_t)TPLength,
            DecodedTP)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket TParams failed to decode");
        goto Error;
    }
    Offset += (uint16_t)TPLength;

    if (TicketLength == Offset + AppTicketLength) {
        Status = QUIC_STATUS_SUCCESS;
        *AppDataLength = (uint32_t)AppTicketLength;
        if (AppTicketLength > 0) {
            *AppData = Ticket + Offset;
        }
    } else {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket app data length corrupt");
    }

Error:
    return Status;
}

QUIC_STATUS
QuicCryptoEncodeClientTicket(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint32_t TicketLength,
    _In_reads_bytes_(TicketLength)
        const uint8_t* Ticket,
    _In_ const QUIC_TRANSPORT_PARAMETERS* ServerTP,
    _In_ uint32_t QuicVersion,
    _Outptr_result_buffer_(*ClientTicketLength)
        const uint8_t** ClientTicket,
    _Out_ uint32_t* ClientTicketLength
    )
{
    QUIC_STATUS Status;
    uint32_t EncodedTPLength = 0;
    uint8_t* ClientTicketBuffer = NULL;
    const uint8_t* EncodedServerTP = NULL;

    *ClientTicket = NULL;
    *ClientTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS ServerTPCopy = *ServerTP;
    //
    // The client must remember all TPs it can process except for the following
    //
    ServerTPCopy.Flags &= ~(
        QUIC_TP_FLAG_ACK_DELAY_EXPONENT |
        QUIC_TP_FLAG_MAX_ACK_DELAY |
        QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID |
        QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID |
        QUIC_TP_FLAG_PREFERRED_ADDRESS |
        QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID |
        QUIC_TP_FLAG_STATELESS_RESET_TOKEN);

    EncodedServerTP =
        QuicCryptoTlsEncodeTransportParameters(
            Connection,
            TRUE,
            &ServerTPCopy,
            NULL,
            &EncodedTPLength);
    if (EncodedServerTP == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Adjust for any TLS header potentially added to the TP buffer
    //
    EncodedTPLength -= CxPlatTlsTPHeaderSize;

    uint32_t ClientTicketBufferLength =
        (uint32_t)(QuicVarIntSize(CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION) +
        sizeof(QuicVersion) +
        QuicVarIntSize(EncodedTPLength) +
        QuicVarIntSize(TicketLength) +
        EncodedTPLength +
        TicketLength);

    ClientTicketBuffer = CXPLAT_ALLOC_NONPAGED(ClientTicketBufferLength, QUIC_POOL_CLIENT_CRYPTO_TICKET);
    if (ClientTicketBuffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Client resumption ticket",
            ClientTicketBufferLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Encoded ticket blob format is as follows:
    //   Ticket Version (QUIC_VAR_INT) [1..4]
    //   Negotiated Quic Version (network byte order) [4]
    //   Transport Parameters length (QUIC_VAR_INT) [1..2]
    //   Received Ticket length (QUIC_VAR_INT) [1..2]
    //   Transport Parameters [...]
    //   Received Ticket (omitted if length is zero) [...]
    //

    _Analysis_assume_(sizeof(*ClientTicketBuffer) >= 8);
    uint8_t* TicketCursor = QuicVarIntEncode(CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION, ClientTicketBuffer);
    CxPlatCopyMemory(TicketCursor, &QuicVersion, sizeof(QuicVersion));
    TicketCursor += sizeof(QuicVersion);
    TicketCursor = QuicVarIntEncode(EncodedTPLength, TicketCursor);
    TicketCursor = QuicVarIntEncode(TicketLength, TicketCursor);
    CxPlatCopyMemory(TicketCursor, EncodedServerTP + CxPlatTlsTPHeaderSize, EncodedTPLength);
    TicketCursor += EncodedTPLength;
    if (TicketLength > 0) {
        CxPlatCopyMemory(TicketCursor, Ticket, TicketLength);
        TicketCursor += TicketLength;
    }
    CXPLAT_DBG_ASSERT(TicketCursor == ClientTicketBuffer + ClientTicketBufferLength);

    *ClientTicket = ClientTicketBuffer;
    *ClientTicketLength = ClientTicketBufferLength;

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (EncodedServerTP != NULL) {
        CXPLAT_FREE(EncodedServerTP, QUIC_POOL_TLS_TRANSPARAMS);
    }

    return Status;
}

QUIC_STATUS
QuicCryptoDecodeClientTicket(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint16_t ClientTicketLength,
    _In_reads_bytes_(ClientTicketLength)
        const uint8_t* ClientTicket,
    _Out_ QUIC_TRANSPORT_PARAMETERS* DecodedTP,
    _Outptr_result_buffer_maybenull_(*ServerTicketLength)
        uint8_t** ServerTicket,
    _Out_ uint32_t* ServerTicketLength,
    _Out_ uint32_t* QuicVersion
    )
{
    QUIC_STATUS Status = QUIC_STATUS_INVALID_PARAMETER;
    uint16_t Offset = 0;
    QUIC_VAR_INT TicketVersion = 0, TPLength = 0, TicketLength = 0;

    *ServerTicket = NULL;
    *ServerTicketLength = 0;
    *QuicVersion = 0;

    if (!QuicVarIntDecode(ClientTicketLength, ClientTicket, &Offset, &TicketVersion)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Client Ticket version failed to decode");
        goto Error;
    }
    if (TicketVersion != CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Client Ticket version unsupported");
        goto Error;
    }
    if (ClientTicketLength < Offset + sizeof(uint32_t)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Client Ticket not long enough for QUIC version");
        goto Error;
    }
    CxPlatCopyMemory(QuicVersion, ClientTicket + Offset, sizeof(*QuicVersion));
    if (!QuicIsVersionSupported(*QuicVersion)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket for unsupported QUIC version");
        goto Error;
    }
    Offset += sizeof(*QuicVersion);
    if (!QuicVarIntDecode(ClientTicketLength, ClientTicket, &Offset, &TPLength)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Client Ticket TP length failed to decode");
        goto Error;
    }
    if (!QuicVarIntDecode(ClientTicketLength, ClientTicket, &Offset, &TicketLength)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket data length failed to decode");
        goto Error;
    }
    if (ClientTicketLength < Offset + TPLength) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Client Ticket not long enough for Client Transport Parameters");
        goto Error;
    }
    if (!QuicCryptoTlsDecodeTransportParameters(
            Connection,
            TRUE,  // IsServerTP
            ClientTicket + Offset,
            (uint16_t)TPLength,
            DecodedTP)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Resumption Ticket TParams failed to decode");
        goto Error;
    }
    Offset += (uint16_t)TPLength;
    if (Offset + TicketLength != ClientTicketLength) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Client resumption ticket length is corrupt");
        goto Error;
    }
    if (TicketLength != 0) {
        *ServerTicket = CXPLAT_ALLOC_NONPAGED((uint32_t)TicketLength, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
        if (*ServerTicket == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Resumption ticket copy",
                TicketLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        CxPlatCopyMemory(*ServerTicket, (uint8_t*)ClientTicket + Offset, (uint16_t)TicketLength);
    }
    *ServerTicketLength = (uint32_t)TicketLength;
    Offset += (uint16_t)TicketLength;
    CXPLAT_DBG_ASSERT(ClientTicketLength == Offset);

    Status = QUIC_STATUS_SUCCESS;

Error:
    return Status;
}

QUIC_STATUS
QuicCryptoReNegotiateAlpn(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint16_t AlpnListLength,
    _In_reads_bytes_(AlpnListLength)
        const uint8_t* AlpnList
    )
{
    CXPLAT_DBG_ASSERT(Connection != NULL);
    CXPLAT_DBG_ASSERT(AlpnList != NULL);
    CXPLAT_DBG_ASSERT(AlpnListLength > 0);

    const uint8_t* PrevNegotiatedAlpn = Connection->Crypto.TlsState.NegotiatedAlpn;
    if (AlpnList[0] == PrevNegotiatedAlpn[0]) {
        if (memcmp(AlpnList + 1, PrevNegotiatedAlpn + 1, AlpnList[0]) == 0) {
            return QUIC_STATUS_SUCCESS;
        }
    }

    const uint8_t* NewNegotiatedAlpn = NULL;
    while (AlpnListLength != 0) {
        const uint8_t* Result =
            CxPlatTlsAlpnFindInList(
                Connection->Crypto.TlsState.ClientAlpnListLength,
                Connection->Crypto.TlsState.ClientAlpnList,
                AlpnList[0],
                AlpnList + 1);
        if (Result != NULL) {
            NewNegotiatedAlpn = AlpnList;
            break;
        }
        AlpnListLength -= AlpnList[0] + 1;
        AlpnList += AlpnList[0] + 1;
    }

    if (NewNegotiatedAlpn == NULL) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "No ALPN match found");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_INTERNAL_ERROR);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Free current ALPN buffer if it's allocated on heap.
    //
    if (Connection->Crypto.TlsState.NegotiatedAlpn != Connection->Crypto.TlsState.SmallAlpnBuffer) {
        CXPLAT_FREE(Connection->Crypto.TlsState.NegotiatedAlpn, QUIC_POOL_ALPN);
        Connection->Crypto.TlsState.NegotiatedAlpn = NULL;
    }

    uint8_t* NegotiatedAlpn = NULL;
    uint8_t NegotiatedAlpnLength = NewNegotiatedAlpn[0];
    if (NegotiatedAlpnLength < TLS_SMALL_ALPN_BUFFER_SIZE) {
        NegotiatedAlpn = Connection->Crypto.TlsState.SmallAlpnBuffer;
    } else {
        NegotiatedAlpn = CXPLAT_ALLOC_NONPAGED(NegotiatedAlpnLength + sizeof(uint8_t), QUIC_POOL_ALPN);
        if (NegotiatedAlpn == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "NegotiatedAlpn",
                NegotiatedAlpnLength);
            QuicConnTransportError(
                Connection,
                QUIC_ERROR_INTERNAL_ERROR);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }
    NegotiatedAlpn[0] = NegotiatedAlpnLength;
    CxPlatCopyMemory(NegotiatedAlpn + 1, NewNegotiatedAlpn + 1, NegotiatedAlpnLength);
    Connection->Crypto.TlsState.NegotiatedAlpn = NegotiatedAlpn;

    return QUIC_STATUS_SUCCESS;
}
