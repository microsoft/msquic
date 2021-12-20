/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// All the necessary state for building and sending QUIC packets.
//
typedef struct QUIC_PACKET_BUILDER {

    //
    // Connection packets are being built for.
    //
    QUIC_CONNECTION* Connection;

    //
    // The current path being used.
    //
    QUIC_PATH* Path;

    //
    // The source connection ID.
    //
    QUIC_CID_HASH_ENTRY* SourceCid;

    //
    // Represents a set of UDP datagrams.
    //
    CXPLAT_SEND_DATA* SendData;

    //
    // Represents a single UDP payload. Can contain multiple coalesced QUIC
    // packets.
    //
    QUIC_BUFFER* Datagram;

    //
    // The encryption key for the current QUIC packet.
    //
    QUIC_PACKET_KEY* Key;

    //
    // Cipher text across multiple packets to batch header protection.
    //
    uint8_t CipherBatch[CXPLAT_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];

    //
    // Output header protection mask.
    //
    uint8_t HpMask[CXPLAT_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];


    //
    // Headers that need to be batched.
    //
    uint8_t* HeaderBatch[QUIC_MAX_CRYPTO_BATCH_COUNT];

    //
    // Indicates a batch of packets has been sent.
    //
    uint8_t PacketBatchSent : 1;

    //
    // Indicates the current batch of packets just sent out included a
    // retransmittable packet.
    //
    uint8_t PacketBatchRetransmittable : 1;

    //
    // The number of batched packets to do header protection on.
    //
    uint8_t BatchCount : 4;

    //
    // The total number of datagrams that have been created.
    //
    uint8_t TotalCountDatagrams;

    //
    // The size of the encryption AEAD tag at the end of the current QUIC
    // packet.
    //
    uint8_t EncryptionOverhead;

    //
    // The encryption level for the current QUIC packet.
    //
    QUIC_ENCRYPT_LEVEL EncryptLevel;

    //
    // The type of the current QUIC packet.
    //
    uint8_t PacketType;

    //
    // Length of the packet number encoded into the current QUIC packet header.
    //
    uint8_t PacketNumberLength;

    //
    // The written length of the current Datagram.
    //
    uint16_t DatagramLength;

    //
    // The total number of bytes sent across all created datagrams.
    //
    uint32_t TotalDatagramsLength;

    //
    // Indicates the datagram (or more specifically, the last QUIC packet in the
    // datagram) should be padded to the minimum length.
    //
    uint16_t MinimumDatagramLength;

    //
    // The offset of the start of the current QUIC packet in the Datagram.
    //
    uint16_t PacketStart;

    //
    // The length of the current QUIC packet's header.
    //
    uint16_t HeaderLength;

    //
    // The offset in the current QUIC packet for writing the long header payload
    // lenth field (two bytes).
    //
    uint16_t PayloadLengthOffset;

    //
    // The number of bytes currently allowed to be sent out.
    //
    uint32_t SendAllowance;

    uint64_t BatchId;

    //
    // Represents the metadata of the current QUIC packet.
    //
    QUIC_SENT_PACKET_METADATA* Metadata;
    QUIC_MAX_SENT_PACKET_METADATA MetadataStorage;

} QUIC_PACKET_BUILDER;

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_PACKET_BUILDER) < 1024,
    L"Packet builder should be small enough to fit on the stack.");

//
// Initializes the packet builder for general use.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderInitialize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    );

//
// Cleans up any leftover data still buffered for send.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderCleanup(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

//
// Prepares the packet builder for framing control payload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForControlFrames(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN IsTailLossProbe,
    _In_ uint32_t SendFlags
    );

//
// Prepares the packet builder for PMTUD.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForPathMtuDiscovery(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

//
// Prepares the packet builder for stream payload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForStreamFrames(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN IsTailLossProbe
    );

//
// Finishes up the current packet so it can be sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPacketBuilderFinalize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN FlushBatchedDatagrams
    );

//
// Returns TRUE if congestion control isn't currently blocking sends.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicPacketBuilderHasAllowance(
    _In_ const QUIC_PACKET_BUILDER* Builder
    )
{
    return
        Builder->SendAllowance > 0 ||
        QuicCongestionControlGetExemptions(&Builder->Connection->CongestionControl) > 0;
}

//
// Returns TRUE if the packet has run out of room for frames.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicPacketBuilderAddFrame(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint8_t FrameType,
    _In_ BOOLEAN IsAckEliciting
    )
{
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET);
    Builder->Metadata->Frames[Builder->Metadata->FrameCount].Type = FrameType;
    Builder->Metadata->Flags.IsAckEliciting |= IsAckEliciting;
    return ++Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET;
}

//
// Returns TRUE if the packet has run out of room for frames.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicPacketBuilderAddStreamFrame(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_STREAM* Stream,
    _In_ uint8_t FrameType
    )
{
    Builder->Metadata->Frames[Builder->Metadata->FrameCount].MAX_STREAM_DATA.Stream = Stream;
    QuicStreamSentMetadataIncrement(Stream);
    return QuicPacketBuilderAddFrame(Builder, FrameType, TRUE);
}
