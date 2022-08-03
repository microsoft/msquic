/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// The maximum number of frames we will write to a single packet.
//
#define QUIC_MAX_FRAMES_PER_PACKET 12

typedef struct QUIC_STREAM QUIC_STREAM;

#define QUIC_SENT_FRAME_FLAG_STREAM_OPEN    0x01    // STREAM frame opened stream
#define QUIC_SENT_FRAME_FLAG_STREAM_FIN     0x02    // STREAM frame included FIN bit

//
// Tracker for a sent frame.
//
typedef struct QUIC_SENT_FRAME_METADATA {

    union {
        struct {
            uint64_t LargestAckedPacketNumber;
        } ACK;
        struct {
            QUIC_STREAM* Stream;
        } RESET_STREAM;
        struct {
            QUIC_STREAM* Stream;
        } STOP_SENDING;
        struct {
            uint32_t Offset;
            uint16_t Length;
        } CRYPTO;
        struct {
            QUIC_STREAM* Stream;
        } STREAM;
        struct {
            QUIC_STREAM* Stream;
        } MAX_STREAM_DATA;
        struct {
            QUIC_STREAM* Stream;
        } STREAM_DATA_BLOCKED;
        struct {
            QUIC_VAR_INT Sequence;
        } NEW_CONNECTION_ID;
        struct {
            QUIC_VAR_INT Sequence;
        } RETIRE_CONNECTION_ID;
        struct {
            uint8_t Data[8];
        } PATH_CHALLENGE;
        struct {
            uint8_t Data[8];
        } PATH_RESPONSE;
        struct {
            void* ClientContext;
        } DATAGRAM;
        struct {
            QUIC_VAR_INT Sequence;
        } ACK_FREQUENCY;
    };
    //
    // The following to fields are for STREAM. However, if they were in stream
    // they force the union to completely contain them, which doesn't allow the
    // Type and Flags fields to be packed nicely.
    //
    //
    // TODO- optimization: encode in 32 bits.
    //
    uint64_t StreamOffset;
    uint16_t StreamLength;
    uint8_t Type; // QUIC_FRAME_*
    uint8_t Flags; // QUIC_SENT_FRAME_FLAG_*

} QUIC_SENT_FRAME_METADATA;

CXPLAT_STATIC_ASSERT(
    QUIC_FRAME_MAX_SUPPORTED <= (uint64_t)UINT8_MAX,
    "Metadata 'Type' field above assumes frames types fit in 8-bits");

typedef struct QUIC_SEND_PACKET_FLAGS {

    uint8_t KeyType                 : 2;
    BOOLEAN IsAckEliciting          : 1;
    BOOLEAN IsMtuProbe              : 1;
    BOOLEAN KeyPhase                : 1;
    BOOLEAN SuspectedLost           : 1;
#if DEBUG
    BOOLEAN Freed                   : 1;
#endif

} QUIC_SEND_PACKET_FLAGS;

//
// Tracker for a sent packet.
//
typedef struct QUIC_SENT_PACKET_METADATA {

    struct QUIC_SENT_PACKET_METADATA *Next;

    uint64_t PacketId;
    uint64_t PacketNumber;
    uint32_t SentTime; // In microseconds
    uint16_t PacketLength;
    uint8_t PathId;

    //
    // Hints about the QUIC packet and included frames.
    //
    QUIC_SEND_PACKET_FLAGS Flags;

    //
    // Frames included in this packet.
    //
    uint8_t FrameCount;
    QUIC_SENT_FRAME_METADATA Frames[0];

} QUIC_SENT_PACKET_METADATA;

#define SIZEOF_QUIC_SENT_PACKET_METADATA(FrameCount) \
    (sizeof(QUIC_SENT_PACKET_METADATA) + FrameCount * sizeof(QUIC_SENT_FRAME_METADATA))

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint8_t
QuicPacketTraceType(
    _In_ const QUIC_SENT_PACKET_METADATA* Metadata
    )
{
    return
        Metadata->Flags.KeyType == QUIC_PACKET_KEY_1_RTT ?
            QUIC_TRACE_PACKET_ONE_RTT : (Metadata->Flags.KeyType + 1);
}

void
QuicSentPacketMetadataReleaseFrames(
    _In_ QUIC_SENT_PACKET_METADATA* Metadata
    );

//
// Helper for allocating the maximum sent packet metadata on the stack.
//
typedef union QUIC_MAX_SENT_PACKET_METADATA
{
    QUIC_SENT_PACKET_METADATA Metadata;
    uint8_t Raw[sizeof(QUIC_SENT_PACKET_METADATA) +
              sizeof(QUIC_SENT_FRAME_METADATA) * QUIC_MAX_FRAMES_PER_PACKET];

} QUIC_MAX_SENT_PACKET_METADATA;

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_MAX_SENT_PACKET_METADATA) < 512,
    "Max Send Packet Metadata should be small enough to be allocated on the stack");

//
// A collection of object pools for each size of packet and
// associated frame metadata.
//
typedef struct QUIC_SENT_PACKET_POOL {

    CXPLAT_POOL Pools[QUIC_MAX_FRAMES_PER_PACKET];

} QUIC_SENT_PACKET_POOL;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolInitialize(
    _Inout_ QUIC_SENT_PACKET_POOL* Pool
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolUninitialize(
    _In_ QUIC_SENT_PACKET_POOL* Pool
    );

//
// Allocates a sent packet metadata item.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_SENT_PACKET_METADATA*
QuicSentPacketPoolGetPacketMetadata(
    _In_ QUIC_SENT_PACKET_POOL* Pool,
    _In_ uint8_t FrameCount
    );

//
// Frees a sent packet metadata item.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolReturnPacketMetadata(
    _In_ QUIC_SENT_PACKET_POOL* Pool,
    _In_ QUIC_SENT_PACKET_METADATA* Metadata
    );
