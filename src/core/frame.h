/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// QUIC Transport Error codes defined by the QUIC Transport RFC.
//

#if defined(__cplusplus)
extern "C" {
#endif

//
// An endpoint uses this with CONNECTION_CLOSE to signal that the connection
// is being closed abruptly in the absence of any error.
//
#define QUIC_ERROR_NO_ERROR                     0x0
//
// The endpoint encountered an unspecified internal error and cannot continue
// with the connection.
//
#define QUIC_ERROR_INTERNAL_ERROR               0x1
//
// The server refused to accept the new connection.
//
#define QUIC_ERROR_CONNECTION_REFUSED           0x2
//
// An endpoint received more data than it permitted in its advertised data
// limits.
//
#define QUIC_ERROR_FLOW_CONTROL_ERROR           0x3
//
// An endpoint received a frame for a stream identifier that exceeded its
// advertised limit for the corresponding stream type.
//
#define QUIC_ERROR_STREAM_LIMIT_ERROR           0x4
//
// An endpoint received a frame for a stream that was not in a state that
// permitted that frame.
//
#define QUIC_ERROR_STREAM_STATE_ERROR           0x5
//
// An endpoint received a STREAM frame containing data that exceeded the
// previously established final size. Or an endpoint received a STREAM frame
// or a RESET_STREAM frame containing a final size that was lower than the size
// of stream data that was already received.  Or an endpoint received a STREAM
// frame or a RESET_STREAM frame containing a different final size to the one
// already established.
//
#define QUIC_ERROR_FINAL_SIZE_ERROR             0x6
//
// An endpoint received a frame that was badly formatted. For instance, an empty
// STREAM frame that omitted the FIN flag, or an ACK frame that has more
// acknowledgment ranges than the remainder of the packet could carry.
//
#define QUIC_ERROR_FRAME_ENCODING_ERROR         0x7
//
// An endpoint received transport parameters that were badly formatted, included
// an invalid value, was absent even though it is mandatory, was present though
// it is forbidden, or is otherwise in error.
//
#define QUIC_ERROR_TRANSPORT_PARAMETER_ERROR    0x8
//
// An endpoint detected an error with protocol compliance that was not covered
// by more specific error codes.
//
#define QUIC_ERROR_PROTOCOL_VIOLATION           0xA
//
// An endpoint has received more data in CRYPTO frames than it can buffer.
//
#define QUIC_ERROR_CRYPTO_BUFFER_EXCEEDED       0xD
//
// An endpoint detected errors in performing key updates.
//
#define QUIC_ERROR_KEY_UPDATE_ERROR             0xE
//
// An endpoint has exceeded the maximum number of failed packet decryptions
// over its lifetime.
//
#define QUIC_ERROR_AEAD_LIMIT_REACHED           0xF
//
// The cryptographic handshake failed. A range of 256 values is reserved for
// carrying error codes specific to the cryptographic handshake that is used.
// Codes for errors occurring when TLS is used for the crypto handshake are
// described in Section 4.8 of [QUIC-TLS].
//
#define QUIC_ERROR_CRYPTO_ERROR(TlsAlertCode)   ((QUIC_VAR_INT)(0x100 | (TlsAlertCode)))
#define IS_QUIC_CRYPTO_ERROR(QuicCryptoError)   ((QuicCryptoError & 0xFF00) == 0x100)

#define QUIC_ERROR_CRYPTO_HANDSHAKE_FAILURE         QUIC_ERROR_CRYPTO_ERROR(40)  // TLS error code for 'handshake_failure'
#define QUIC_ERROR_CRYPTO_USER_CANCELED             QUIC_ERROR_CRYPTO_ERROR(90)  // TLS error code for 'user_canceled'
#define QUIC_ERROR_CRYPTO_NO_APPLICATION_PROTOCOL   QUIC_ERROR_CRYPTO_ERROR(120) // TLS error code for 'no_application_protocol'

#define QUIC_ERROR_VERSION_NEGOTIATION_ERROR    0x53F8

//
// Used for determining which errors to count for performance counters.
//
inline
BOOLEAN
QuicErrorIsProtocolError(
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    return
        ErrorCode >= QUIC_ERROR_FLOW_CONTROL_ERROR &&
        ErrorCode <= QUIC_ERROR_AEAD_LIMIT_REACHED;
}

//
// Different types of QUIC frames
//
typedef enum QUIC_FRAME_TYPE {
    QUIC_FRAME_PADDING              = 0x0ULL,
    QUIC_FRAME_PING                 = 0x1ULL,
    QUIC_FRAME_ACK                  = 0x2ULL, // to 0x3
    QUIC_FRAME_ACK_1                = 0x3ULL,
    QUIC_FRAME_RESET_STREAM         = 0x4ULL,
    QUIC_FRAME_STOP_SENDING         = 0x5ULL,
    QUIC_FRAME_CRYPTO               = 0x6ULL,
    QUIC_FRAME_NEW_TOKEN            = 0x7ULL,
    QUIC_FRAME_STREAM               = 0x8ULL, // to 0xf
    QUIC_FRAME_STREAM_1             = 0x9ULL,
    QUIC_FRAME_STREAM_2             = 0xaULL,
    QUIC_FRAME_STREAM_3             = 0xbULL,
    QUIC_FRAME_STREAM_4             = 0xcULL,
    QUIC_FRAME_STREAM_5             = 0xdULL,
    QUIC_FRAME_STREAM_6             = 0xeULL,
    QUIC_FRAME_STREAM_7             = 0xfULL,
    QUIC_FRAME_MAX_DATA             = 0x10ULL,
    QUIC_FRAME_MAX_STREAM_DATA      = 0x11ULL,
    QUIC_FRAME_MAX_STREAMS          = 0x12ULL, // to 0x13
    QUIC_FRAME_MAX_STREAMS_1        = 0x13ULL,
    QUIC_FRAME_DATA_BLOCKED         = 0x14ULL,
    QUIC_FRAME_STREAM_DATA_BLOCKED  = 0x15ULL,
    QUIC_FRAME_STREAMS_BLOCKED      = 0x16ULL, // to 0x17
    QUIC_FRAME_STREAMS_BLOCKED_1    = 0x17ULL,
    QUIC_FRAME_NEW_CONNECTION_ID    = 0x18ULL,
    QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19ULL,
    QUIC_FRAME_PATH_CHALLENGE       = 0x1aULL,
    QUIC_FRAME_PATH_RESPONSE        = 0x1bULL,
    QUIC_FRAME_CONNECTION_CLOSE     = 0x1cULL, // to 0x1d
    QUIC_FRAME_CONNECTION_CLOSE_1   = 0x1dULL,
    QUIC_FRAME_HANDSHAKE_DONE       = 0x1eULL,
    /* 0x1f to 0x2f are unused currently */
    QUIC_FRAME_DATAGRAM             = 0x30ULL, // to 0x31
    QUIC_FRAME_DATAGRAM_1           = 0x31ULL,
    /* 0x32 to 0xad are unused currently */
    QUIC_FRAME_ACK_FREQUENCY        = 0xafULL,
    QUIC_FRAME_IMMEDIATE_ACK        = 0xacULL,

    QUIC_FRAME_MAX_SUPPORTED

} QUIC_FRAME_TYPE;

CXPLAT_STATIC_ASSERT(
    QUIC_FRAME_MAX_SUPPORTED <= (uint64_t)UINT32_MAX,
    "Logging assumes frames types fit in 32-bits");

#define QUIC_FRAME_IS_KNOWN(X) \
    (X <= QUIC_FRAME_HANDSHAKE_DONE || \
     (X >= QUIC_FRAME_DATAGRAM && X <= QUIC_FRAME_DATAGRAM_1) || \
     X == QUIC_FRAME_ACK_FREQUENCY || X == QUIC_FRAME_IMMEDIATE_ACK \
    )

//
// QUIC_FRAME_ACK Encoding/Decoding
//

typedef struct QUIC_ACK_EX {

    QUIC_VAR_INT LargestAcknowledged;
    QUIC_VAR_INT AckDelay;
    QUIC_VAR_INT AdditionalAckBlockCount;
    QUIC_VAR_INT FirstAckBlock;

} QUIC_ACK_EX;

typedef struct QUIC_ACK_BLOCK_EX {

    QUIC_VAR_INT Gap;
    QUIC_VAR_INT AckBlock;

} QUIC_ACK_BLOCK_EX;

typedef struct QUIC_ACK_ECN_EX {

    QUIC_VAR_INT ECT_0_Count;
    QUIC_VAR_INT ECT_1_Count;
    QUIC_VAR_INT CE_Count;

} QUIC_ACK_ECN_EX;

_Success_(return != FALSE)
BOOLEAN
QuicAckFrameEncode(
    _In_ const QUIC_RANGE * const AckBlocks,
    _In_ uint64_t AckDelay,
    _In_opt_ QUIC_ACK_ECN_EX* Ecn,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicAckFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ BOOLEAN* InvalidFrame,
    _Inout_ QUIC_RANGE* AckRanges, // Pre-Initialized by caller
    _When_(FrameType == QUIC_FRAME_ACK_1, _Out_)
        QUIC_ACK_ECN_EX* Ecn,
    _Out_ uint64_t* AckDelay
    );

//
// QUIC_FRAME_RESET_STREAM Encoding/Decoding
//

typedef struct QUIC_RESET_STREAM_EX {

    QUIC_VAR_INT StreamID;
    QUIC_VAR_INT ErrorCode;
    QUIC_VAR_INT FinalSize;

} QUIC_RESET_STREAM_EX;

_Success_(return != FALSE)
BOOLEAN
QuicResetStreamFrameEncode(
    _In_ const QUIC_RESET_STREAM_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicResetStreamFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_RESET_STREAM_EX* Frame
    );

//
// QUIC_FRAME_STOP_SENDING Encoding/Decoding
//

typedef struct QUIC_STOP_SENDING_EX {

    QUIC_VAR_INT StreamID;
    QUIC_VAR_INT ErrorCode;

} QUIC_STOP_SENDING_EX;

_Success_(return != FALSE)
BOOLEAN
QuicStopSendingFrameEncode(
    _In_ const QUIC_STOP_SENDING_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicStopSendingFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_STOP_SENDING_EX* Frame
    );

//
// QUIC_FRAME_CRYPTO Encoding/Decoding
//

typedef struct QUIC_CRYPTO_EX {

    QUIC_VAR_INT Offset;
    QUIC_VAR_INT Length;
    _Field_size_bytes_(Length)
    const uint8_t * Data;

} QUIC_CRYPTO_EX;

_Success_(return != FALSE)
BOOLEAN
QuicCryptoFrameEncode(
    _In_ const QUIC_CRYPTO_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicCryptoFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_CRYPTO_EX* Frame
    );

//
// QUIC_FRAME_NEW_TOKEN Encoding/Decoding
//

typedef struct QUIC_NEW_TOKEN_EX {

    QUIC_VAR_INT TokenLength;
    const uint8_t* Token;

} QUIC_NEW_TOKEN_EX;

_Success_(return != FALSE)
BOOLEAN
QuicNewTokenFrameEncode(
    _In_ const QUIC_NEW_TOKEN_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicNewTokenFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_NEW_TOKEN_EX* Frame
    );

//
// QUIC_FRAME_STREAM Encoding/Decoding
//

typedef struct QUIC_STREAM_FRAME_TYPE {

    union {
        struct {
            uint8_t FIN : 1;
            uint8_t LEN : 1;
            uint8_t OFF : 1;
            uint8_t FrameType : 5; // Always 0b00001
        };
        uint8_t Type;
    };

} QUIC_STREAM_FRAME_TYPE;

#define MIN_STREAM_FRAME_LENGTH (sizeof(QUIC_STREAM_FRAME_TYPE) + 2)

typedef struct QUIC_STREAM_EX {

    BOOLEAN Fin;
    BOOLEAN ExplicitLength;
    QUIC_VAR_INT StreamID;
    QUIC_VAR_INT Offset;
    QUIC_VAR_INT Length;
    _Field_size_bytes_(Length)
    const uint8_t * Data;

} QUIC_STREAM_EX;

inline
uint8_t
QuicStreamFrameHeaderSize(
    _In_ const QUIC_STREAM_EX * const Frame
    )
{
    uint8_t Size =
        sizeof(uint8_t) + // Type
        QuicVarIntSize(Frame->StreamID);
    if (Frame->Offset != 0) {
        Size += QuicVarIntSize(Frame->Offset);
    }
    if (Frame->ExplicitLength) {
        Size += 2; // We always use two bytes for the explicit length.
    }
    return Size;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamFrameEncode(
    _In_ const QUIC_STREAM_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicStreamFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_
    _Deref_in_range_(0, BufferLength)
    _Deref_out_range_(0, BufferLength)
        uint16_t* Offset,
    _Out_ QUIC_STREAM_EX* Frame
    );

//
// QUIC_FRAME_MAX_DATA Encoding/Decoding
//

typedef struct QUIC_MAX_DATA_EX {

    QUIC_VAR_INT MaximumData;

} QUIC_MAX_DATA_EX;

_Success_(return != FALSE)
BOOLEAN
QuicMaxDataFrameEncode(
    _In_ const QUIC_MAX_DATA_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicMaxDataFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_MAX_DATA_EX* Frame
    );

//
// QUIC_FRAME_MAX_STREAM_DATA Encoding/Decoding
//

typedef struct QUIC_MAX_STREAM_DATA_EX {

    QUIC_VAR_INT StreamID;
    QUIC_VAR_INT MaximumData;

} QUIC_MAX_STREAM_DATA_EX;

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamDataFrameEncode(
    _In_ const QUIC_MAX_STREAM_DATA_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamDataFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_MAX_STREAM_DATA_EX* Frame
    );

//
// QUIC_FRAME_MAX_STREAMS Encoding/Decoding
//

typedef struct QUIC_MAX_STREAMS_EX {

    BOOLEAN BidirectionalStreams;
    QUIC_VAR_INT MaximumStreams;

} QUIC_MAX_STREAMS_EX;

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamsFrameEncode(
    _In_ const QUIC_MAX_STREAMS_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamsFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_MAX_STREAMS_EX* Frame
    );

//
// QUIC_FRAME_DATA_BLOCKED Encoding/Decoding
//

typedef struct QUIC_DATA_BLOCKED_EX {

    QUIC_VAR_INT DataLimit;

} QUIC_DATA_BLOCKED_EX;

_Success_(return != FALSE)
BOOLEAN
QuicDataBlockedFrameEncode(
    _In_ const QUIC_DATA_BLOCKED_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicDataBlockedFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_DATA_BLOCKED_EX* Frame
    );

//
// QUIC_FRAME_STREAM_DATA_BLOCKED Encoding/Decoding
//

typedef struct QUIC_STREAM_DATA_BLOCKED_EX {

    QUIC_VAR_INT StreamID;
    QUIC_VAR_INT StreamDataLimit;

} QUIC_STREAM_DATA_BLOCKED_EX;

_Success_(return != FALSE)
BOOLEAN
QuicStreamDataBlockedFrameEncode(
    _In_ const QUIC_STREAM_DATA_BLOCKED_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicStreamDataBlockedFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_STREAM_DATA_BLOCKED_EX* Frame
    );

//
// QUIC_FRAME_STREAMS_BLOCKED Encoding/Decoding
//

typedef struct QUIC_STREAMS_BLOCKED_EX {

    BOOLEAN BidirectionalStreams;
    QUIC_VAR_INT StreamLimit;

} QUIC_STREAMS_BLOCKED_EX;

_Success_(return != FALSE)
BOOLEAN
QuicStreamsBlockedFrameEncode(
    _In_ const QUIC_STREAMS_BLOCKED_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicStreamsBlockedFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_STREAMS_BLOCKED_EX* Frame
    );

//
// QUIC_FRAME_NEW_CONNECTION_ID Encoding/Decoding
//

typedef struct QUIC_NEW_CONNECTION_ID_EX {

    uint8_t Length;
    QUIC_VAR_INT Sequence;
    QUIC_VAR_INT RetirePriorTo;
    uint8_t Buffer[QUIC_MAX_CONNECTION_ID_LENGTH_V1 + QUIC_STATELESS_RESET_TOKEN_LENGTH];
    //uint8_t ConnectionID[Length];
    //uint8_t StatelessResetToken[16];

} QUIC_NEW_CONNECTION_ID_EX;

_Success_(return != FALSE)
BOOLEAN
QuicNewConnectionIDFrameEncode(
    _In_ const QUIC_NEW_CONNECTION_ID_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicNewConnectionIDFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_NEW_CONNECTION_ID_EX* Frame
    );

//
// QUIC_FRAME_RETIRE_CONNECTION_ID Encoding/Decoding
//

typedef struct QUIC_RETIRE_CONNECTION_ID_EX {

    QUIC_VAR_INT Sequence;

} QUIC_RETIRE_CONNECTION_ID_EX;

_Success_(return != FALSE)
BOOLEAN
QuicRetireConnectionIDFrameEncode(
    _In_ const QUIC_RETIRE_CONNECTION_ID_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicRetireConnectionIDFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_RETIRE_CONNECTION_ID_EX* Frame
    );

//
// QUIC_FRAME_PATH_CHALLENGE Encoding/Decoding
//

typedef struct QUIC_PATH_CHALLENGE_EX {

    uint8_t Data[8];

} QUIC_PATH_CHALLENGE_EX;

//
// Struct for QUIC_FRAME_PATH_CHALLENGE is the same as for
// QUIC_FRAME_PATH_RESPONSE.
//

typedef QUIC_PATH_CHALLENGE_EX QUIC_PATH_RESPONSE_EX;

_Success_(return != FALSE)
BOOLEAN
QuicPathChallengeFrameEncode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ const QUIC_PATH_CHALLENGE_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicPathChallengeFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_PATH_CHALLENGE_EX* Frame
    );

//
// QUIC_FRAME_CONNECTION_CLOSE Encoding/Decoding
//

typedef struct QUIC_CONNECTION_CLOSE_EX {

    BOOLEAN ApplicationClosed;
    QUIC_VAR_INT ErrorCode;
    QUIC_VAR_INT FrameType;
    QUIC_VAR_INT ReasonPhraseLength;
    char* ReasonPhrase;     // UTF-8 string.

} QUIC_CONNECTION_CLOSE_EX;

_Success_(return != FALSE)
BOOLEAN
QuicConnCloseFrameEncode(
    _In_ const QUIC_CONNECTION_CLOSE_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicConnCloseFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_CONNECTION_CLOSE_EX* Frame
    );

//
// QUIC_FRAME_DATAGRAM Encoding/Decoding
//

typedef struct _QUIC_DATAGRAM_FRAME_TYPE {

    union {
        struct {
            uint8_t LEN : 1;
            uint8_t FrameType : 7; // Always 0b0011000
        };
        uint8_t Type;
    };

} QUIC_DATAGRAM_FRAME_TYPE;

typedef struct _QUIC_DATAGRAM_EX {

    BOOLEAN ExplicitLength;
    QUIC_VAR_INT Length;
    _Field_size_bytes_(Length)
    const uint8_t* Data;

} QUIC_DATAGRAM_EX;

_Success_(return != FALSE)
BOOLEAN
QuicDatagramFrameEncodeEx(
    _In_reads_(BufferCount)
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ uint64_t TotalLength,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicDatagramFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Deref_in_range_(0, BufferLength)
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_DATAGRAM_EX* Frame
    );

//
// QUIC_ACK_FREQUENCY Encoding/Decoding
//

typedef struct QUIC_ACK_FREQUENCY_EX {

    QUIC_VAR_INT SequenceNumber;
    QUIC_VAR_INT PacketTolerance;
    QUIC_VAR_INT UpdateMaxAckDelay; // In microseconds (us)
    BOOLEAN IgnoreOrder;
    BOOLEAN IgnoreCE;

} QUIC_ACK_FREQUENCY_EX;

_Success_(return != FALSE)
BOOLEAN
QuicAckFrequencyFrameEncode(
    _In_ const QUIC_ACK_FREQUENCY_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    );

_Success_(return != FALSE)
BOOLEAN
QuicAckFrequencyFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_ACK_FREQUENCY_EX* Frame
    );

//
// Helper functions
//

//
// Gets the Stream ID from a Stream related frame.
//
inline
_Success_(return != FALSE)
BOOLEAN
QuicStreamFramePeekID(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _In_ uint16_t Offset,
    _Out_ uint64_t* StreamID
    )
{
    //
    // All Stream related frames have the Stream ID as the first parameter.
    //
    return QuicVarIntDecode(BufferLength, Buffer, &Offset, StreamID);
}

//
// Skips over the given Stream related frame.
//
inline
_Success_(return != FALSE)
BOOLEAN
QuicStreamFrameSkip(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset
    )
{
    switch (FrameType) {
    case QUIC_FRAME_RESET_STREAM: {
        QUIC_RESET_STREAM_EX Frame;
        return QuicResetStreamFrameDecode(BufferLength, Buffer, Offset, &Frame);
    }
    case QUIC_FRAME_MAX_STREAM_DATA: {
        QUIC_MAX_STREAM_DATA_EX Frame;
        return QuicMaxStreamDataFrameDecode(BufferLength, Buffer, Offset, &Frame);
    }
    case QUIC_FRAME_STREAM_DATA_BLOCKED: {
        QUIC_STREAM_DATA_BLOCKED_EX Frame;
        return QuicStreamDataBlockedFrameDecode(BufferLength, Buffer, Offset, &Frame);
    }
    case QUIC_FRAME_STOP_SENDING: {
        QUIC_STOP_SENDING_EX Frame;
        return QuicStopSendingFrameDecode(BufferLength, Buffer, Offset, &Frame);
    }
    default: { // QUIC_FRAME_STREAM*
        QUIC_STREAM_EX Frame;
        return QuicStreamFrameDecode(FrameType, BufferLength, Buffer, Offset, &Frame);
    }
    }
}

//
// Logs all the frames in a decrypted packet.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicFrameLogAll(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN Rx,
    _In_ uint64_t PacketNumber,
    _In_ uint16_t PacketLength,
    _In_reads_bytes_(PacketLength)
        const uint8_t * const Packet,
    _In_ uint16_t Offset
    );

#if defined(__cplusplus)
}
#endif
