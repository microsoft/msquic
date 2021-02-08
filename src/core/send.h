/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define SEND_PACKET_SHORT_HEADER_TYPE 0xff

inline
uint8_t
QuicKeyTypeToPacketType(
    QUIC_PACKET_KEY_TYPE KeyType
    )
{
    switch (KeyType) {
    case QUIC_PACKET_KEY_INITIAL:      return QUIC_INITIAL;
    case QUIC_PACKET_KEY_0_RTT:        return QUIC_0_RTT_PROTECTED;
    case QUIC_PACKET_KEY_HANDSHAKE:    return QUIC_HANDSHAKE;
    case QUIC_PACKET_KEY_1_RTT:
    default:                           return SEND_PACKET_SHORT_HEADER_TYPE;
    }
}

inline
QUIC_PACKET_KEY_TYPE
QuicPacketTypeToKeyType(
    uint8_t PacketType
    )
{
    switch (PacketType) {
    case QUIC_INITIAL:
    case QUIC_RETRY:            return QUIC_PACKET_KEY_INITIAL;
    case QUIC_HANDSHAKE:        return QUIC_PACKET_KEY_HANDSHAKE;
    case QUIC_0_RTT_PROTECTED:  return QUIC_PACKET_KEY_0_RTT;
    default:                    return QUIC_PACKET_KEY_1_RTT;
    }
}

inline
uint8_t
QuicEncryptLevelToPacketType(
    QUIC_ENCRYPT_LEVEL Level
    )
{
    switch (Level) {
    case QUIC_ENCRYPT_LEVEL_INITIAL:    return QUIC_INITIAL;
    case QUIC_ENCRYPT_LEVEL_HANDSHAKE:  return QUIC_HANDSHAKE;
    case QUIC_ENCRYPT_LEVEL_1_RTT:
    default:                            return SEND_PACKET_SHORT_HEADER_TYPE;
    }
}

inline
QUIC_ENCRYPT_LEVEL
QuicPacketTypeToEncryptLevel(
    uint8_t PacketType
    )
{
    switch (PacketType) {
    case QUIC_INITIAL:          return QUIC_ENCRYPT_LEVEL_INITIAL;
    case QUIC_HANDSHAKE:        return QUIC_ENCRYPT_LEVEL_HANDSHAKE;
    default:                    return QUIC_ENCRYPT_LEVEL_1_RTT;
    }
}

//
// Flags representing types of control messages that need to be sent out. Any
// per-stream control messages are stored with the stream itself. The order
// reflects the order the data is framed into a packet.
//

#define QUIC_CONN_SEND_FLAG_ACK                     0x00000001U
#define QUIC_CONN_SEND_FLAG_CRYPTO                  0x00000002U
#define QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE        0x00000004U
#define QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE       0x00000008U
#define QUIC_CONN_SEND_FLAG_DATA_BLOCKED            0x00000010U
#define QUIC_CONN_SEND_FLAG_MAX_DATA                0x00000020U
#define QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI        0x00000040U
#define QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI         0x00000080U
#define QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID       0x00000100U
#define QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID    0x00000200U
#define QUIC_CONN_SEND_FLAG_PATH_CHALLENGE          0x00000400U
#define QUIC_CONN_SEND_FLAG_PATH_RESPONSE           0x00000800U
#define QUIC_CONN_SEND_FLAG_PING                    0x00001000U
#define QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE          0x00002000U
#define QUIC_CONN_SEND_FLAG_DATAGRAM                0x00004000U
#define QUIC_CONN_SEND_FLAG_PMTUD                   0x80000000U

//
// Flags that aren't blocked by congestion control.
//
#define QUIC_CONN_SEND_FLAGS_BYPASS_CC \
( \
    QUIC_CONN_SEND_FLAG_ACK | \
    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | \
    QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE \
)

//
// Flags we need to remove (and prevent from being added) when the connection
// is closed.
//
#define QUIC_CONN_SEND_FLAG_CONN_CLOSED_MASK \
( \
    QUIC_CONN_SEND_FLAG_DATA_BLOCKED | \
    QUIC_CONN_SEND_FLAG_MAX_DATA | \
    QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI | \
    QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI | \
    QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID | \
    QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID | \
    QUIC_CONN_SEND_FLAG_PATH_CHALLENGE | \
    QUIC_CONN_SEND_FLAG_PATH_RESPONSE | \
    QUIC_CONN_SEND_FLAG_PING | \
    QUIC_CONN_SEND_FLAG_DATAGRAM | \
    QUIC_CONN_SEND_FLAG_PMTUD \
)

//
// Set of flags we're allowed to send during the handshake.
//
#define QUIC_CONN_SEND_FLAG_ALLOWED_HANDSHAKE \
( \
    QUIC_CONN_SEND_FLAG_ACK | \
    QUIC_CONN_SEND_FLAG_CRYPTO | \
    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | \
    QUIC_CONN_SEND_FLAG_PING \
)

//
// Flags representing types of frames that need to be sent out on a specific
// stream. The order reflects the order the data is framed into a packet.
//

#define QUIC_STREAM_SEND_FLAG_DATA_BLOCKED  0x0001U
#define QUIC_STREAM_SEND_FLAG_MAX_DATA      0x0002U
#define QUIC_STREAM_SEND_FLAG_SEND_ABORT    0x0004U
#define QUIC_STREAM_SEND_FLAG_RECV_ABORT    0x0008U
#define QUIC_STREAM_SEND_FLAG_DATA          0x0010U
#define QUIC_STREAM_SEND_FLAG_OPEN          0x0020U
#define QUIC_STREAM_SEND_FLAG_FIN           0x0040U

#define QUIC_STREAM_SEND_FLAGS_ALL          0xFFFFU

inline BOOLEAN HasStreamControlFrames(uint32_t Flags)
{
    return Flags &
        (QUIC_STREAM_SEND_FLAG_DATA_BLOCKED |
         QUIC_STREAM_SEND_FLAG_MAX_DATA |
         QUIC_STREAM_SEND_FLAG_SEND_ABORT |
         QUIC_STREAM_SEND_FLAG_RECV_ABORT);
}

inline BOOLEAN HasStreamDataFrames(uint32_t Flags)
{
    return Flags &
        (QUIC_STREAM_SEND_FLAG_DATA |
         QUIC_STREAM_SEND_FLAG_OPEN |
         QUIC_STREAM_SEND_FLAG_FIN);
}

typedef struct QUIC_SEND {

    //
    // Indicates the FLUSH_SEND operation is already pending on the Connection.
    //
    BOOLEAN FlushOperationPending : 1;

    //
    // Indicates the delayed ACK timer is running.
    //
    BOOLEAN DelayedAckTimerActive : 1;

    //
    // TRUE if LastFlushTime is valid (i.e. if there has been at least
    // one flush).
    //
    BOOLEAN LastFlushTimeValid : 1;

    //
    // Indicates at least one tail loss probe packet must be sent.
    //
    BOOLEAN TailLossProbeNeeded : 1;

    //
    // The next packet number to use.
    //
    uint64_t NextPacketNumber;

    //
    // Last time send flush occurred. Used for pacing calculations.
    //
    uint64_t LastFlushTime;

    //
    // The value we send in MAX_DATA frames.
    //
    uint64_t MaxData;

    //
    // The max value received in MAX_DATA frames.
    //
    uint64_t PeerMaxData;

    //
    // Sum of in-order received/buffered bytes across all streams.
    // At all times, OrderedStreamBytesReceived <= MaxData.
    //
    uint64_t OrderedStreamBytesReceived;

    //
    // Sum of in-order sent bytes across all streams.
    // At all times, OrderedStreamBytesSent <= PeerMaxData.
    //
    uint64_t OrderedStreamBytesSent;

    //
    // Set of flags indicating what data is ready to be sent out.
    //
    uint32_t SendFlags;

    //
    // List of streams with data or control frames to send.
    //
    CXPLAT_LIST_ENTRY SendStreams;

    //
    // The current token to send with an Initial packet.
    //
    const uint8_t* InitialToken;

    //
    // Length of the InitialToken variable.
    //
    uint16_t InitialTokenLength;

} QUIC_SEND;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendInitialize(
    _Inout_ QUIC_SEND* Send,
    _In_ const QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendUninitialize(
    _In_ QUIC_SEND* Send
    );

#if DEBUG
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendValidate(
    _In_ QUIC_SEND* Send
    );
#else
#define QuicSendValidate(Send)
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendApplyNewSettings(
    _Inout_ QUIC_SEND* Send,
    _In_ const QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendReset(
    _In_ QUIC_SEND* Send
    );

typedef enum QUIC_SEND_FLUSH_REASON {
    REASON_CONNECTION_FLAGS,
    REASON_STREAM_FLAGS,
    REASON_PROBE,
    REASON_LOSS,
    REASON_ACK,
    REASON_TRANSPORT_PARAMETERS,
    REASON_CONGESTION_CONTROL,
    REASON_CONNECTION_FLOW_CONTROL,
    REASON_NEW_KEY,
    REASON_STREAM_FLOW_CONTROL,
    REASON_STREAM_ID_FLOW_CONTROL,
    REASON_AMP_PROTECTION,
    REASON_SCHEDULING
} QUIC_SEND_FLUSH_REASON;

//
// Queues a FLUSH_SEND operation if not already queued.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendQueueFlush(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_SEND_FLUSH_REASON Reason
    );

//
// Queues a FLUSH_SEND operation for stream data.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendQueueFlushForStream(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN WasPreviouslyQueued
    );

//
// Tries to drain all queued data that needs to be sent. Returns TRUE if all the
// data was drained.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSendFlush(
    _In_ QUIC_SEND* Send
    );

//
// Starts the delayed ACK timer if not already running.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendStartDelayedAckTimer(
    _In_ QUIC_SEND* Send
    );

//
// Called in response to the delayed ACK timer expiring.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendProcessDelayedAckTimer(
    _In_ QUIC_SEND* Send
    );

//
// Indicates the connection has a given QUIC_CONN_SEND_FLAG_* that is ready
// to be sent. Returns TRUE if the flag is (or already was) queued.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendSetSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ uint32_t SendFlag
    );

//
// Clears the given QUIC_CONN_SEND_FLAG_*.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendClearSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ uint32_t SendFlag
    );

//
// Ensures the ACK send flags and delayed ACK timer are in the proper state.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendUpdateAckState(
    _In_ QUIC_SEND* Send
    );

//
// Indicates the stream has a given QUIC_STREAM_SEND_FLAG_* that is ready
// to be sent. Returns TRUE if the flag is (or already was) queued.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSendSetStreamSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t SendFlag
    );

//
// Clears the given QUIC_STREAM_SEND_FLAG_* and removes the Stream from the
// send queue if it no longer has anything pending.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendClearStreamSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t SendFlag
    );
