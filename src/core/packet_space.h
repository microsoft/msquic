/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef enum QUIC_ENCRYPT_LEVEL {

    QUIC_ENCRYPT_LEVEL_INITIAL,
    QUIC_ENCRYPT_LEVEL_HANDSHAKE,
    QUIC_ENCRYPT_LEVEL_1_RTT,       // Also used for 0-RTT

    QUIC_ENCRYPT_LEVEL_COUNT

} QUIC_ENCRYPT_LEVEL;

inline
QUIC_PACKET_KEY_TYPE
QuicEncryptLevelToKeyType(
    QUIC_ENCRYPT_LEVEL Level
    )
{
    switch (Level) {
    case QUIC_ENCRYPT_LEVEL_INITIAL:    return QUIC_PACKET_KEY_INITIAL;
    case QUIC_ENCRYPT_LEVEL_HANDSHAKE:  return QUIC_PACKET_KEY_HANDSHAKE;
    case QUIC_ENCRYPT_LEVEL_1_RTT:
    default:                            return QUIC_PACKET_KEY_1_RTT;
    }
}

inline
QUIC_ENCRYPT_LEVEL
QuicKeyTypeToEncryptLevel(
    QUIC_PACKET_KEY_TYPE KeyType
    )
{
    switch (KeyType) {
    case QUIC_PACKET_KEY_INITIAL:      return QUIC_ENCRYPT_LEVEL_INITIAL;
    case QUIC_PACKET_KEY_0_RTT:        return QUIC_ENCRYPT_LEVEL_1_RTT;
    case QUIC_PACKET_KEY_HANDSHAKE:    return QUIC_ENCRYPT_LEVEL_HANDSHAKE;
    case QUIC_PACKET_KEY_1_RTT:
    default:                           return QUIC_ENCRYPT_LEVEL_1_RTT;
    }
}

typedef struct QUIC_PACKET_SPACE {

    //
    // The encryption level this packet space is for.
    //
    QUIC_ENCRYPT_LEVEL EncryptLevel;

    //
    // Numbers of entries in the DeferredPackets list.
    //
    uint8_t DeferredPacketsCount;

    //
    // The (expected) next packet number to receive. Used for decoding received
    // packet numbers.
    //
    uint64_t NextRecvPacketNumber;

    //
    // ECT and CE counters.
    //
    uint64_t EcnEctCounter;
    uint64_t EcnCeCounter; // maps to ecn_ce_counters in RFC 9002.

    //
    // Owning connection of this packet space.
    //
    QUIC_CONNECTION* Connection;

    //
    // List of received packets that we don't have the key for yet.
    //
    QUIC_RX_PACKET* DeferredPackets;

    //
    // Information related to packets that have been received and need to be
    // acknowledged.
    //
    QUIC_ACK_TRACKER AckTracker;

    //
    // Packet number of the first sent packet of the current key phase.
    //
    uint64_t WriteKeyPhaseStartPacketNumber;

    //
    // Packet number of the first received packet of the current key phase.
    //
    uint64_t ReadKeyPhaseStartPacketNumber;

    //
    // Count of bytes sent at the current key phase.
    //
    uint64_t CurrentKeyPhaseBytesSent;

    //
    // The current KEY_PHASE of the packet space.
    //
    BOOLEAN CurrentKeyPhase : 1;

    //
    // True when we force a key change.
    //
    BOOLEAN AwaitingKeyPhaseConfirmation: 1;

} QUIC_PACKET_SPACE;

//
// Helper to get the QUIC_PACKET_SPACE for an ack tracker.
//
inline
QUIC_PACKET_SPACE*
QuicAckTrackerGetPacketSpace(
    _In_ QUIC_ACK_TRACKER* Tracker
    )
{
    return CXPLAT_CONTAINING_RECORD(Tracker, QUIC_PACKET_SPACE, AckTracker);
}

//
// Initializes a new packet space.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPacketSpaceInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _Out_ QUIC_PACKET_SPACE** NewPackets
    );

//
// Uninitializes the packet space.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketSpaceUninitialize(
    _In_ QUIC_PACKET_SPACE* Packets
    );

//
// Resets the packet space.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketSpaceReset(
    _In_ QUIC_PACKET_SPACE* Packets
    );
