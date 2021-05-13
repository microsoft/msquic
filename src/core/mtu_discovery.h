/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_MTU_DISCOVERY {

    //
    // The timestamp that Search Complete was entered.
    //
    uint64_t SearchCompleteEnterTimeUs;

    //
    // The maximum MTU allowed by the current path.
    //
    uint16_t MaxMtu;

    //
    // The current MTU size being probed.
    //
    uint16_t ProbeSize;

    //
    // The amount of probes that have occured at the current size.
    //
    uint8_t ProbeCount;

    //
    // Is MTU discovery is searching or search complete.
    //
    BOOLEAN IsSearchComplete    : 1;

    //
    // Check for has 1500 been probed to ensure its tested.
    //
    BOOLEAN HasProbed1500       : 1;

} QUIC_MTU_DISCOVERY;

//
// Move MTU discovery into the searching state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Trigger MTU discovery on a new path.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryPeerValidated(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Handle Ack of an MTU discovery probe.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicMtuDiscoveryOnAckedPacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Handle an MTU discovery probe being discarded by loss detection when lost.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryProbePacketDiscarded(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t PacketMtu
    );
