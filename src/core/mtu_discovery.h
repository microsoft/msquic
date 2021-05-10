/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef enum QUIC_MTU_DISCOVERY_STATE {

    //
    // MTU discovery is in the searching state.
    //
    QUIC_MTU_DISCOVERY_STATE_SEARCHING,

    //
    // MTU discovery is in the waiting state.
    //
    QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE,

} QUIC_MTU_DISCOVERY_STATE;

typedef struct QUIC_MTU_DISCOVERY {

    //
    // The timestamp that Search Complete was entered.
    //
    uint64_t SearchCompleteEnterTimeUs;

    //
    // The current discovery state.
    //
    QUIC_MTU_DISCOVERY_STATE State;

    //
    // The minimum MTU allowed by the current path.
    //
    uint16_t MinMtu;

    //
    // The maximum MTU allowed by the current path.
    //
    uint16_t MaxMtu;

    //
    // The current MTU.
    //
    uint16_t CurrentMtu;

    //
    // The current MTU size being probed.
    //
    uint16_t ProbedSize;

    //
    // The amount of probes that have occured at the current size.
    //
    uint8_t ProbeCount;

} QUIC_MTU_DISCOVERY;

//
// Move MTU discovery into the searching state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    );

//
// Trigger MTU discovery on a new path.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryNewPath(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_PATH* Path
    );

//
// Handle Ack of an MTU discovery probe.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicMtuDiscoveryOnAckedPacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu,
    _In_ QUIC_PATH* Path
    );

//
// Handle an MTU discovery probe being discarded by loss detection when lost.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryProbePacketDiscarded(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu
    );

//
// Check to see if enough time has passed while in Search Complete to retry MTU
// discovery.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicMtuDiscoveryCheckSearchCompleteReset(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    //
    // Only trigger a new send if we're in Search Complete and enough time has
    // passed.
    //
    if (MtuDiscovery->State != QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE) {
        return;
    }
    if (CxPlatTimeDiff64(MtuDiscovery->SearchCompleteEnterTimeUs, CxPlatTimeUs64()) >= QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT) {
        QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    }
}
