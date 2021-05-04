/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef enum QUIC_MTU_DISCOVERY_STATE {
    QUIC_MTU_DISCOVERY_STATE_BASE,
    QUIC_MTU_DISCOVERY_STATE_SEARCHING,
    QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE,
    QUIC_MTU_DISCOVERY_STATE_ERROR,
} QUIC_MTU_DISCOVERY_STATE;

typedef struct QUIC_MTU_DISCOVERY {
    uint64_t SearchWaitingEnterTime;
    QUIC_MTU_DISCOVERY_STATE State;
    uint16_t MinMtu;
    uint16_t MaxMtu;
    uint16_t ProbedSize;
    uint16_t CurrentMtu;
    //uint16_t MaxMtuProbeWindow;
    //uint16_t MinMtuProbeWindow;
    uint8_t ProbeCount;
} QUIC_MTU_DISCOVERY;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryNewPath(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_PATH* Path
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicMtuDiscoveryOnAckedPacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryProbePacketDiscarded(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicMtuDiscoveryCheckSearchCompleteReset(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    if (MtuDiscovery->State != QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE) {
        return;
    }
    if (CxPlatTimeDiff64(MtuDiscovery->SearchWaitingEnterTime, CxPlatTimeUs64()) >= QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT) {
        QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    }
}
