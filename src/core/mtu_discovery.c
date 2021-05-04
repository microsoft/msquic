/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "mtu_discovery.c.clog.h"
#endif

#define MTU_INCREMENT 80

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicMtuDiscoverySendProbePacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DPLPMTUD);
    //QuicConnTimerSet(Connection, QUIC_CONN_TIMER_DPLPMTUD, QUIC_DPLPMTUD_PROBE_TIMER_TIMEOUT);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicMtuDiscoveryMoveToSearchComplete(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE;
    QuicConnTimerSet(Connection, QUIC_CONN_TIMER_DPLPMTUD, QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint16_t
QuicGetNextProbeSize(
    _In_ const QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    uint16_t Mtu = MtuDiscovery->CurrentMtu + MTU_INCREMENT;
    if (Mtu > MtuDiscovery->MaxMtu) {
        Mtu = MtuDiscovery->MaxMtu;
    } else if (Mtu == 1520) {
        //
        // 1520 is the 4th multiplier, but we want 1500, so force that.
        //
        Mtu = 1500;
    }
    printf("Probing %u\n", Mtu);
    return Mtu;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCHING;
    MtuDiscovery->ProbeCount = 0;
    MtuDiscovery->ProbedSize = QuicGetNextProbeSize(MtuDiscovery);

    QuicMtuDiscoverySendProbePacket(MtuDiscovery);
}

//
// Called when a new path is initialized.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryNewPath(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_PATH* Path
    )
{
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    MtuDiscovery->MaxMtu = QuicConnGetMaxMtuForPath(Connection, Path);
    MtuDiscovery->MinMtu = Path->Mtu;
    MtuDiscovery->CurrentMtu = Path->Mtu;

    //MtuDiscovery->MaxMtuProbeWindow = MtuDiscovery->MaxMtu;
    //MtuDiscovery->MinMtuProbeWindow = MtuDiscovery->MinMtu;

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicMtuDiscoveryOnAckedPacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // If out of order receives are received, ignore the packet
    //
    if (PacketMtu != MtuDiscovery->ProbedSize) {
        return FALSE;
    }

    MtuDiscovery->CurrentMtu = MtuDiscovery->ProbedSize;
    Path->Mtu = MtuDiscovery->ProbedSize;
    printf("Mtu updated to %u\n", Path->Mtu);
    QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);

    if (Path->Mtu == MtuDiscovery->MaxMtu) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
        return TRUE;
    }

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryProbePacketDiscarded(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu
    )
{
    //
    // If out of order receives are received, ignore the packet
    //
    if (PacketMtu != MtuDiscovery->ProbedSize) {
        return;
    }

    if (MtuDiscovery->ProbeCount >= QUIC_DPLPMTUD_MAX_PROBES - 1) {
        printf("Moving to search complete\n");
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
        return;
    }
    MtuDiscovery->ProbeCount++;
    printf("Retrying %u %u times\n", MtuDiscovery->ProbedSize, MtuDiscovery->ProbeCount);
    QuicMtuDiscoverySendProbePacket(MtuDiscovery);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryTimerExpired(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    if (MtuDiscovery->State == QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE) {
        //
        // Expired PMTU_RAISE_TIMER. If we're already at max MTU, we can't do anything.
        //
        if (MtuDiscovery->CurrentMtu == MtuDiscovery->MaxMtu) {
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
        QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    }
    // } else {
    //     //
    //     // Expired PROBE_TIMER
    //     //
    //     if (MtuDiscovery->ProbeCount >= QUIC_DPLPMTUD_MAX_PROBES - 1) {
    //         QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
    //         return;
    //     }
    //     MtuDiscovery->ProbeCount++;
    //     QuicMtuDiscoverySendProbePacket(MtuDiscovery);
    // }
}
