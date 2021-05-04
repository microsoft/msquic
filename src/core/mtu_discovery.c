/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "mtu_discovery.c.clog.h"
#endif

#define MTU_LOOKUP_TABLE_LENGTH 7

static
const
uint16_t
QuicMtuLookupTable[MTU_LOOKUP_TABLE_LENGTH] = {
    QUIC_DEFAULT_PATH_MTU,
    1360,
    1400,
    1500,
    3000,
    5000,
    10000
};

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
QuicMtuDiscoverySendProbePacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    printf("Trying MTU of %u\n", MtuDiscovery->ProbedSize);
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DPLPMTUD);
    QuicConnTimerSet(Connection, QUIC_CONN_TIMER_DPLPMTUD, QUIC_DPLPMTUD_PROBE_TIMER_TIMEOUT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    CXPLAT_DBG_ASSERT(MtuDiscovery->CurrentMtuIndex + 1 < MTU_LOOKUP_TABLE_LENGTH);

    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCHING;
    MtuDiscovery->ProbeCount = 0;
    MtuDiscovery->ProbedSize = QuicMtuLookupTable[MtuDiscovery->CurrentMtuIndex + 1];
    if (MtuDiscovery->ProbedSize > MtuDiscovery->MaxMtu) {
        MtuDiscovery->ProbedSize = MtuDiscovery->MaxMtu;
    }

    QuicMtuDiscoverySendProbePacket(MtuDiscovery);
}

//
// Called when a new path is initialized.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicMtuDiscoveryNewPath(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_PATH* Path,
    _In_ uint16_t MaxMtu
    )
{
    CXPLAT_DBG_ASSERT(Path->Mtu == QuicMtuLookupTable[0]);

    MtuDiscovery->MaxMtu = MaxMtu;
    MtuDiscovery->CurrentMtuIndex = 0;

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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
        printf("Probe Failure Receive %u %u\n", PacketMtu, MtuDiscovery->ProbedSize);
        return FALSE;
    }

    MtuDiscovery->CurrentMtuIndex++;
    Path->Mtu = MtuDiscovery->ProbedSize;
    printf("Updating MTU to %u\n", Path->Mtu);
    QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);

    if (MtuDiscovery->CurrentMtuIndex >= MTU_LOOKUP_TABLE_LENGTH || Path->Mtu == MtuDiscovery->MaxMtu) {
        MtuDiscovery->CurrentMtuIndex = MTU_LOOKUP_TABLE_LENGTH;
        printf("Moving to Search Complete because of max MTU\n");
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
        return TRUE;
    }

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicMtuDiscoveryTimerExpired(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    if (MtuDiscovery->State == QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE) {
        printf("PMTU_RAISE_TIMER Expired\n");
        //
        // Expired PMTU_RAISE_TIMER. If we're already at max MTU, we can't do anything.
        //
        if (MtuDiscovery->CurrentMtuIndex >= MTU_LOOKUP_TABLE_LENGTH) {
            printf("Staying in search complete\n");
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
        printf("Leaving search complete\n");
        QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    } else {
        printf("Probe Timer Expired %u\n", MtuDiscovery->ProbeCount);
        //
        // Expired PROBE_TIMER
        //
        if (MtuDiscovery->ProbeCount >= QUIC_DPLPMTUD_MAX_PROBES - 1) {
            printf("Moving to Search Complete because of max probes\n");
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
        MtuDiscovery->ProbeCount++;
        QuicMtuDiscoverySendProbePacket(MtuDiscovery);
    }
}
