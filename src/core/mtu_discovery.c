/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "mtu_discovery.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
QuicMtuDiscoveryMoveToSearchComplete(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE;

    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    QuicConnTimerSet(Connection, QUIC_CONN_TIMER_DPLPMTUD, QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
QuicMtuDiscoverySendProbePacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ BOOLEAN IncreaseProbeSize
    )
{
    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCHING;
    if (IncreaseProbeSize) {
        MtuDiscovery->ProbeCount = 0;
        //
        // TODO improve this algorithm
        //
        MtuDiscovery->ProbedSize += 40;
        if (MtuDiscovery->ProbedSize > MtuDiscovery->MaxMTU) {
            MtuDiscovery->ProbedSize = MtuDiscovery->MaxMTU;
        }
    }
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DPLPMTUD);
    QuicConnTimerSet(Connection, QUIC_CONN_TIMER_DPLPMTUD, QUIC_DPLPMTUD_PROBE_TIMER_TIMEOUT);
}

//
// Called when a new path is initialized.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicMtuDiscoveryNewPath(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t MaxMTU
    )
{
    MtuDiscovery->CurrentMTU = QUIC_DEFAULT_PATH_MTU;
    MtuDiscovery->MaxMTU = MaxMTU;
    MtuDiscovery->ProbedSize = QUIC_DEFAULT_PATH_MTU;

    QuicMtuDiscoverySendProbePacket(MtuDiscovery, FALSE);
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
        return FALSE;
    }

    MtuDiscovery->CurrentMTU = MtuDiscovery->ProbedSize;
    Path->Mtu = MtuDiscovery->CurrentMTU;
    QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);

    if (MtuDiscovery->ProbedSize == MtuDiscovery->MaxMTU) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
        return TRUE;
    }

    QuicMtuDiscoverySendProbePacket(MtuDiscovery, TRUE);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicMtuDiscoveryTimerExpired(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    if (MtuDiscovery->State == QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE) {
        //
        // Expired PMTU_RAISE_TIMER. If we're already at max MTU, we can't do anything.
        //
        if (MtuDiscovery->CurrentMTU == MtuDiscovery->MaxMTU) {
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
        QuicMtuDiscoverySendProbePacket(MtuDiscovery, TRUE);
    } else {
        //
        // Expired PROBE_TIMER
        //
        if (MtuDiscovery->ProbeCount >= QUIC_DPLPMTUD_MAX_PROBES) {
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
        MtuDiscovery->ProbeCount++;
        QuicMtuDiscoverySendProbePacket(MtuDiscovery, FALSE);
    }
}
