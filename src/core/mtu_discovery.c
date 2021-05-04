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
QuicMtuDiscoverySendProbePacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    //printf("Trying MTU of %u\n", MtuDiscovery->ProbedSize);
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
uint16_t
QuicGetNextProbeSize(
    _In_ const QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    if (MtuDiscovery->MaxMtu <= 1500 &&
        MtuDiscovery->MaxMtu == MtuDiscovery->MaxMtuProbeWindow) {
        //
        // First try the max value if less than ethernet size
        //
        return MtuDiscovery->MaxMtu;
    }
    //
    // Binary Search to find the best match
    //

}

_IRQL_requires_max_(DISPATCH_LEVEL)
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
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicMtuDiscoveryNewPath(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_PATH* Path
    )
{
    QUIC_CONNECTION* Connection = CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    uint16_t LocalMtu = CxPlatSocketGetLocalMtu(Path->Binding->Socket);
    uint16_t RemoteMtu = 0xFFFF;
    if ((Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE)) {
        RemoteMtu = (uint16_t)Connection->PeerTransportParams.MaxUdpPayloadSize;
    }
    // TODO add settings
    MtuDiscovery->MaxMtu = min(LocalMtu, RemoteMtu);
    MtuDiscovery->MinMtu = Path->Mtu;
    MtuDiscovery->CurrentMtu = Path->Mtu;

    MtuDiscovery->MaxMtuProbeWindow = MtuDiscovery->MaxMtu;
    MtuDiscovery->MinMtuProbeWindow = MtuDiscovery->MinMtu;

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
        //printf("Probe Failure Receive %u %u\n", PacketMtu, MtuDiscovery->ProbedSize);
        return FALSE;
    }

    MtuDiscovery->CurrentMtu = MtuDiscovery->ProbedSize;
    Path->Mtu = MtuDiscovery->ProbedSize;
    //printf("Updating MTU to %u\n", Path->Mtu);
    QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);

    if (Path->Mtu == MtuDiscovery->MaxMtu) {
        //printf("Moving to Search Complete because of max MTU\n");
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
       // printf("PMTU_RAISE_TIMER Expired\n");
        //
        // Expired PMTU_RAISE_TIMER. If we're already at max MTU, we can't do anything.
        //
        if (MtuDiscovery->CurrentMtu == MtuDiscovery->MaxMtu) {
         //   printf("Staying in search complete\n");
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
       // printf("Leaving search complete\n");
        QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
    } else {
//printf("Probe Timer Expired %u\n", MtuDiscovery->ProbeCount);
        //
        // Expired PROBE_TIMER
        //
        if (MtuDiscovery->ProbeCount >= QUIC_DPLPMTUD_MAX_PROBES - 1) {
      //      printf("Moving to Search Complete because of max probes\n");
            QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
            return;
        }
        MtuDiscovery->ProbeCount++;
        QuicMtuDiscoverySendProbePacket(MtuDiscovery);
    }
}
