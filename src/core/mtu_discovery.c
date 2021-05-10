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
    QUIC_CONNECTION* Connection =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DPLPMTUD);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicMtuDiscoveryMoveToSearchComplete(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_CONNECTION* Connection =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCH_COMPLETE;
    MtuDiscovery->SearchWaitingEnterTime = CxPlatTimeUs64();
    QuicTraceLogConnInfo(
        MtuProbeMoveToSearchComplete,
        Connection,
        "Mtu Probe Entering Search Complete at MTU %u and time %llu",
        MtuDiscovery->CurrentMtu,
        (long long unsigned)MtuDiscovery->SearchWaitingEnterTime);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint16_t
QuicGetNextProbeSize(
    _In_ const QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    //
    // N.B. This algorithm must always be increasing. Other logic in the module
    // depends on that behavior.
    //

    uint16_t Mtu = MtuDiscovery->CurrentMtu + MTU_INCREMENT;
    if (Mtu > MtuDiscovery->MaxMtu) {
        Mtu = MtuDiscovery->MaxMtu;
    } else if (Mtu == 1520) {
        //
        // 1520 is computed by the current algorithm, but we want 1500, so force that.
        // Changing MTU_INCREMENT requires changing this logic, as does changing the
        // initial MTU
        //
        Mtu = 1500;
    }
    return Mtu;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_CONNECTION* Connection =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    MtuDiscovery->State = QUIC_MTU_DISCOVERY_STATE_SEARCHING;
    MtuDiscovery->ProbeCount = 0;
    MtuDiscovery->ProbedSize = QuicGetNextProbeSize(MtuDiscovery);
    QuicTraceLogConnInfo(
        MtuProbeMoveToSearching,
        Connection,
        "Mtu Probe Search Packet Sending with MTU %u",
        MtuDiscovery->ProbedSize);

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
    QUIC_CONNECTION* Connection =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    //
    // As the only way to enter this is on a validated path, we know that the minimum
    // MTU must at least be the current path MTU.
    //
    MtuDiscovery->MaxMtu = QuicConnGetMaxMtuForPath(Connection, Path);
    MtuDiscovery->MinMtu = Path->Mtu;
    MtuDiscovery->CurrentMtu = Path->Mtu;

    QuicTraceLogConnInfo(
        MtuProbePathInitialized,
        Connection,
        "Mtu Probe Path[%hhu] Initialized: max_mtu=%u, min_mtu=%u, cur_mtu=%u",
        Path->ID,
        MtuDiscovery->MaxMtu,
        MtuDiscovery->MinMtu,
        MtuDiscovery->CurrentMtu);

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
        QuicTraceLogConnInfo(
            MtuProbeIncorrectSize,
            Connection,
            "Mtu Probe Received Out of Order: expected=%u received=%u",
            MtuDiscovery->ProbedSize,
            PacketMtu);
        return FALSE;
    }

    //
    // Received packet is new MTU. If we've hit max MTU, enter searching as we can't go
    // higher, otherwise attept next MTU size.
    //
    MtuDiscovery->CurrentMtu = MtuDiscovery->ProbedSize;
    Path->Mtu = MtuDiscovery->ProbedSize;
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
    QUIC_CONNECTION* Connection =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    //
    // If out of order receives are received, ignore the packet
    //
    if (PacketMtu != MtuDiscovery->ProbedSize) {
        QuicTraceLogConnInfo(
            MtuProbeIncorrectSize,
            Connection,
            "Mtu Probe Received Out of Order: expected=%u received=%u",
            MtuDiscovery->ProbedSize,
            PacketMtu);
        return;
    }

    QuicTraceLogConnInfo(
        MtuProbeDiscarded,
        Connection,
        "Mtu Probe Packet Discarded: size=%u, probe_count=%u",
        MtuDiscovery->ProbedSize,
        MtuDiscovery->ProbeCount);

    //
    // If we've done max probes, we've found our max, enter search complete
    // waiting phase. Otherwise send out another probe of the same size.
    //
    if (MtuDiscovery->ProbeCount >= QUIC_DPLPMTUD_MAX_PROBES - 1) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
        return;
    }
    MtuDiscovery->ProbeCount++;
    QuicMtuDiscoverySendProbePacket(MtuDiscovery);
}
