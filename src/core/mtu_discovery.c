/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This module handles the MTU discovery logic.

    Upon a new path being validated, MTU discovery is started on that path.
    This is done by sending a probe packet larger than the current MTU.

    If the probe packet is acknowledged, that is set as the current MTU and a
    new probe packet is sent. This is repeated until the maximum allowed MTU is
    reached.

    If a probe packet is not ACKed, the probe at the same size will be retried.
    If this fails QUIC_DPLPMTUD_MAX_PROBES times, max MTU is considered found
    and searching stops.

    Once searching has stopped, discovery will stay idle until
    QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT has passed. The next send will then
    trigger a new MTU discovery period, unless maximum allowed MTU is already
    reached.

    The current algorithm is very simplistic, increasing by 80 bytes each
    probe. A special case is added so 1500 is always a checked value, as 1500
    is often the max allowed over the internet.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "mtu_discovery.c.clog.h"
#endif

CXPLAT_STATIC_ASSERT(CXPLAT_MAX_MTU >= QUIC_DPLPMUTD_DEFAULT_MAX_MTU, L"Default max must not be more than max");

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
    MtuDiscovery->IsSearching = FALSE;
    MtuDiscovery->SearchCompleteEnterTimeUs = CxPlatTimeUs64();
    QuicTraceLogConnInfo(
        MtuSearchComplete,
        Connection,
        "Mtu Discovery Entering Search Complete at MTU %u",
        MtuDiscovery->CurrentMtu);
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

    uint16_t Mtu = MtuDiscovery->CurrentMtu + QUIC_DPLPMTUD_INCREMENT;
    if (Mtu > MtuDiscovery->MaxMtu) {
        Mtu = MtuDiscovery->MaxMtu;
    } else if (Mtu == 1520) {
        //
        // 1520 is computed by the current algorithm, but we want 1500, so force that.
        // Changing QUIC_DPLPMTUD_INCREMENT requires changing this logic, as does
        // changing the initial MTU.
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
    MtuDiscovery->IsSearching = TRUE;
    MtuDiscovery->ProbeCount = 0;
    MtuDiscovery->ProbedSize = QuicGetNextProbeSize(MtuDiscovery);
    if (MtuDiscovery->ProbedSize == MtuDiscovery->CurrentMtu) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery);
        return;
    }
    QuicTraceLogConnInfo(
        MtuSearching,
        Connection,
        "Mtu Discovery Search Packet Sending with MTU %u",
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
    CXPLAT_DBG_ASSERT(MtuDiscovery->MinMtu <= MtuDiscovery->CurrentMtu &&
                      MtuDiscovery->CurrentMtu <= MtuDiscovery->MaxMtu);

    QuicTraceLogConnInfo(
        MtuPathInitialized,
        Connection,
        "Mtu Discovery Path[%hhu] Initialized: max_mtu=%u, min_mtu=%u, cur_mtu=%u",
        Path->ID,
        MtuDiscovery->MaxMtu,
        MtuDiscovery->MinMtu,
        MtuDiscovery->CurrentMtu);

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicMtuDiscoveryOnAckedPacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu,
    _In_ QUIC_PATH* Path
    )
{
    QUIC_CONNECTION* Connection =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_CONNECTION, MtuDiscovery);
    //
    // If out of order receives are received, ignore the packet
    //
    if (PacketMtu != MtuDiscovery->ProbedSize) {
        QuicTraceLogConnVerbose(
            MtuIncorrectSize,
            Connection,
            "Mtu Discovery Received Out of Order: expected=%u received=%u",
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
        QuicTraceLogConnVerbose(
            MtuIncorrectSize,
            Connection,
            "Mtu Discovery Received Out of Order: expected=%u received=%u",
            MtuDiscovery->ProbedSize,
            PacketMtu);
        return;
    }

    QuicTraceLogConnInfo(
        MtuDiscarded,
        Connection,
        "Mtu Discovery Packet Discarded: size=%u, probe_count=%u",
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
