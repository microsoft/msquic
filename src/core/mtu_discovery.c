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
CXPLAT_STATIC_ASSERT(QUIC_DPLPMUTD_MIN_MTU <= QUIC_DPLPMUTD_DEFAULT_MIN_MTU, L"Default min must not be more than min");

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicMtuDiscoverySendProbePacket(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DPLPMTUD);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicMtuDiscoveryMoveToSearchComplete(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH* Path =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_PATH, MtuDiscovery);
    MtuDiscovery->IsSearchComplete = TRUE;
    MtuDiscovery->SearchCompleteEnterTimeUs = CxPlatTimeUs64();
    QuicTraceLogConnInfo(
        MtuSearchComplete,
        Connection,
        "Path[%hhu] Mtu Discovery Entering Search Complete at MTU %hu",
        Path->ID,
        Path->Mtu);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint16_t
QuicGetNextProbeSize(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery
    )
{
    QUIC_PATH* Path =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_PATH, MtuDiscovery);
    //
    // N.B. This algorithm must always be increasing. Other logic in the module
    // depends on that behavior.
    //

    //
    // Jump automatically to 1280 to return algorithm to ideal case. 1280 should
    // be supported in most scenarios. With minimum being 1248, this will always
    // be less then a full increment.
    //
    if (Path->Mtu < 1280) {
        return CXPLAT_MIN(1280, MtuDiscovery->MaxMtu);
    }

    uint16_t Mtu = Path->Mtu + QUIC_DPLPMTUD_INCREMENT;
    if (Mtu > MtuDiscovery->MaxMtu) {
        Mtu = MtuDiscovery->MaxMtu;
    }

    //
    // Our increasing algorithm might not hit 1500 by default. Ensure that
    // happens.
    //
    if (!MtuDiscovery->HasProbed1500 && Mtu >= 1500) {
        MtuDiscovery->HasProbed1500 = TRUE;
        Mtu = 1500;
    }
    return Mtu;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryMoveToSearching(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH* Path =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_PATH, MtuDiscovery);
    MtuDiscovery->IsSearchComplete = FALSE;
    MtuDiscovery->ProbeCount = 0;
    //
    // If the path has not had min MTU validated, send probe for min MTU.
    //
    MtuDiscovery->ProbeSize =
        Path->IsMinMtuValidated ?
            QuicGetNextProbeSize(MtuDiscovery) :
            Path->Mtu;

    //
    // If we're attempting to probe the current MTU, and min MTU is validated
    // then we've hit max allowed MTU. Enter search complete.
    //
    if (MtuDiscovery->ProbeSize == Path->Mtu && Path->IsMinMtuValidated) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery, Connection);
        return;
    }
    QuicTraceLogConnInfo(
        MtuSearching,
        Connection,
        "Path[%hhu] Mtu Discovery Search Packet Sending with MTU %hu",
        Path->ID,
        MtuDiscovery->ProbeSize);

    QuicMtuDiscoverySendProbePacket(Connection);
}

//
// Called when a new path is initialized.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryPeerValidated(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH* Path =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_PATH, MtuDiscovery);

    //
    // The minimum allowed MTU for the connection is what Path->Mtu is set to by
    // default
    //
    MtuDiscovery->MaxMtu = QuicConnGetMaxMtuForPath(Connection, Path);
    MtuDiscovery->HasProbed1500 = Path->Mtu >= 1500;
    CXPLAT_DBG_ASSERT(Path->Mtu <= MtuDiscovery->MaxMtu);

    QuicTraceLogConnInfo(
        MtuPathInitialized,
        Connection,
        "Path[%hhu] Mtu Discovery Initialized: max_mtu=%u, cur/min_mtu=%u",
        Path->ID,
        MtuDiscovery->MaxMtu,
        Path->Mtu);

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery, Connection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicMtuDiscoveryOnAckedPacket(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ uint16_t PacketMtu,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH* Path =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_PATH, MtuDiscovery);
    //
    // If out of order receives are received, ignore the packet
    //
    if (PacketMtu != MtuDiscovery->ProbeSize) {
        QuicTraceLogConnVerbose(
            MtuIncorrectSize,
            Connection,
            "Path[%hhu] Mtu Discovery Received Out of Order: expected=%u received=%u",
            Path->ID,
            MtuDiscovery->ProbeSize,
            PacketMtu);
        return FALSE;
    }

    //
    // Received packet is new MTU. If we've hit max MTU, enter searching as we can't go
    // higher, otherwise attept next MTU size.
    //
    Path->Mtu = MtuDiscovery->ProbeSize;
    QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);

    if (Path->Mtu == MtuDiscovery->MaxMtu) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery, Connection);
        return TRUE;
    }

    QuicMtuDiscoveryMoveToSearching(MtuDiscovery, Connection);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicMtuDiscoveryProbePacketDiscarded(
    _In_ QUIC_MTU_DISCOVERY* MtuDiscovery,
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t PacketMtu
    )
{
    QUIC_PATH* Path =
        CXPLAT_CONTAINING_RECORD(MtuDiscovery, QUIC_PATH, MtuDiscovery);
    //
    // If out of order receives are received, ignore the packet
    //
    if (PacketMtu != MtuDiscovery->ProbeSize) {
        QuicTraceLogConnVerbose(
            MtuIncorrectSize,
            Connection,
            "Path[%hhu] Mtu Discovery Received Out of Order: expected=%u received=%u",
            Path->ID,
            MtuDiscovery->ProbeSize,
            PacketMtu);
        return;
    }

    QuicTraceLogConnInfo(
        MtuDiscarded,
        Connection,
        "Path[%hhu] Mtu Discovery Packet Discarded: size=%u, probe_count=%u",
        Path->ID,
        MtuDiscovery->ProbeSize,
        MtuDiscovery->ProbeCount);

    //
    // If we've done max probes, we've found our max, enter search complete
    // waiting phase. Otherwise send out another probe of the same size.
    //
    if (MtuDiscovery->ProbeCount >=
            (int16_t)Connection->Settings.MtuDiscoveryMissingProbeCount - 1) {
        QuicMtuDiscoveryMoveToSearchComplete(MtuDiscovery, Connection);
        return;
    }
    MtuDiscovery->ProbeCount++;
    QuicMtuDiscoverySendProbePacket(Connection);
}
