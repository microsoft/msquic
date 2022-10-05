/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Per path functionality for the connection.

TODO:

    Make Path ETW events.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "path.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    CxPlatZeroMemory(Path, sizeof(QUIC_PATH));
    Path->ID = Connection->NextPathId++; // TODO - Check for duplicates after wrap around?
    Path->MinRtt = UINT32_MAX;
    Path->Mtu = Connection->Settings.MinimumMtu;
    Path->SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
    Path->RttVariance = Path->SmoothedRtt / 2;

    QuicTraceLogConnInfo(
        PathInitialized,
        Connection,
        "Path[%hhu] Initialized",
        Path->ID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Index
    )
{
    CXPLAT_DBG_ASSERT(Index < Connection->PathsCount);
    const QUIC_PATH* Path = &Connection->Paths[Index];
    QuicTraceLogConnInfo(
        PathRemoved,
        Connection,
        "Path[%hhu] Removed",
        Path->ID);

#if DEBUG
    if (Path->DestCid) {
        QUIC_CID_CLEAR_PATH(Path->DestCid);
    }
#endif

    if (Index + 1 < Connection->PathsCount) {
        CxPlatMoveMemory(
            Connection->Paths + Index,
            Connection->Paths + Index + 1,
            (Connection->PathsCount - Index - 1) * sizeof(QUIC_PATH));
    }

    Connection->PathsCount--;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t NewAllowance
    )
{
    Path->Allowance = NewAllowance;
    BOOLEAN IsBlocked = Path->Allowance < QUIC_MIN_SEND_ALLOWANCE;

    if (!Path->IsPeerValidated) {
        if (!IsBlocked) {
            if (QuicConnRemoveOutFlowBlockedReason(
                    Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {

                if (Connection->Send.SendFlags != 0) {
                    //
                    // We were blocked by amplification protection (no allowance
                    // left) and we have stuff to send, so flush the send now.
                    //
                    QuicSendQueueFlush(&Connection->Send, REASON_AMP_PROTECTION);
                }

                //
                // Now that we are no longer blocked by amplification protection
                // we need to re-enable the loss detection timers. This call may
                // even cause the loss timer to fire immediately because packets
                // were already lost, but we didn't know it.
                //
                QuicLossDetectionUpdateTimer(&Connection->LossDetection, TRUE);
            }

        } else {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetValid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_PATH_VALID_REASON Reason
    )
{
    if (Path->IsPeerValidated) {
        return;
    }

    const char* ReasonStrings[] = {
        "Initial Token",
        "Handshake Packet",
        "Path Response"
    };

    QuicTraceLogConnInfo(
        PathValidated,
        Connection,
        "Path[%hhu] Validated (%s)",
        Path->ID,
        ReasonStrings[Reason]);

    Path->IsPeerValidated = TRUE;
    QuicPathSetAllowance(Connection, Path, UINT32_MAX);

    if (Reason == QUIC_PATH_VALID_PATH_RESPONSE) {
        //
        // If the active path was just validated, then let's queue up DPLPMTUD.
        // This will force validate min mtu if it has not already been
        // validated.
        //
        QuicMtuDiscoveryPeerValidated(&Path->MtuDiscovery, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
_Success_(return != NULL)
QUIC_PATH*
QuicConnGetPathByID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t ID,
    _Out_ uint8_t* Index
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].ID == ID) {
            *Index = i;
            return &Connection->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCopyRouteInfo(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
#ifdef QUIC_USE_RAW_DATAPATH
    CxPlatCopyMemory(DstRoute, SrcRoute, (uint8_t*)&SrcRoute->State - (uint8_t*)SrcRoute);
#else
    *DstRoute = *SrcRoute;
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForDatagram(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const CXPLAT_RECV_DATA* Datagram
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (!QuicAddrCompare(
                &Datagram->Route->LocalAddress,
                &Connection->Paths[i].Route.LocalAddress) ||
            !QuicAddrCompare(
                &Datagram->Route->RemoteAddress,
                &Connection->Paths[i].Route.RemoteAddress)) {
            if (!Connection->State.HandshakeConfirmed) {
                //
                // Ignore packets on any other paths until connected/confirmed.
                //
                return NULL;
            }
            continue;
        }
        return &Connection->Paths[i];
    }

    if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
        //
        // See if any old paths share the same remote address, and is just a rebind.
        // If so, remove the old paths.
        // NB: Traversing the array backwards is simpler and more efficient here due
        // to the array shifting that happens in QuicPathRemove.
        //
        for (uint8_t i = Connection->PathsCount - 1; i > 0; i--) {
            if (!Connection->Paths[i].IsActive
                && QuicAddrGetFamily(&Datagram->Route->RemoteAddress) == QuicAddrGetFamily(&Connection->Paths[i].Route.RemoteAddress)
                && QuicAddrCompareIp(&Datagram->Route->RemoteAddress, &Connection->Paths[i].Route.RemoteAddress)
                && QuicAddrCompare(&Datagram->Route->LocalAddress, &Connection->Paths[i].Route.LocalAddress)) {
                QuicPathRemove(Connection, i);
            }
        }

        if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
            //
            // Already tracking the maximum number of paths, and can't free
            // any more.
            //
            return NULL;
        }
    }

    if (Connection->PathsCount > 1) {
        //
        // Make room for the new path (at index 1).
        //
        CxPlatMoveMemory(
            &Connection->Paths[2],
            &Connection->Paths[1],
            (Connection->PathsCount - 1) * sizeof(QUIC_PATH));
    }

    QUIC_PATH* Path = &Connection->Paths[1];
    QuicPathInitialize(Connection, Path);
    Connection->PathsCount++;

    if (Connection->Paths[0].DestCid->CID.Length == 0) {
        Path->DestCid = Connection->Paths[0].DestCid; // TODO - Copy instead?
    }
    Path->Binding = Connection->Paths[0].Binding;
    QuicCopyRouteInfo(&Path->Route, Datagram->Route);
    QuicPathValidate(Path);

    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    BOOLEAN UdpPortChangeOnly = FALSE;
    if (Path == &Connection->Paths[0]) {
        CXPLAT_DBG_ASSERT(!Path->IsActive);
        Path->IsActive = TRUE;
    } else {
        CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
        UdpPortChangeOnly =
            QuicAddrGetFamily(&Path->Route.RemoteAddress) == QuicAddrGetFamily(&Connection->Paths[0].Route.RemoteAddress) &&
            QuicAddrCompareIp(&Path->Route.RemoteAddress, &Connection->Paths[0].Route.RemoteAddress);

        QUIC_PATH PrevActivePath = Connection->Paths[0];

        PrevActivePath.IsActive = FALSE;
        Path->IsActive = TRUE;
        if (UdpPortChangeOnly) {
            //
            // We assume port only changes don't change the PMTU.
            //
            Path->IsMinMtuValidated = PrevActivePath.IsMinMtuValidated;
        }

        Connection->Paths[0] = *Path;
        *Path = PrevActivePath;
    }

    QuicTraceLogConnInfo(
        PathActive,
        Connection,
        "Path[%hhu] Set active (rebind=%hhu)",
        Connection->Paths[0].ID,
        UdpPortChangeOnly);

    if (!UdpPortChangeOnly) {
        QuicCongestionControlReset(&Connection->CongestionControl, FALSE);
    }
    CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
    CXPLAT_DBG_ASSERT(!Path->DestCid->CID.Retired);
}
