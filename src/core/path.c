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
    QuicZeroMemory(Path, sizeof(QUIC_PATH));
    Path->ID = Connection->NextPathId++; // TODO - Check for duplicates after wrap around?
    Path->MinRtt = UINT32_MAX;
    Path->Mtu = QUIC_DEFAULT_PATH_MTU;
    if (Connection->Session != NULL) {
        Path->SmoothedRtt = MS_TO_US(Connection->Session->Settings.InitialRttMs);
    } else {
        Path->SmoothedRtt = MS_TO_US(QUIC_INITIAL_RTT);
    }

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
    QUIC_DBG_ASSERT(Index < Connection->PathsCount);
    const QUIC_PATH* Path = &Connection->Paths[Index];
    QuicTraceLogConnInfo(
        PathRemoved,
        Connection,
        "Path[%hhu] Removed",
        Path->ID);

    if (Index + 1 < Connection->PathsCount) {
        QuicMoveMemory(
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
    BOOLEAN WasBlocked = Path->Allowance < QUIC_MIN_SEND_ALLOWANCE;
    Path->Allowance = NewAllowance;

    if (!Path->IsPeerValidated &&
        (Path->Allowance < QUIC_MIN_SEND_ALLOWANCE) != WasBlocked) {
        if (WasBlocked) {
            QuicConnRemoveOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
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
            // even cause the loss timer to fire (be queued) immediately
            // because packets were already lost, but we didn't know it.
            //
            QuicLossDetectionUpdateTimer(&Connection->LossDetection);
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

    if (Path->IsPeerValidated && Reason == QUIC_PATH_VALID_PATH_RESPONSE) {
        //
        // If the active path was just validated, then let's queue up a PMTUD
        // packet.
        //
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PMTUD);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathByID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t ID
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].ID == ID) {
            return &Connection->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForDatagram(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RECV_DATAGRAM* Datagram
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (!QuicAddrCompare(
                &Datagram->Tuple->LocalAddress,
                &Connection->Paths[i].LocalAddress) ||
            !QuicAddrCompare(
                &Datagram->Tuple->RemoteAddress,
                &Connection->Paths[i].RemoteAddress)) {
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
        // Already tracking the maximum number of paths.
        //
        return NULL;
    }

    if (Connection->PathsCount > 1) {
        //
        // Make room for the new path (at index 1).
        //
        QuicMoveMemory(
            &Connection->Paths[2],
            &Connection->Paths[1],
            (Connection->PathsCount - 1) * sizeof(QUIC_PATH));
    }

    QUIC_PATH* Path = &Connection->Paths[1];
    QuicPathInitialize(Connection, Path);
    Connection->PathsCount++;

    Path->DestCid = Connection->Paths[0].DestCid;
    Path->Binding = Connection->Paths[0].Binding;
    Path->LocalAddress = Datagram->Tuple->LocalAddress;
    Path->RemoteAddress = Datagram->Tuple->RemoteAddress;

    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    QUIC_DBG_ASSERT(Path != &Connection->Paths[0]);

    BOOLEAN UdpPortChangeOnly =
        QuicAddrGetFamily(&Path->RemoteAddress) == QuicAddrGetFamily(&Connection->Paths[0].RemoteAddress) &&
        QuicAddrCompareIp(&Path->RemoteAddress, &Connection->Paths[0].RemoteAddress);

    QuicTraceLogConnInfo(
        PathActive,
        Connection,
        "Path[%hhu] Set active (rebind=%hhu)",
        Path->ID,
        UdpPortChangeOnly);

    QUIC_PATH PrevActivePath = Connection->Paths[0];

    PrevActivePath.IsActive = FALSE;
    Path->IsActive = TRUE;

    Connection->Paths[0] = *Path;
    *Path = PrevActivePath;

    if (!UdpPortChangeOnly) {
        QuicCongestionControlReset(&Connection->CongestionControl);
    }
}
