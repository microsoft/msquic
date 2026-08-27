/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Per path functionality for the connection.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "path.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicPathInitialize(
    _In_ uint8_t PathId,
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_PATH* Path
    )
{
    CxPlatZeroMemory(Path, sizeof(QUIC_PATH));
    Path->ID = PathId; // TODO - Check for duplicates after wrap around?
    Path->InUse = TRUE;
    Path->MinRtt = UINT32_MAX;
    Path->Mtu = Connection->Settings.MinimumMtu;
    Path->SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
    Path->RttVariance = Path->SmoothedRtt / 2;
    Path->EcnValidationState =
        Connection->Settings.EcnEnabled ? ECN_VALIDATION_TESTING : ECN_VALIDATION_FAILED;

    if (Connection->Settings.QTIPEnabled) {
        CxPlatRandom(sizeof(Path->Route.TcpState.SequenceNumber), &Path->Route.TcpState.SequenceNumber);
    }

    QuicTraceEvent(
        ConnPathInitialized,
        "[conn][%p] Path[%hhu] Initialized",
        Connection,
        Path->ID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetInitialize(
    _Out_ QUIC_PATH_SET* PathSet,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CxPlatZeroMemory(PathSet, sizeof(*PathSet));
    QuicPathInitialize(PathSet->NextPathId++, Connection, &PathSet->Paths[0]);
    PathSet->Paths[0].IsActive = TRUE;
    PathSet->Count = 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_PATH*
QuicPathGetActive(
    _In_ const QUIC_PATH_SET* PathSet
    )
{
    CXPLAT_DBG_ASSERT(PathSet->Count > 0);
    CXPLAT_DBG_ASSERT(PathSet->Paths[0].IsActive);
    return (QUIC_PATH*)&PathSet->Paths[0];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t PathId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateActive(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    QUIC_PATH* ActivePath = QuicPathGetActive(PathSet);
    if (PathSet->NextActivePathId == ActivePath->ID) {
        //
        // The active path hasn't changed, nothing to do.
        //
        return;
    }

    QuicPathSetActive(Connection, PathSet->NextActivePathId);

    ActivePath = QuicPathGetActive(PathSet);
    QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(
            sizeof(ActivePath->Route.RemoteAddress),
            &ActivePath->Route.RemoteAddress)); // TODO - Addr removed event?

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
    Event.PEER_ADDRESS_CHANGED.Address = &ActivePath->Route.RemoteAddress;
    QuicTraceLogConnVerbose(
        IndicatePeerAddrChanged,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
    (void)QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Index
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    CXPLAT_DBG_ASSERT(PathSet->Count <= QUIC_MAX_PATH_COUNT);
    if (PathSet->Count == 0 ||
        Index >= QUIC_MAX_PATH_COUNT ||
        !PathSet->Paths[Index].InUse) {
        CXPLAT_TEL_ASSERTMSG(
            PathSet->Count > 0 &&
            Index < QUIC_MAX_PATH_COUNT &&
            PathSet->Paths[Index].InUse,
            "Double or out-of-range path removal!");
        return FALSE;
    }
    CXPLAT_DBG_ASSERT(Index < PathSet->Count);

    const QUIC_PATH* Path = &PathSet->Paths[Index];
    CXPLAT_DBG_ASSERT(Path->InUse);
    CXPLAT_DBG_ASSERT(
        PathSet->NextActivePathId == QuicPathGetActive(PathSet)->ID ||
        Path->ID != PathSet->NextActivePathId);
    QuicTraceEvent(
        ConnPathRemoved,
        "[conn][%p] Path[%hhu] Removed",
        Connection,
        Path->ID);

    if (PathSet->Count == 1) {
        //
        // Last remaining path. Silently close per RFC 9000 sections 8.2.4 +
        // 10.2, but leave the Paths array intact so in-flight operations see
        // a valid Paths[0] until shutdown completes.
        //
        if (!Connection->State.ClosedLocally) {
            QuicConnCloseLocally(
                Connection,
                QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                (uint64_t)QUIC_STATUS_UNREACHABLE,
                NULL);
        }
        return FALSE;
    }

    if (Index == 0) {
        CXPLAT_DBG_ASSERT(PathSet->Count > 1);
        //
        // Removing the active path while other paths exist. Promote the best
        // available fallback: prefer a peer-validated path, otherwise accept
        // any path.
        //
        uint8_t FallbackIndex = 1;
        for (uint8_t j = 1; j < PathSet->Count; ++j) {
            if (PathSet->Paths[j].IsPeerValidated) {
                FallbackIndex = j;
                break;
            }
        }
        QuicTraceLogConnInfo(
            PathActiveFallback,
            Connection,
            "Path[%hhu] removed; falling back to Path[%hhu]",
            Path->ID,
            PathSet->Paths[FallbackIndex].ID);
        QuicPathSetActive(Connection, PathSet->Paths[FallbackIndex].ID);
        //
        // After the swap the old active path now lives at FallbackIndex.
        // Fall through to remove it there.
        //
        Index = FallbackIndex;
    }

#if DEBUG
    if (PathSet->Paths[Index].DestCid) {
        QUIC_CID_CLEAR_PATH(PathSet->Paths[Index].DestCid);
    }
#endif

    if (Index + 1 < PathSet->Count) {
        CxPlatMoveMemory(
            PathSet->Paths + Index,
            PathSet->Paths + Index + 1,
            (PathSet->Count - Index - 1) * sizeof(QUIC_PATH));
    }

    PathSet->Count--;
    // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): False positive: new index is valid.
    PathSet->Paths[PathSet->Count].InUse = FALSE;
    return TRUE;
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

    QuicTraceEvent(
        ConnPathValidated,
        "[conn][%p] Path[%hhu] Validated (%hhu)",
        Connection,
        Path->ID,
        Reason);

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

    //
    // One fewer in-progress validation; re-evaluate (or cancel) the timer.
    //
    QuicConnPathValidationTimerUpdate(Connection);
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
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    for (uint8_t i = 0; i < PathSet->Count; ++i) {
        if (PathSet->Paths[i].ID == ID) {
            *Index = i;
            return &PathSet->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathMatchPacket(
    _In_ const QUIC_PATH* Path,
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    return
        QuicAddrCompare(
            &Packet->Route->LocalAddress,
            &Path->Route.LocalAddress) &&
        QuicAddrCompare(
            &Packet->Route->RemoteAddress,
            &Path->Route.RemoteAddress);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForPacket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    for (uint8_t i = 0; i < PathSet->Count; ++i) {
        if (!QuicPathMatchPacket(&PathSet->Paths[i], Packet)) {
            if (!Connection->State.HandshakeConfirmed) {
                //
                // Ignore packets on any other paths until connected/confirmed.
                //
                return NULL;
            }
            continue;
        }
        return &PathSet->Paths[i];
    }

    if (PathSet->Count == QUIC_MAX_PATH_COUNT) {
        //
        // See if any old paths share the same remote address, and is just a rebind.
        // If so, remove the old paths.
        // NB: Traversing the array backwards is simpler and more efficient here due
        // to the array shifting that happens in QuicPathRemove.
        //
        for (int i = PathSet->Count - 1; i > 0; i--) {
            if (!PathSet->Paths[i].IsActive
                && PathSet->Paths[i].ID != PathSet->NextActivePathId
                && QuicAddrGetFamily(&Packet->Route->RemoteAddress) == QuicAddrGetFamily(&PathSet->Paths[i].Route.RemoteAddress)
                && QuicAddrCompareIp(&Packet->Route->RemoteAddress, &PathSet->Paths[i].Route.RemoteAddress)
                && QuicAddrCompare(&Packet->Route->LocalAddress, &PathSet->Paths[i].Route.LocalAddress)) {
                QuicPathRemove(Connection, (uint8_t)i);
            }
        }

        if (PathSet->Count == QUIC_MAX_PATH_COUNT) {
            //
            // Already tracking the maximum number of paths, and can't free
            // any more.
            //
            return NULL;
        }
    }

    if (PathSet->Count > 1) {
        //
        // Make room for the new path (at index 1).
        //
        CxPlatMoveMemory(
            &PathSet->Paths[2],
            &PathSet->Paths[1],
            (PathSet->Count - 1) * sizeof(QUIC_PATH));
    }

    CXPLAT_DBG_ASSERT(PathSet->Count < QUIC_MAX_PATH_COUNT);
    QUIC_PATH* Path = &PathSet->Paths[1];
    QuicPathInitialize(PathSet->NextPathId++, Connection, Path);
    PathSet->Count++;

    QUIC_PATH* ActivePath = QuicPathGetActive(PathSet);
    if (ActivePath->DestCid->CID.Length == 0) {
        Path->DestCid = ActivePath->DestCid; // TODO - Copy instead?
    }
    Path->Binding = ActivePath->Binding;
    QuicCopyRouteInfo(&Path->Route, Packet->Route);
    QuicPathValidate(Path);

    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t PathId
    )
{
    BOOLEAN UdpPortChangeOnly = FALSE;
    uint8_t PathIndex;
    QUIC_PATH* Path = QuicConnGetPathByID(Connection, PathId, &PathIndex);
    CXPLAT_DBG_ASSERT(Path != NULL);

    QUIC_PATH* ActivePath = QuicPathGetActive(&Connection->Paths);
    if (Path == ActivePath) {
        CXPLAT_DBG_ASSERT(!Path->IsActive);
        Path->IsActive = TRUE;
    } else {
        CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
        UdpPortChangeOnly =
            QuicAddrGetFamily(&Path->Route.RemoteAddress) == QuicAddrGetFamily(&ActivePath->Route.RemoteAddress) &&
            QuicAddrCompareIp(&Path->Route.RemoteAddress, &ActivePath->Route.RemoteAddress);

        QUIC_PATH PrevActivePath = *ActivePath;

        PrevActivePath.IsActive = FALSE;
        Path->IsActive = TRUE;
        if (UdpPortChangeOnly) {
            //
            // We assume port only changes don't change the PMTU.
            //
            Path->IsMinMtuValidated = PrevActivePath.IsMinMtuValidated;
        }

        *ActivePath = *Path;
        *Path = PrevActivePath;
    }

    QuicTraceEvent(
        ConnPathActive,
        "[conn][%p] Path[%hhu] Set active (rebind=%hhu)",
        Connection,
        ActivePath->ID,
        UdpPortChangeOnly);

    if (!UdpPortChangeOnly) {
        QuicCongestionControlReset(&Connection->CongestionControl, FALSE);
    }
    Connection->Paths.NextActivePathId = ActivePath->ID;
    CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
    CXPLAT_DBG_ASSERT(!Path->DestCid->CID.Retired);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateQeo(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ CXPLAT_QEO_OPERATION Operation
    )
{
    const QUIC_CID_HASH_ENTRY* SourceCid =
        CXPLAT_CONTAINING_RECORD(Connection->SourceCids.Next, QUIC_CID_HASH_ENTRY, Link);
    CXPLAT_QEO_CONNECTION Offloads[2] = {
    {
        Operation,
        CXPLAT_QEO_DIRECTION_TRANSMIT,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        Connection->Send.NextPacketNumber,
        Path->Route.RemoteAddress,
        Path->DestCid->CID.Length,
    },
    {
        Operation,
        CXPLAT_QEO_DIRECTION_RECEIVE,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        0, // NextPacketNumber
        Path->Route.LocalAddress,
        SourceCid->CID.Length,
    }};
    CxPlatCopyMemory(Offloads[0].ConnectionId, Path->DestCid->CID.Data, Path->DestCid->CID.Length);
    CxPlatCopyMemory(Offloads[1].ConnectionId, SourceCid->CID.Data, SourceCid->CID.Length);

    if (Operation == CXPLAT_QEO_OPERATION_ADD) {
        CXPLAT_DBG_ASSERT(Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]);
        Offloads[0].KeyPhase = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].KeyPhase = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].NextPacketNumber = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->AckTracker.LargestPacketNumberAcknowledged;
        if (QuicTlsPopulateOffloadKeys(Connection->Crypto.TLS, Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT], "Tx offload", &Offloads[0]) &&
            QuicTlsPopulateOffloadKeys(Connection->Crypto.TLS, Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT],  "Rx offload", &Offloads[1]) &&
            QUIC_SUCCEEDED(CxPlatSocketUpdateQeo(Path->Binding->Socket, Offloads, 2))) {
            Connection->Stats.EncryptionOffloaded = TRUE;
            Path->EncryptionOffloading = TRUE;
            QuicTraceLogConnInfo(
                PathQeoEnabled,
                Connection,
                "Path[%hhu] QEO enabled",
                Path->ID);
        }
        CxPlatSecureZeroMemory(Offloads, sizeof(Offloads));
    } else {
        CXPLAT_DBG_ASSERT(Path->EncryptionOffloading);
        (void)CxPlatSocketUpdateQeo(Path->Binding->Socket, Offloads, 2);
        Path->EncryptionOffloading = FALSE;
        QuicTraceLogConnInfo(
            PathQeoDisabled,
            Connection,
            "Path[%hhu] QEO disabled",
            Path->ID);
    }
}
