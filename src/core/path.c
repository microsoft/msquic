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
    Path->InUse = TRUE;
    Path->RemoteAddressSequenceNumberValid = FALSE;
    Path->RemoteAddressSequenceNumber = QUIC_VAR_INT_MAX;
    Path->PunchMeNowRoundValid = FALSE;
    Path->PunchMeNowRound = QUIC_VAR_INT_MAX;
    Path->SendObservedAddress = TRUE;
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
BOOLEAN
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Index
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    if (Connection->PathsCount == 0 ||
        Index >= QUIC_MAX_PATH_COUNT ||
        !Connection->Paths[Index].InUse) {
        CXPLAT_TEL_ASSERTMSG(
            Connection->PathsCount > 0 &&
            Index < QUIC_MAX_PATH_COUNT &&
            Connection->Paths[Index].InUse,
            "Double or out-of-range path removal!");
        return FALSE;
    }
    CXPLAT_DBG_ASSERT(Index < Connection->PathsCount);

    const QUIC_PATH* Path = &Connection->Paths[Index];
    CXPLAT_DBG_ASSERT(Path->InUse);
    QuicTraceEvent(
        ConnPathRemoved,
        "[conn][%p] Path[%hhu] Removed",
        Connection,
        Path->ID);

    if (Connection->PathsCount == 1) {
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
        //
        // Removing the active path while other paths exist. Promote the best
        // available fallback: prefer a peer-validated path, otherwise accept
        // any path.
        //
        uint8_t FallbackIndex = 1;
        for (uint8_t j = 1; j < Connection->PathsCount; ++j) {
            if (Connection->Paths[j].IsPeerValidated) {
                FallbackIndex = j;
                break;
            }
        }
        QuicTraceLogConnInfo(
            PathActiveFallback,
            Connection,
            "Path[%hhu] removed; falling back to Path[%hhu]",
            Path->ID,
            Connection->Paths[FallbackIndex].ID);
        QuicPathSetActive(Connection, &Connection->Paths[FallbackIndex]);
        //
        // In non-multipath mode QuicPathSetActive swaps Paths[0] and
        // Paths[FallbackIndex], so the path being removed now lives at
        // FallbackIndex and we remove it there. In multipath mode no swap
        // happens (QuicPathSetActive only sets the new path's IsActive flag),
        // so the path being removed is still at index 0 and Index must stay 0
        // -- otherwise we would remove the just-promoted fallback path instead,
        // leaking its UDP binding.
        //
        if (!Connection->State.MultipathNegotiated) {
            Index = FallbackIndex;
        }
    }

    //
    // Release the removed path's PathID reference. After the fallback swap
    // above the path being removed lives at Paths[Index], so reference it
    // directly rather than through the (now possibly stale) Path pointer.
    //
    // PathID can be NULL when a path was added but failed to fully open (e.g.
    // QuicConnOpenNewPath failing at binding creation, before a PathID is
    // assigned); QuicConnAddPath then calls here to undo the half-added slot.
    //
    if (Connection->Paths[Index].PathID != NULL) {
        QuicPathIDRelease(Connection->Paths[Index].PathID, QUIC_PATHID_REF_PATH);
        Connection->Paths[Index].PathID = NULL;
    }

#if DEBUG
    if (Connection->Paths[Index].DestCid) {
        QUIC_CID_CLEAR_PATH(Connection->Paths[Index].DestCid);
    }
#endif

    if (Index + 1 < Connection->PathsCount) {
        CxPlatMoveMemory(
            Connection->Paths + Index,
            Connection->Paths + Index + 1,
            (Connection->PathsCount - Index - 1) * sizeof(QUIC_PATH));
        if (Connection->State.MultipathNegotiated) {
            //
            // Update all PathID back references.
            //
            for (uint8_t i = Index; i < Connection->PathsCount - 1; ++i) {
                if (Connection->Paths[i].PathID != NULL) {
                    Connection->Paths[i].PathID->Path = &Connection->Paths[i];
                }
            }
        }
    }
    Connection->PathsCount--;
    Connection->Paths[Connection->PathsCount].InUse = FALSE;
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
            if (QuicPathIDRemoveOutFlowBlockedReason(
                    Path->PathID, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {

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
                QuicLossDetectionUpdateTimer(&Path->PathID->LossDetection, TRUE);
            }

        } else {
            QuicPathIDAddOutFlowBlockedReason(
                Path->PathID, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
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

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_PATH_VALIDATED;
    Event.PATH_VALIDATED.LocalAddress = &Path->Route.LocalAddress;
    Event.PATH_VALIDATED.RemoteAddress = &Path->Route.RemoteAddress;
    QuicTraceLogConnVerbose(
        IndicatePathValidated,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PATH_VALIDATED");
    (void)QuicConnIndicateEvent(Connection, &Event);

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
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].ID == ID) {
            *Index = i;
            return &Connection->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathByAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (QuicAddrCompare(
                LocalAddress,
                &Connection->Paths[i].Route.LocalAddress) &&
            QuicAddrCompare(
                RemoteAddress,
                &Connection->Paths[i].Route.RemoteAddress)) {
            return &Connection->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForPacket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    BOOLEAN FatalError = FALSE;
    QUIC_PATHID* PathID = QuicPathIDSetGetPathIDForLocal(&Connection->PathIDs, Packet->PathId, &FatalError);
    CXPLAT_DBG_ASSERT(!FatalError);
    if (PathID == NULL) {
        return NULL;
    }   
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (PathID != Connection->Paths[i].PathID ||
            !QuicAddrCompare(
                &Packet->Route->LocalAddress,
                &Connection->Paths[i].Route.LocalAddress) ||
            !QuicAddrCompare(
                &Packet->Route->RemoteAddress,
                &Connection->Paths[i].Route.RemoteAddress)) {
            if (!Connection->State.HandshakeConfirmed) {
                //
                // Ignore packets on any other paths until connected/confirmed.
                //
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                return NULL;
            }
            continue;
        }
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return &Connection->Paths[i];
    }

    if (!((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
          (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated))) {
        // Client doesn't create a new path.
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
        //
        // See if any old paths share the same remote address, and is just a rebind.
        // If so, remove the old paths.
        // NB: Traversing the array backwards is simpler and more efficient here due
        // to the array shifting that happens in QuicPathRemove.
        //
        for (int i = Connection->PathsCount - 1; i > 0; i--) {
            if (!Connection->Paths[i].IsActive
                && QuicAddrGetFamily(&Packet->Route->RemoteAddress) == QuicAddrGetFamily(&Connection->Paths[i].Route.RemoteAddress)
                && QuicAddrCompareIp(&Packet->Route->RemoteAddress, &Connection->Paths[i].Route.RemoteAddress)
                && QuicAddrCompare(&Packet->Route->LocalAddress, &Connection->Paths[i].Route.LocalAddress)) {
                CXPLAT_DBG_ASSERT(Connection->Paths[i].Binding != NULL);
                QuicLibraryReleaseBinding(Connection->Paths[i].Binding);
                Connection->Paths[i].Binding = NULL;
                QuicPathRemove(Connection, (uint8_t)i);
            }
        }

        if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
            //
            // Already tracking the maximum number of paths, and can't free
            // any more.
            //
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            return NULL;
        }
    }

    QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound = NULL;
    for (CXPLAT_LIST_ENTRY* Entry = Connection->BoundAddresses.Flink;
            Entry != &Connection->BoundAddresses;
            Entry = Entry->Flink) {
        Bound =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_BOUND_ADDRESS_LIST_ENTRY,
                Link);
        if (QuicAddrCompare(&Packet->Route->LocalAddress, &Bound->Address)) {
            break;
        }
        Bound = NULL;
    }
    if (Bound == NULL || Bound->Removing) {
        //
        // No matching local address found.
        //
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    CXPLAT_DBG_ASSERT(Bound->Binding != NULL);
    if (!QuicLibraryTryAddRefBinding(Bound->Binding)) {
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    if (Connection->PathsCount > 1) {
        //
        // Make room for the new path (at index 1).
        //
        CxPlatMoveMemory(
            &Connection->Paths[2],
            &Connection->Paths[1],
            (Connection->PathsCount - 1) * sizeof(QUIC_PATH));
        if (Connection->State.MultipathNegotiated) {
            //
            // Update all PathID back references.
            //
            for (uint8_t i = 2; i < Connection->PathsCount + 1; ++i) {
                if (Connection->Paths[i].PathID != NULL) {
                    Connection->Paths[i].PathID->Path = &Connection->Paths[i];
                }
            }
        }
    }

    CXPLAT_DBG_ASSERT(Connection->PathsCount < QUIC_MAX_PATH_COUNT);
    QUIC_PATH* Path = &Connection->Paths[1];
    QuicPathInitialize(Connection, Path);
    Connection->PathsCount++;

    if (Connection->Paths[0].DestCid->CID.Length == 0) {
        Path->DestCid = Connection->Paths[0].DestCid; // TODO - Copy instead?
    }
    Path->UseBound = TRUE;
    Path->Binding = Bound->Binding;
    QuicPathIDAddRef(PathID, QUIC_PATHID_REF_PATH);
    Path->PathID = PathID;
    PathID->Path = Path;
    if (Connection->State.MultipathNegotiated) {
        QuicCongestionControlInitialize(&PathID->CongestionControl, &Connection->Settings);
    }
    PathID->Flags.InUse = TRUE;
    QuicCopyRouteInfo(&Path->Route, Packet->Route);
    Path->Route.State = RouteUnresolved;
    Path->Route.Queue = NULL;

    QuicPathValidate(Path);
    QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_notnull_
QUIC_PATH*
QuicConnChoosePath(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH* Path = &Connection->Paths[0];
    
    if (Connection->State.MultipathNegotiated && Connection->State.HandshakeConfirmed) {
        QUIC_PATH* ActivePaths[QUIC_MAX_PATH_COUNT];
        uint8_t ActivePathCount = 0;
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (Connection->Paths[i].IsActive &&
                !Connection->Paths[i].LocalClose &&
                !Connection->Paths[i].RemoteClose) {
                ActivePaths[ActivePathCount++] = &Connection->Paths[i];
            }
        }
        if (ActivePathCount > 0) {
            uint8_t Random;
            CxPlatRandom(sizeof(Random), &Random);
            Path = ActivePaths[Random % ActivePathCount];
        }
    }

    QuicTraceLogConnInfo(
        PathChosen,
        Connection,
        "Path[%hhu][PathID][%u] Chosen",
        Path->ID,
        Path->PathID->ID);

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

    if (Connection->State.MultipathNegotiated) {
        Path->IsActive = TRUE;
    } else if (Path == &Connection->Paths[0]) {
        CXPLAT_DBG_ASSERT(!Path->IsActive);
        Path->IsActive = TRUE;
    } else {
        CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
        UdpPortChangeOnly =
            QuicConnIsServer(Connection) &&
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

    //
    // When changing path, we need to increment the sequence number for observed
    // address.
    //
    if (Path->SendObservedAddress) {
        Connection->ObservedAddressSequenceNumber++;
        if (Connection->State.ObservedAddressNegotiated) {
            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_OBSERVED_ADDRESS);
        }
    }

    QuicTraceEvent(
        ConnPathActive,
        "[conn][%p] Path[%hhu] Set active (rebind=%hhu)",
        Connection,
        Connection->Paths[0].ID,
        UdpPortChangeOnly);

    if (!UdpPortChangeOnly) {
        QuicCongestionControlReset(&Path->PathID->CongestionControl, FALSE);
    }
    CXPLAT_DBG_ASSERT(Connection->Paths[0].DestCid != NULL);
    CXPLAT_DBG_ASSERT(!Connection->Paths[0].DestCid->CID.Retired);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateQeo(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ CXPLAT_QEO_OPERATION Operation
    )
{
    const QUIC_CID_SLIST_ENTRY* SourceCid =
        CXPLAT_CONTAINING_RECORD(Path->PathID->SourceCids.Next, QUIC_CID_SLIST_ENTRY, Link);
    CXPLAT_QEO_CONNECTION Offloads[2] = {
    {
        Operation,
        CXPLAT_QEO_DIRECTION_TRANSMIT,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        Path->PathID->NextPacketNumber,
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
        CXPLAT_DBG_ASSERT(Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]);
        Offloads[0].KeyPhase = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].KeyPhase = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].NextPacketNumber = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->AckTracker.LargestPacketNumberAcknowledged;
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
