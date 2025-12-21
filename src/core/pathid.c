/*++
    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
Abstract:
    A path id manages the resources for multipath. This file
    contains the initialization and cleanup functionality for the path id.
--*/
#include "precomp.h"
#ifdef QUIC_CLOG
#include "pathid.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPathIDInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _Outptr_ _At_(*NewPathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** NewPathID
    )
{
    QUIC_STATUS Status;
    QUIC_PATHID* PathID = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_PATHID), QUIC_POOL_PATHID);
    if (PathID == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CxPlatZeroMemory(PathID, sizeof(QUIC_PATHID));
    PathID->ID = UINT32_MAX;
    PathID->Connection = Connection;
    PathID->SourceCidLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
    CxPlatListInitializeHead(&PathID->DestCids);
    QuicLossDetectionInitialize(&PathID->LossDetection);
    PathID->RefCount = 1;
#if DEBUG
    PathID->RefTypeCount[QUIC_PATHID_REF_PATHID_SET] = 1;
#endif
    *NewPathID = PathID;

    Status = QUIC_STATUS_SUCCESS;
Exit:
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPathIDFree(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    )
{
    CXPLAT_TEL_ASSERT(PathID->SourceCids.Next == NULL);

    while (!CxPlatListIsEmpty(&PathID->DestCids)) {
        QUIC_CID_LIST_ENTRY *CID =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&PathID->DestCids),
                QUIC_CID_LIST_ENTRY,
                Link);
        CXPLAT_FREE(CID, QUIC_POOL_CIDLIST);
    }

    QuicLossDetectionUninitialize(&PathID->LossDetection);

    for (uint32_t i = 0; i < ARRAYSIZE(PathID->Packets); i++) {
        if (PathID->Packets[i] != NULL) {
            QuicPacketSpaceUninitialize(PathID->Packets[i]);
            PathID->Packets[i] = NULL;
        }
    }

    PathID->Flags.Freed = TRUE;
    CXPLAT_FREE(PathID, QUIC_POOL_PATHID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDProcessPathCloseTimerOperation(
    _Inout_ QUIC_PATHID* PathID
    )
{
    if (PathID->Flags.WaitClose) {
        uint64_t TimeNow = CxPlatTimeUs64();
        if (PathID->CloseTime <= TimeNow) {
            PathID->Flags.WaitClose = FALSE;
            PathID->Flags.Closed = TRUE;
            QuicTraceEvent(
                ConnPathIDCloseTimerExpired,
                "[conn][%p][pathid][%u] Close Timer expired",
                PathID->Connection,
                PathID->ID);
            QuicPathIDSetTryFreePathID(&PathID->Connection->PathIDs, PathID);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDAddDestCID(
    _Inout_ QUIC_PATHID* PathID,
    _In_ QUIC_CID_LIST_ENTRY *DestCid
    )
{
    CxPlatListInsertTail(&PathID->DestCids, &DestCid->Link);
    QuicTraceEvent(
        ConnDestCidAdded,
        "[conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDAddSourceCID(
    _Inout_ QUIC_PATHID* PathID,
    _In_ QUIC_CID_SLIST_ENTRY *SourceCid,
    _In_ BOOLEAN IsInitial
    )
{
    if (IsInitial) {
        SourceCid->CID.IsInitial = TRUE;
        CxPlatListPushEntry(&PathID->SourceCids, &SourceCid->Link);
    } else {
        CXPLAT_SLIST_ENTRY** Tail = &PathID->SourceCids.Next;
        while (*Tail != NULL) {
            Tail = &(*Tail)->Next;
        }
        *Tail = &SourceCid->Link;
        SourceCid->Link.Next = NULL;
    }

    QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p][pathid][%u] (SeqNum=%llu) New Source CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDFreeSourceCids(
    _Inout_ QUIC_PATHID* PathID
    )
{
    while (PathID->SourceCids.Next != NULL) {
        QUIC_CID_SLIST_ENTRY* CID =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListPopEntry(&PathID->SourceCids),
                QUIC_CID_SLIST_ENTRY,
                Link);
        while (CID->HashEntries.Next != NULL) {
            QUIC_CID_HASH_ENTRY* CID1 =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListPopEntry(&CID->HashEntries),
                    QUIC_CID_HASH_ENTRY,
                    Link);
            QuicBindingRemoveSourceConnectionID(
                CID1->Binding,
                CID1);
            CXPLAT_FREE(CID1, QUIC_POOL_CIDHASH);
        }
        CXPLAT_FREE(CID, QUIC_POOL_CIDSLIST);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDTraceRundown(
    _In_ QUIC_PATHID* PathID
    )
{
    for (CXPLAT_SLIST_ENTRY* Entry = PathID->SourceCids.Next;
            Entry != NULL;
            Entry = Entry->Next) {
        const QUIC_CID_SLIST_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_SLIST_ENTRY,
                Link);
        UNREFERENCED_PARAMETER(SourceCid);
        QuicTraceEvent(
            ConnSourceCidAdded,
            "[conn][%p][pathid][%u] (SeqNum=%llu) New Source CID: %!CID!",
            PathID->Connection,
            PathID->ID,
            SourceCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
    }
    for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
            Entry != &PathID->DestCids;
            Entry = Entry->Flink) {
        const QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        UNREFERENCED_PARAMETER(DestCid);
        QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!",
            PathID->Connection,
            PathID->ID,
            DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
    }
}

uint8_t
QuicPathIDSourceCidsCount(
    _In_ const QUIC_PATHID* PathID
    )
{
    uint8_t Count = 0;
    const CXPLAT_SLIST_ENTRY* Entry = PathID->SourceCids.Next;
    while (Entry != NULL) {
        QUIC_CID_SLIST_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(Entry, QUIC_CID_SLIST_ENTRY, Link);
        if (!SourceCid->CID.Retired) {
            ++Count;
        }
        Entry = Entry->Next;
    }
    return Count;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_SLIST_ENTRY*
QuicPathIDGenerateNewSourceCid(
    _In_ QUIC_PATHID* PathID,
    _In_ BOOLEAN IsInitial
    )
{
    uint8_t TryCount = 0;
    QUIC_CID_SLIST_ENTRY* SourceCid;

    if (!PathID->Connection->State.ShareBinding) {
        //
        // We aren't sharing the binding, therefore aren't actually using a CID.
        // No need to generate a new one.
        //
        return NULL;
    }

    uint8_t CurrentCidCount = QuicPathIDSourceCidsCount(PathID);
    CXPLAT_DBG_ASSERT(CurrentCidCount < PathID->SourceCidLimit);

    //
    // Find all the bindings that are currently in use by this connection.
    //
    QUIC_BINDING* Bindings[QUIC_MAX_PATH_COUNT] = {NULL};
    uint8_t BindingsCount = 0;

    for (uint8_t i = 0; i < PathID->Connection->PathsCount; ++i) {
        if (PathID->Connection->Paths[i].Binding != NULL) {
            BOOLEAN NewBinding = TRUE;
            for (uint8_t j = 0; j < BindingsCount; ++j) {
                if (PathID->Connection->Paths[i].Binding == Bindings[j]) {
                    NewBinding = FALSE;
                    break;
                }
            }
            if (NewBinding) {
                Bindings[BindingsCount++] = PathID->Connection->Paths[i].Binding;
            }
        }
    }

    //
    // Keep randomly generating new source CIDs until we find one that doesn't
    // collide with an existing one.
    //

    do {
        SourceCid =
            QuicCidNewRandomSource(
                PathID,
                PathID->Connection->ServerID,
                PathID->Connection->PartitionID,
                PathID->Connection->CibirId[0],
                PathID->Connection->CibirId+2);
        if (SourceCid == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "new Src CID",
                sizeof(QUIC_CID_SLIST_ENTRY) + MsQuicLib.CidTotalLength);
            QuicConnFatalError(PathID->Connection, QUIC_STATUS_INTERNAL_ERROR, NULL);
            return NULL;
        }

        BOOLEAN Collision = FALSE;
        int8_t Revert = -1;
        for (uint8_t i = 0; i < BindingsCount; ++i) {
            if (!QuicBindingAddSourceConnectionID(Bindings[i], SourceCid)) {
                Collision = TRUE;
                if (i > 0) {
                    Revert = i - 1;
                }
                break;
            }
        }

        if (Collision) {
            if (Revert >= 0) {
                for (int8_t i = Revert; i >= 0; --i) {
                    if (Bindings[i] != NULL) {
                        while (SourceCid->HashEntries.Next != NULL) {
                            QUIC_CID_HASH_ENTRY* CID =
                                CXPLAT_CONTAINING_RECORD(
                                    CxPlatListPopEntry(&SourceCid->HashEntries),
                                    QUIC_CID_HASH_ENTRY,
                                    Link);
                            if (CID->Binding == Bindings[i]) {
                                QuicBindingRemoveSourceConnectionID(
                                    Bindings[i],
                                    CID);
                                CXPLAT_FREE(CID, QUIC_POOL_CIDHASH);
                                break;
                            }
                        }
                    }
                }
            }
            CXPLAT_FREE(SourceCid, QUIC_POOL_CIDSLIST);
            SourceCid = NULL;
            if (++TryCount > QUIC_CID_MAX_COLLISION_RETRY) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    PathID->Connection,
                    "Too many CID collisions");
                QuicConnFatalError(PathID->Connection, QUIC_STATUS_INTERNAL_ERROR, NULL);
                return NULL;
            }
            QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                PathID->Connection,
                "CID collision, trying again");
        }
    } while (SourceCid == NULL);

    SourceCid->CID.SequenceNumber = PathID->NextSourceCidSequenceNumber++;

    if (PathID->ID != 0 || SourceCid->CID.SequenceNumber > 0) {
        SourceCid->CID.NeedsToSend = TRUE;
        QuicSendSetSendFlag(&PathID->Connection->Send, QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID);
    }

    QuicPathIDAddSourceCID(PathID, SourceCid, IsInitial);

    return SourceCid;
}

//
// This generates new source CIDs for the peer to use to talk to us. If
// indicated, it invalidates all the existing ones, sets a a new retire prior to
// sequence number to send out and generates replacement CIDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDGenerateNewSourceCids(
    _In_ QUIC_PATHID* PathID,
    _In_ BOOLEAN ReplaceExistingCids
    )
{
    if (!PathID->Connection->State.ShareBinding) {
        //
        // Can't generate any new CIDs, so this is a no-op.
        //
        return;
    }

    //
    // If we're replacing existing ones, then generate all new CIDs (up to the
    // limit). Otherwise, just generate whatever number we need to hit the
    // limit.
    //
    uint8_t NewCidCount;
    if (ReplaceExistingCids) {
        NewCidCount = 0;
        CXPLAT_SLIST_ENTRY* Entry = PathID->SourceCids.Next;
        while (Entry != NULL) {
            QUIC_CID_SLIST_ENTRY* SourceCid =
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_CID_SLIST_ENTRY, Link);
            if (!SourceCid->CID.Retired) {
                SourceCid->CID.Retired = TRUE;
                NewCidCount++;
            }
            Entry = Entry->Next;
        }
    } else {
        uint8_t CurrentCidCount = QuicPathIDSourceCidsCount(PathID);
        CXPLAT_DBG_ASSERT(CurrentCidCount <= PathID->SourceCidLimit);
        if (CurrentCidCount < PathID->SourceCidLimit) {
            NewCidCount = PathID->SourceCidLimit - CurrentCidCount;
        } else {
            NewCidCount = 0;
        }
    }

    for (uint8_t i = 0; i < NewCidCount; ++i) {
        if (QuicPathIDGenerateNewSourceCid(PathID, FALSE) == NULL) {
            break;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_LIST_ENTRY*
QuicPathIDGetUnusedDestCid(
    _In_ const QUIC_PATHID* PathID
    )
{
    for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
            Entry != &PathID->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (!DestCid->CID.UsedLocally && !DestCid->CID.Retired) {
            return DestCid;
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDRetireCid(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_CID_LIST_ENTRY* DestCid
    )
{
    QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
    PathID->DestCidCount--;
    DestCid->CID.Retired = TRUE;
    DestCid->CID.NeedsToSend = TRUE;
    QuicSendSetSendFlag(&PathID->Connection->Send, QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID);

    PathID->RetiredDestCidCount++;
    if (PathID->RetiredDestCidCount > 8 * QUIC_ACTIVE_CONNECTION_ID_LIMIT) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            PathID->Connection,
            "Peer exceeded retire CID limit");
        QuicConnSilentlyAbort(PathID->Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDRetireCurrentDestCid(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_PATH* Path
    )
{
    if (Path->DestCid->CID.Length == 0) {
        QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            PathID->Connection,
            "Can't retire current CID because it's zero length");
        return TRUE; // No need to update so treat as success.
    }

    QUIC_CID_LIST_ENTRY* NewDestCid = QuicPathIDGetUnusedDestCid(PathID);
    if (NewDestCid == NULL) {
        QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            PathID->Connection,
            "Can't retire current CID because we don't have a replacement");
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(Path->DestCid != NewDestCid);
    QUIC_CID_LIST_ENTRY* OldDestCid = Path->DestCid;
    QUIC_CID_CLEAR_PATH(Path->DestCid);
    QuicPathIDRetireCid(PathID, Path->DestCid);
    Path->DestCid = NewDestCid;
    QUIC_CID_SET_PATH(PathID->Connection, Path->DestCid, Path);
    QUIC_CID_VALIDATE_NULL(PathID->Connection, OldDestCid);
    Path->DestCid->CID.UsedLocally = TRUE;
    QuicTraceEvent(
        ConnDestCidUpdated,
        "[conn][%p][pathid][%u] (SeqNum=%llu) Updated Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        Path->DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));

    PathID->Connection->Stats.Misc.DestCidUpdateCount++;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDOnRetirePriorToUpdated(
    _In_ QUIC_PATHID* PathID
    )
{
    BOOLEAN ReplaceRetiredCids = FALSE;

    for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
            Entry != &PathID->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (DestCid->CID.SequenceNumber >= PathID->RetirePriorTo ||
            DestCid->CID.Retired) {
            continue;
        }

        if (DestCid->CID.UsedLocally) {
            ReplaceRetiredCids = TRUE;
        }

        QUIC_CID_CLEAR_PATH(DestCid);
        QuicPathIDRetireCid(PathID, DestCid);
    }

    return ReplaceRetiredCids;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDReplaceRetiredCids(
    _In_ QUIC_PATHID* PathID
    )
{
    CXPLAT_DBG_ASSERT(PathID->Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < PathID->Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &PathID->Connection->Paths[i];
        if (Path->PathID != PathID || Path->DestCid == NULL || !Path->DestCid->CID.Retired) {
            continue;
        }

        QUIC_CID_LIST_ENTRY* NewDestCid = QuicPathIDGetUnusedDestCid(PathID);
        if (NewDestCid == NULL) {
            if (Path->IsActive) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    PathID->Connection,
                    "Active path has no replacement for retired CID");
                QuicConnSilentlyAbort(PathID->Connection); // Must silently abort because we can't send anything now.
                return FALSE;
            }
            QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                PathID->Connection,
                "Non-active path has no replacement for retired CID.");
            CXPLAT_DBG_ASSERT(i != 0);
            CXPLAT_DBG_ASSERT(PathID->Connection->Paths[i].Binding != NULL);
            QuicLibraryReleaseBinding(PathID->Connection->Paths[i].Binding);
            PathID->Connection->Paths[i].Binding = NULL;
            QuicPathRemove(PathID->Connection, i--);
            continue;
        }

        CXPLAT_DBG_ASSERT(NewDestCid != Path->DestCid);
        QUIC_CID_LIST_ENTRY* OldDestCid = Path->DestCid;
        Path->DestCid = NewDestCid;
        QUIC_CID_SET_PATH(PathID->Connection, NewDestCid, Path);
        QUIC_CID_VALIDATE_NULL(PathID->Connection, OldDestCid);
        Path->DestCid->CID.UsedLocally = TRUE;
        Path->InitiatedCidUpdate = TRUE;
        QuicPathValidate(Path);
        QuicTraceEvent(
            ConnDestCidUpdated,
            "[conn][%p][pathid][%u] (SeqNum=%llu) Updated Destination CID: %!CID!",
            PathID->Connection,
            PathID->ID,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));

    }

#if DEBUG
    for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
            Entry != &PathID->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        CXPLAT_DBG_ASSERT(!DestCid->CID.Retired || DestCid->AssignedPath == NULL);
    }
#endif

    return TRUE;
}

//
// Updates the current destination CID to the received packet's source CID, if
// not already equal. Only used during the handshake, on the client side.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDUpdateDestCid(
    _In_ QUIC_PATHID* PathID,
    _In_ const QUIC_RX_PACKET* const Packet
    )
{
    CXPLAT_DBG_ASSERT(QuicConnIsClient(PathID->Connection));
    CXPLAT_DBG_ASSERT(!PathID->Connection->State.Connected);

    if (CxPlatListIsEmpty(&PathID->DestCids)) {
        CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled());
        QuicConnTransportError(PathID->Connection, QUIC_ERROR_INTERNAL_ERROR);
        return FALSE;
    }
    QUIC_CID_LIST_ENTRY* DestCid =
        CXPLAT_CONTAINING_RECORD(
            PathID->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);
    CXPLAT_DBG_ASSERT(PathID->Connection->Paths[0].DestCid == DestCid);

    if (Packet->SourceCidLen != DestCid->CID.Length ||
        memcmp(Packet->SourceCid, DestCid->CID.Data, DestCid->CID.Length) != 0) {

        // TODO - Only update for the first packet of each type (Initial and Retry).

        QuicTraceEvent(
            ConnDestCidRemoved,
            "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Destination CID: %!CID!",
            PathID->Connection,
            PathID->ID,
            DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));

        //
        // We have just received the a packet from a new source CID
        // from the server. Remove the current DestCid we have for the
        // server (which we randomly generated) and replace it with
        // the one we have just received.
        //
        if (Packet->SourceCidLen <= DestCid->CID.Length) {
            //
            // Since the current structure has enough room for the
            // new CID, we will just reuse it.
            //
            DestCid->CID.IsInitial = FALSE;
            DestCid->CID.Length = Packet->SourceCidLen;
            CxPlatCopyMemory(DestCid->CID.Data, Packet->SourceCid, DestCid->CID.Length);
        } else {
            //
            // There isn't enough room in the existing structure,
            // so we must allocate a new one and free the old one.
            //
            CxPlatListEntryRemove(&DestCid->Link);
            CXPLAT_FREE(DestCid, QUIC_POOL_CIDLIST);
            DestCid =
                QuicCidNewDestination(
                    Packet->SourceCidLen,
                    Packet->SourceCid);
            if (DestCid == NULL) {
                PathID->DestCidCount--;
                PathID->Connection->Paths[0].DestCid = NULL;
                QuicConnFatalError(PathID->Connection, QUIC_STATUS_OUT_OF_MEMORY, "Out of memory");
                return FALSE;
            }

            PathID->Connection->Paths[0].DestCid = DestCid;
            QUIC_CID_SET_PATH(PathID->Connection, DestCid, &PathID->Connection->Paths[0]);
            DestCid->CID.UsedLocally = TRUE;
            CxPlatListInsertHead(&PathID->DestCids, &DestCid->Link);
        }

        if (DestCid != NULL) {
            QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!",
                PathID->Connection,
                PathID->ID,
                DestCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
        }
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDAssignCids(
    _In_ QUIC_PATHID* PathID
    )
{
    BOOLEAN Assigned = FALSE;

    CXPLAT_DBG_ASSERT(PathID->Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < PathID->Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &PathID->Connection->Paths[i];
        if (Path->PathID != PathID || Path->DestCid != NULL ||
            !Path->InUse || Path->Binding == NULL) {
            continue;
        }

        QUIC_CID_LIST_ENTRY* NewDestCid = QuicPathIDGetUnusedDestCid(PathID);
        if (NewDestCid == NULL) {
            return Assigned;
        }

        Path->DestCid = NewDestCid;
        QUIC_CID_SET_PATH(PathID->Connection, NewDestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;
        QuicPathValidate(Path);

        Path->SendChallenge = TRUE;
        Path->PathValidationStartTime = CxPlatTimeUs64();

        CxPlatRandom(sizeof(Path->Challenge), Path->Challenge);

        Assigned = TRUE;
    }

    return Assigned;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDWriteNewConnectionIDFrame(
    _In_ QUIC_PATHID* PathID,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Inout_ BOOLEAN* HasMoreCidsToSend,
    _Inout_ BOOLEAN* MaxFrameLimitHit
    )
{
    QUIC_FRAME_TYPE FrameType =
        PathID->Connection->State.MultipathNegotiated ?
            QUIC_FRAME_PATH_NEW_CONNECTION_ID : QUIC_FRAME_NEW_CONNECTION_ID;
    for (CXPLAT_SLIST_ENTRY* Entry = PathID->SourceCids.Next;
            Entry != NULL;
            Entry = Entry->Next) {
        QUIC_CID_SLIST_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_SLIST_ENTRY,
                Link);
        if (!SourceCid->CID.NeedsToSend) {
            continue;
        }
        if (*MaxFrameLimitHit) {
            *HasMoreCidsToSend = TRUE;
            return TRUE;
        }

        QUIC_NEW_CONNECTION_ID_EX Frame = {
            SourceCid->CID.Length,
            PathID->ID,
            SourceCid->CID.SequenceNumber,
            0,
            { 0 } };
        CXPLAT_DBG_ASSERT(PathID->SourceCidLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
        if (Frame.Sequence >= PathID->SourceCidLimit) {
            Frame.RetirePriorTo = Frame.Sequence + 1 - PathID->SourceCidLimit;
        }
        CxPlatCopyMemory(
            Frame.Buffer,
            SourceCid->CID.Data,
            SourceCid->CID.Length);
        CXPLAT_DBG_ASSERT(SourceCid->CID.Length == MsQuicLib.CidTotalLength);
        QuicLibraryGenerateStatelessResetToken(
            PathID->Connection->Partition,
            SourceCid->CID.Data,
            Frame.Buffer + SourceCid->CID.Length);

        if (QuicNewConnectionIDFrameEncode(
                FrameType,
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            SourceCid->CID.NeedsToSend = FALSE;
            Builder->Metadata->Frames[
                Builder->Metadata->FrameCount].NEW_CONNECTION_ID.PathID =
                    PathID->ID;
            Builder->Metadata->Frames[
                Builder->Metadata->FrameCount].NEW_CONNECTION_ID.Sequence =
                    SourceCid->CID.SequenceNumber;
            *MaxFrameLimitHit =
                QuicPacketBuilderAddFrame(
                    Builder,
                    FrameType,
                    TRUE);
        } else {
            *HasMoreCidsToSend = TRUE;
            return FALSE;
        }
    }
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDWriteRetireConnectionIDFrame(
    _In_ QUIC_PATHID* PathID,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Inout_ BOOLEAN* HasMoreCidsToSend,
    _Inout_ BOOLEAN* MaxFrameLimitHit
    )
{
    QUIC_FRAME_TYPE FrameType =
        PathID->Connection->State.MultipathNegotiated ?
            QUIC_FRAME_PATH_RETIRE_CONNECTION_ID : QUIC_FRAME_RETIRE_CONNECTION_ID;
    for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
            Entry != &PathID->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (!DestCid->CID.NeedsToSend) {
            continue;
        }
        CXPLAT_DBG_ASSERT(DestCid->CID.Retired);

        if (*MaxFrameLimitHit) {
            *HasMoreCidsToSend = TRUE;
            return TRUE;
        }

        QUIC_RETIRE_CONNECTION_ID_EX Frame = {
            PathID->ID,
            DestCid->CID.SequenceNumber
        };

        if (QuicRetireConnectionIDFrameEncode(
                FrameType,
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            DestCid->CID.NeedsToSend = FALSE;
            Builder->Metadata->Frames[
                Builder->Metadata->FrameCount].RETIRE_CONNECTION_ID.PathID =
                    PathID->ID;
            Builder->Metadata->Frames[
                Builder->Metadata->FrameCount].RETIRE_CONNECTION_ID.Sequence =
                    DestCid->CID.SequenceNumber;

            *MaxFrameLimitHit =
                QuicPacketBuilderAddFrame(Builder, FrameType, TRUE);
        } else {
            *HasMoreCidsToSend = TRUE;
            return FALSE;
        }
    }
    return TRUE;
}
