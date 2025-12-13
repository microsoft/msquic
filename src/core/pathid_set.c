/*++
    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
Abstract:
    A path id set manages all PathID-related state for a single connection. It
    keeps track of locally and remotely initiated path ids, and synchronizes max
    path ids with the peer.
--*/
#include "precomp.h"
#ifdef QUIC_CLOG
#include "pathid_set.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    PathIDSet->MaxPathID = 0;
    PathIDSet->MaxCurrentPathIDCount = 1;
    PathIDSet->CurrentPathIDCount = 0;
    CxPlatDispatchRwLockInitialize(&PathIDSet->RwLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUninitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    if (PathIDSet->Flags.HashTableInitialized) {
        CXPLAT_DBG_ASSERT(PathIDSet->HASH.Table->NumEntries == 0);
        CxPlatHashtableUninitialize(PathIDSet->HASH.Table);
    }
}

BOOLEAN
QuicPathIDSetGetPathIDs(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _Out_writes_(*PathIDCount) QUIC_PATHID** PathIDs,
    _Inout_ uint8_t* PathIDCount
    )
{
    BOOLEAN Within = TRUE;
    uint8_t Count = 0;
    CxPlatDispatchRwLockAcquireExclusive(&PathIDSet->RwLock, PrevIrql);
    if (!PathIDSet->Flags.HashTableInitialized) {
        if (Count < *PathIDCount) {
            QuicPathIDAddRef(PathIDSet->SINGLE.PathID, QUIC_PATHID_REF_LOOKUP);
            PathIDs[Count++] = PathIDSet->SINGLE.PathID;
        } else {
            Within = FALSE;
        }
        *PathIDCount = Count;
    } else {
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(PathIDSet->HASH.Table, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(PathIDSet->HASH.Table, &Enumerator)) != NULL) {
            if (Count < *PathIDCount) {
                QUIC_PATHID* PathID =
                    CXPLAT_CONTAINING_RECORD(Entry, QUIC_PATHID, TableEntry);
                QuicPathIDAddRef(PathID, QUIC_PATHID_REF_LOOKUP);
                PathIDs[Count++] = PathID;
            } else {
                break;
            }
        }
        *PathIDCount = Count;
        if (Entry != NULL) {
            Within = FALSE;
        }
        CxPlatHashtableEnumerateEnd(PathIDSet->HASH.Table, &Enumerator);
    }
    CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);
    return Within;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetTraceRundown(
    _In_ QUIC_PATHID_SET* PathIDSet
    )
{
    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    for (uint8_t i = 0; i < PathIDCount; i++) {
        QuicPathIDTraceRundown(PathIDs[i]);
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPathIDSetInsertPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ QUIC_PATHID* PathID
    )
{
    BOOLEAN Success = FALSE;

    if (PathIDSet->CurrentPathIDCount == 0) {
        PathID->Flags.InPathIDTable = TRUE;
        PathIDSet->SINGLE.PathID = PathID;
        Success = TRUE;
        goto Exit;
    } else if (!PathIDSet->Flags.HashTableInitialized) {
        QUIC_PATHID* ExisitingPathID = PathIDSet->SINGLE.PathID;
        PathIDSet->HASH.Table = NULL;
        //
        // Lazily initialize the hash table.
        //
        if (!CxPlatHashtableInitialize(&PathIDSet->HASH.Table, CXPLAT_HASH_MIN_SIZE)) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "pathid hash table",
                0);
            goto Exit;
        }
        CxPlatHashtableInsert(
            PathIDSet->HASH.Table,
            &ExisitingPathID->TableEntry,
            ExisitingPathID->ID,
            NULL);
        PathIDSet->Flags.HashTableInitialized = TRUE;
    }
    PathID->Flags.InPathIDTable = TRUE;
    CxPlatHashtableInsert(
        PathIDSet->HASH.Table,
        &PathID->TableEntry,
        PathID->ID,
        NULL);
    Success = TRUE;

Exit:
    return Success;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
QUIC_PATHID*
QuicPathIDSetLookupPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t Id
    )
{
    QUIC_PATHID *PathID = NULL;
    CxPlatDispatchRwLockAcquireShared(&PathIDSet->RwLock, PrevIrql);

    if (PathIDSet->CurrentPathIDCount == 0) {
        goto Exit; // No pathids have been created yet.
    } else if (!PathIDSet->Flags.HashTableInitialized) {
        if (PathIDSet->SINGLE.PathID->ID == Id) {
            PathID = PathIDSet->SINGLE.PathID;
        }
    } else {
        
        CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
        CXPLAT_HASHTABLE_ENTRY* Entry =
            CxPlatHashtableLookup(PathIDSet->HASH.Table, Id, &Context);
        while (Entry != NULL) {
            QUIC_PATHID* TempPathID =
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_PATHID, TableEntry);
            if (TempPathID->ID == Id) {
                PathID = TempPathID;
                break;
            }
            Entry = CxPlatHashtableLookupNext(PathIDSet->HASH.Table, &Context);
        }
    }

Exit:
    if (PathID != NULL) {
        QuicPathIDAddRef(PathID, QUIC_PATHID_REF_LOOKUP);
    }
    CxPlatDispatchRwLockReleaseShared(&PathIDSet->RwLock, PrevIrql);
    return PathID;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetFree(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    CxPlatDispatchRwLockAcquireExclusive(&PathIDSet->RwLock, PrevIrql);

    if (PathIDSet->CurrentPathIDCount == 0) {
        goto Exit;
    } else if (!PathIDSet->Flags.HashTableInitialized) {
        QuicPathIDFree(PathIDSet->SINGLE.PathID);
        PathIDSet->SINGLE.PathID = NULL;
    } else {
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(PathIDSet->HASH.Table, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(PathIDSet->HASH.Table, &Enumerator)) != NULL) {
            CxPlatHashtableRemove(PathIDSet->HASH.Table, Entry, NULL);
            QUIC_PATHID* PathID = CXPLAT_CONTAINING_RECORD(Entry, QUIC_PATHID, TableEntry);
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_PATHID_SET);
        }
        CxPlatHashtableEnumerateEnd(PathIDSet->HASH.Table, &Enumerator);
    }

Exit:
    CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetFreeSourceCids(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    for (uint8_t i = 0; i < PathIDCount; i++) {
        QuicPathIDFreeSourceCids(PathIDs[i]);
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetProcessLossDetectionTimerOperation(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    for (uint8_t i = 0; i < PathIDCount; i++) {
        QuicLossDetectionProcessTimerOperation(&PathIDs[i]->LossDetection);
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetProcessPathCloseTimerOperation(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    for (uint8_t i = 0; i < PathIDCount; i++) {
        QuicPathIDProcessPathCloseTimerOperation(PathIDs[i]);
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetTryFreePathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    )
{
    if (!PathID->Flags.Abandoned || !PathID->Flags.Closed) {
        return;
    }

    QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);

    QuicTraceEvent(
        ConnPathIDRemove,
        "[conn][%p] Removed PathID %u",
        Connection,
        PathID->ID);

    CXPLAT_DBG_ASSERT(PathID->Path != NULL);
    uint8_t PathIndex;
    QUIC_PATH* Path = QuicConnGetPathByID(Connection, PathID->Path->ID, &PathIndex);
    CXPLAT_DBG_ASSERT(PathID->Path == Path);

    if (!QuicConnIsServer(Connection)) {
        QuicBindingRemoveAllSourceConnectionIDs(Path->Binding, Connection);
    }
    QuicLibraryReleaseBinding(Path->Binding);
    Path->Binding = NULL;

    QuicPathRemove(Connection, PathIndex);

    PathID->Flags.InPathIDTable = FALSE;

    CxPlatDispatchRwLockAcquireExclusive(&PathIDSet->RwLock, PrevIrql);
    if (!PathIDSet->Flags.HashTableInitialized) {
        CXPLAT_DBG_ASSERT(PathID == PathIDSet->SINGLE.PathID);
        PathIDSet->SINGLE.PathID = NULL;
    } else {
        CxPlatHashtableRemove(PathIDSet->HASH.Table, &PathID->TableEntry, NULL);
    }
    CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);
    PathIDSet->CurrentPathIDCount--;

    QuicLossDetectionReset(&PathID->LossDetection);
    QuicPathIDFreeSourceCids(PathID);
    QuicPathIDRelease(PathID, QUIC_PATHID_REF_PATHID_SET);

    if (PathIDSet->CurrentPathIDCount < PathIDSet->MaxCurrentPathIDCount) {
        PathIDSet->MaxPathID++;
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_MAX_PATH_ID);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetGenerateNewSourceCids(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _In_ BOOLEAN ReplaceExistingCids
    )
{
    if (QuicPathIDSetGetConnection(PathIDSet)->State.MultipathNegotiated) {
        uint16_t NewPathIDCount = 0;
        if (PathIDSet->CurrentPathIDCount < PathIDSet->MaxCurrentPathIDCount) {
            NewPathIDCount = PathIDSet->MaxCurrentPathIDCount - PathIDSet->CurrentPathIDCount;
        }
        for (uint16_t i = 0; i < NewPathIDCount; ++i) {
            QUIC_PATHID *PathID = NULL;
            QUIC_STATUS Status = QuicPathIDSetNewLocalPathID(PathIDSet, &PathID);
            if (Status == QUIC_STATUS_PATHID_LIMIT_REACHED) {
                break;
            } else if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    QuicPathIDSetGetConnection(PathIDSet),
                    "Failed to generate new path ID");
                QuicConnTransportError(QuicPathIDSetGetConnection(PathIDSet), QUIC_ERROR_INTERNAL_ERROR);
                return;
            }
        }
    }

    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    for (uint8_t i = 0; i < PathIDCount; i++) {
        QuicPathIDGenerateNewSourceCids(PathIDs[i], ReplaceExistingCids);
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDSetWriteNewConnectionIDFrame(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Out_ BOOLEAN* HasMoreCidsToSend,
    _Out_ BOOLEAN* MaxFrameLimitHit
    )
{
    BOOLEAN HaveRoom = TRUE;
    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    BOOLEAN HasMoreCidsToSend1 = FALSE;
    BOOLEAN MaxFrameLimitHit1 = FALSE;
    for (uint8_t i = 0; i < PathIDCount; i++) {
        if (!MaxFrameLimitHit1) {
            HaveRoom = QuicPathIDWriteNewConnectionIDFrame(
                PathIDs[i],
                Builder,
                AvailableBufferLength,
                &HasMoreCidsToSend1,
                &MaxFrameLimitHit1);
        }
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
    *HasMoreCidsToSend = HasMoreCidsToSend1;
    *MaxFrameLimitHit = MaxFrameLimitHit1;

    return HaveRoom;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDSetWriteRetireConnectionIDFrame(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Out_ BOOLEAN* HasMoreCidsToSend,
    _Out_ BOOLEAN* MaxFrameLimitHit
    )
{
    BOOLEAN HaveRoom = TRUE;
    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    BOOLEAN HasMoreCidsToSend1 = FALSE;
    BOOLEAN MaxFrameLimitHit1 = FALSE;
    for (uint8_t i = 0; i < PathIDCount; i++) {
        if (!MaxFrameLimitHit1) {
            HaveRoom = QuicPathIDWriteRetireConnectionIDFrame(
                PathIDs[i],
                Builder,
                AvailableBufferLength,
                &HasMoreCidsToSend1,
                &MaxFrameLimitHit1);
        }
        QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
    }
    *HasMoreCidsToSend = HasMoreCidsToSend1;
    *MaxFrameLimitHit = MaxFrameLimitHit1;

    return HaveRoom;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDSetProcessAckFrame(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ BOOLEAN* InvalidFrame
    )
{
    QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);

    //
    // Called for each received ACK frame. An ACK frame consists of one or more
    // ACK blocks, each of which acknowledges a contiguous range of packets.
    //

    uint32_t PathId;
    uint64_t AckDelay; // microsec
    QUIC_ACK_ECN_EX Ecn;

    BOOLEAN Result =
        QuicAckFrameDecode(
            FrameType,
            BufferLength,
            Buffer,
            Offset,
            InvalidFrame,
            &PathId,
            &Connection->DecodedAckRanges,
            &Ecn,
            &AckDelay);

    if (Result) {

        BOOLEAN FatalError = FALSE;
        QUIC_PATHID *PathID = NULL;
        PathID = QuicPathIDSetGetPathIDForPeer(
            PathIDSet,
            PathId,
            TRUE,
            &FatalError);

        if (PathID != NULL) {
            uint64_t Largest;
            if (!QuicRangeGetMaxSafe(&Connection->DecodedAckRanges, &Largest) ||
                PathID->LossDetection.LargestSentPacketNumber < Largest) {

                //
                // The ACK frame should never acknowledge a packet number we haven't
                // sent.
                //
                *InvalidFrame = TRUE;
                Result = FALSE;

            } else {

                AckDelay <<= Connection->PeerTransportParams.AckDelayExponent;

                QuicLossDetectionProcessAckBlocks(
                    &PathID->LossDetection,
                    PathID->Path,
                    Packet,
                    EncryptLevel,
                    AckDelay,
                    &Connection->DecodedAckRanges,
                    InvalidFrame,
                    FrameType == QUIC_FRAME_ACK_1 ? &Ecn : NULL);
            }
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        } else {
            *InvalidFrame = TRUE;
            Result = FALSE;
        }
    }

    QuicRangeReset(&Connection->DecodedAckRanges);

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitializeTransportParameters(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t SourceCidLimit,
    _In_ uint32_t MaxPathID
    )
{
    CXPLAT_DBG_ASSERT(PathIDSet->CurrentPathIDCount == 1);
    CXPLAT_DBG_ASSERT(SourceCidLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
    if (PathIDSet->SINGLE.PathID->SourceCidLimit > SourceCidLimit) {
        PathIDSet->SINGLE.PathID->SourceCidLimit = SourceCidLimit;
    }

    PathIDSet->SINGLE.PathID->SourceCidLimit = SourceCidLimit;
 
    if (MaxPathID != UINT32_MAX) {
        PathIDSet->Flags.InitialMaxPathRecvd = TRUE;
        PathIDSet->MaxPathID = QUIC_ACTIVE_PATH_ID_LIMIT - 1;
        PathIDSet->PeerMaxPathID = MaxPathID;
        PathIDSet->MaxCurrentPathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    } else {
        PathIDSet->Flags.InitialMaxPathRecvd = FALSE;
        PathIDSet->MaxPathID = 0;
        PathIDSet->PeerMaxPathID = 0;
        PathIDSet->MaxCurrentPathIDCount = 1;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUpdateMaxPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t MaxPathID
    )
{
    if (PathIDSet->PeerMaxPathID < MaxPathID) {
        QuicTraceLogConnVerbose(
            PeerMaxPathIDUpdated,
            QuicPathIDSetGetConnection(PathIDSet),
            "Peer updated max path id (%u).",
            MaxPathID);
        PathIDSet->PeerMaxPathID = MaxPathID;
        QuicPathIDSetGenerateNewSourceCids(PathIDSet, FALSE);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPathIDSetNewLocalPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _Outptr_ _At_(*NewPathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** NewPathID
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);
    QUIC_PATHID* PathID = NULL;
    BOOLEAN NewPathIDBlocked = PathIDSet->TotalPathIDCount >= (PathIDSet->PeerMaxPathID + 1);

    if (NewPathIDBlocked) {
        if (Connection->State.MultipathNegotiated) {
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATHS_BLOCKED);
        }
        Status = QUIC_STATUS_PATHID_LIMIT_REACHED;
        goto Exit;
    }

    Status = QuicPathIDInitialize(QuicPathIDSetGetConnection(PathIDSet), &PathID);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    PathID->ID = PathIDSet->TotalPathIDCount;
    if (PathID->ID == 0) {
        for (uint32_t i = 0; i < ARRAYSIZE(PathID->Packets); i++) {
            Status =
                QuicPacketSpaceInitialize(
                    PathID,
                    (QUIC_ENCRYPT_LEVEL)i,
                    &PathID->Packets[i]);
            if (QUIC_FAILED(Status)) {
                break;
            }
        }
    } else {
        Status =
            QuicPacketSpaceInitialize(
                PathID,
                QUIC_ENCRYPT_LEVEL_1_RTT,
                &PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]);
    }
    if (QUIC_FAILED(Status)) {
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_PATHID_SET);
        goto Exit;
    }

    CxPlatDispatchRwLockAcquireExclusive(&PathIDSet->RwLock, PrevIrql);
    if (!QuicPathIDSetInsertPathID(PathIDSet, PathID)) {
        CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_PATHID_SET);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);
    PathIDSet->CurrentPathIDCount++;
    PathIDSet->TotalPathIDCount++;

    QuicTraceEvent(
        ConnPathIDAdd,
        "[conn][%p] Added New PathID %u",
        QuicPathIDSetGetConnection(PathIDSet),
        PathID->ID);

    if (PathIDSet->MaxCurrentPathIDCount < PathIDSet->CurrentPathIDCount) {
        PathIDSet->MaxCurrentPathIDCount = PathIDSet->CurrentPathIDCount;
    }
    *NewPathID = PathID;
Exit:
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != NULL)
QUIC_PATHID*
QuicPathIDSetGetPathIDForLocal(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t PathId,
    _Out_ BOOLEAN* FatalError
    )
{
    QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);

    *FatalError = FALSE;

    //
    // Connection is closed. No more pathids are open.
    //
    // if (QuicConnIsClosed(Connection)) {
    //     return NULL;
    // }

    //
    // Validate the stream ID isn't above the allowed max.
    //
    if (PathId > PathIDSet->PeerMaxPathID) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "local tried to use more pathids than allowed");
        QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
        *FatalError = TRUE;
        return NULL;
    }

    QUIC_PATHID* PathID = NULL;
    //
    // If the stream ID is in the acceptable range of already opened streams,
    // look for it; but note it could be missing because it has been closed.
    //
    if (PathId + 1 <= PathIDSet->TotalPathIDCount) {

        //
        // Find the stream for the ID.
        //
        PathID = QuicPathIDSetLookupPathID(PathIDSet, PathId);

    } else {
        //
        // Local tried to open stream that it wasn't allowed to.
        //
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Local tried to open pathid it wasn't allowed to open.");
        QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
        *FatalError = TRUE;
    }

    return PathID;
}

#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't double ref count semantics
_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
QUIC_PATHID*
QuicPathIDSetGetPathIDForPeer(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t PathId,
    _In_ BOOLEAN CreateIfMissing,
    _Out_ BOOLEAN* FatalError
    )
{
    QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);

    *FatalError = FALSE;

    //
    // Connection is closed. No more pathids are open.
    //
    // if (QuicConnIsClosed(Connection)) {
    //     return NULL;
    // }

    //
    // Validate the stream ID isn't above the allowed max.
    //
    if (PathId > PathIDSet->MaxPathID) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer used more pathids than allowed");
        QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
        *FatalError = TRUE;
        return NULL;
    }

    QUIC_PATHID* PathID = NULL;
    //
    // If the stream ID is in the acceptable range of already opened streams,
    // look for it; but note it could be missing because it has been closed.
    //
    if (PathId + 1 <= PathIDSet->TotalPathIDCount) {

        //
        // Find the stream for the ID.
        //
        PathID = QuicPathIDSetLookupPathID(PathIDSet, PathId);

    } else if (CreateIfMissing) {

        do {
            if (PathID != NULL) {
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                PathID = NULL;
            }
            //
            // Calculate the next Path ID.
            //
            uint32_t NewPathId = PathIDSet->TotalPathIDCount;

            QUIC_STATUS Status = QuicPathIDInitialize(QuicPathIDSetGetConnection(PathIDSet), &PathID);
            if (QUIC_FAILED(Status)) {
                *FatalError = TRUE;
                QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
                goto Exit;
            }

            PathID->ID = NewPathId;
            if (PathID->ID == 0) {
                for (uint32_t i = 0; i < ARRAYSIZE(PathID->Packets); i++) {
                    Status =
                        QuicPacketSpaceInitialize(
                            PathID,
                            (QUIC_ENCRYPT_LEVEL)i,
                            &PathID->Packets[i]);
                    if (QUIC_FAILED(Status)) {
                        break;
                    }
                }
            } else {
                Status =
                    QuicPacketSpaceInitialize(
                        PathID,
                        QUIC_ENCRYPT_LEVEL_1_RTT,
                        &PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]);
            }
            if (QUIC_FAILED(Status)) {
                *FatalError = TRUE;
                QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_PATHID_SET);
                PathID = NULL;
                goto Exit;
            }

            CxPlatDispatchRwLockAcquireExclusive(&PathIDSet->RwLock, PrevIrql);
            if (!QuicPathIDSetInsertPathID(PathIDSet, PathID)) {
                CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);
                *FatalError = TRUE;
                QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_PATHID_SET);
                PathID = NULL;
                goto Exit;
            }
            QuicPathIDAddRef(PathID, QUIC_PATHID_REF_LOOKUP);
            CxPlatDispatchRwLockReleaseExclusive(&PathIDSet->RwLock, PrevIrql);

            PathIDSet->CurrentPathIDCount++;
            PathIDSet->TotalPathIDCount++;

            QuicTraceEvent(
                ConnPathIDAdd,
                "[conn][%p] Added New PathID %u",
                Connection,
                PathID->ID);

        } while (PathIDSet->TotalPathIDCount != PathId + 1);
    } else {

        //
        // Remote tried to open stream that it wasn't allowed to.
        //
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Remote tried to open pathid it wasn't allowed to open.");
        QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
        *FatalError = TRUE;
    }
Exit:
    return PathID;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_PATHID*
QuicPathIDSetGetUnusedPathID(
    _In_ QUIC_PATHID_SET* PathIDSet
    )
{
    QUIC_PATHID *PathID = NULL;

    QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
    uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    QuicPathIDSetGetPathIDs(PathIDSet, PathIDs, &PathIDCount);

    for (uint8_t i = 0; i < PathIDCount; i++) {
        if (PathID == NULL && !PathIDs[i]->Flags.InUse) {
            PathID = PathIDs[i];
        } else {
            QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
        }
    }

    return PathID;
}
