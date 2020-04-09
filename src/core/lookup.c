/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    CID-keyed lookup for connections.

--*/

#include "precomp.h"
#include "lookup.c.clog.h"

typedef struct QUIC_CACHEALIGN QUIC_PARTITIONED_HASHTABLE {

    QUIC_DISPATCH_RW_LOCK RwLock;
    QUIC_HASHTABLE Table;

} QUIC_PARTITIONED_HASHTABLE;

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupInsertSourceConnectionID(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ uint32_t Hash,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _In_ BOOLEAN UpdateRefCount
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupInitialize(
    _Inout_ QUIC_LOOKUP* Lookup
    )
{
    QuicZeroMemory(Lookup, sizeof(QUIC_LOOKUP));
    QuicDispatchRwLockInitialize(&Lookup->RwLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupUninitialize(
    _In_ QUIC_LOOKUP* Lookup
    )
{
    QUIC_DBG_ASSERT(Lookup->CidCount == 0);

    if (Lookup->PartitionCount == 0) {
        QUIC_DBG_ASSERT(Lookup->SINGLE.Connection == NULL);
    } else {
        QUIC_DBG_ASSERT(Lookup->HASH.Tables != NULL);
        for (uint8_t i = 0; i < Lookup->PartitionCount; i++) {
            QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[i];
            QUIC_DBG_ASSERT(Table->Table.NumEntries == 0);
            QuicHashtableUninitialize(&Table->Table);
            QuicDispatchRwLockUninitialize(&Table->RwLock);
        }
        QUIC_FREE(Lookup->HASH.Tables);
    }

    QuicDispatchRwLockUninitialize(&Lookup->RwLock);
}

//
// Allocates and initializes a new partitioned hash table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupCreateHashTable(
    _In_ QUIC_LOOKUP* Lookup,
    _In_range_(>, 0) uint8_t PartitionCount
    )
{
    QUIC_DBG_ASSERT(Lookup->LookupTable == NULL);
    QUIC_FRE_ASSERT(PartitionCount > 0);

    Lookup->HASH.Tables =
        QUIC_ALLOC_NONPAGED(sizeof(QUIC_PARTITIONED_HASHTABLE) * PartitionCount);

    if (Lookup->HASH.Tables != NULL) {

        uint8_t Cleanup = 0;
        for (uint8_t i = 0; i < PartitionCount; i++) {
            if (!QuicHashtableInitializeEx(&Lookup->HASH.Tables[i].Table, QUIC_HASH_MIN_SIZE)) {
                Cleanup = i;
                break;
            }
            QuicDispatchRwLockInitialize(&Lookup->HASH.Tables[i].RwLock);
        }
        if (Cleanup != 0) {
            for (uint8_t i = 0; i < Cleanup; i++) {
                QuicHashtableUninitialize(&Lookup->HASH.Tables[i].Table);
            }
            QUIC_FREE(Lookup->HASH.Tables);
            Lookup->HASH.Tables = NULL;
        } else {
            Lookup->PartitionCount = PartitionCount;
        }
    }

    return Lookup->HASH.Tables != NULL;
}

//
// Rebalances the lookup tables to make sure they are optimal for the current
// configuration of connections and listeners. Requires the RwLock to be held
// exclusively.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupRebalance(
    _In_ QUIC_LOOKUP* Lookup,
    _In_opt_ QUIC_CONNECTION* Connection
    )
{
    //
    // Calculate the updated partition count.
    //

    uint8_t PartitionCount;
    if (Lookup->MaximizePartitioning) {
        PartitionCount = MsQuicLib.PartitionCount;

    } else if (Lookup->PartitionCount > 0) {
        PartitionCount = 1;

    } else if (Lookup->PartitionCount == 0 &&
        Lookup->SINGLE.Connection != NULL &&
        Lookup->SINGLE.Connection != Connection) {
        PartitionCount = 1;

    } else {
        PartitionCount = 0;
    }

    //
    // Rebalance the binding if the partition count increased.
    //

    if (PartitionCount > Lookup->PartitionCount) {

        uint8_t PreviousPartitionCount = Lookup->PartitionCount;
        void* PreviousLookup = Lookup->LookupTable;
        Lookup->LookupTable = NULL;

        QUIC_DBG_ASSERT(PartitionCount != 0);

        if (!QuicLookupCreateHashTable(Lookup, PartitionCount)) {
            Lookup->LookupTable = PreviousLookup;
            return FALSE;
        }

        //
        // Move the CIDs to the new table.
        //

        if (PreviousPartitionCount == 0) {

            //
            // Only a single connection before. Enumerate all CIDs on the
            // connection and reinsert them into the new table(s).
            //

            if (PreviousLookup != NULL) {
                QUIC_SINGLE_LIST_ENTRY* Entry =
                    ((QUIC_CONNECTION*)PreviousLookup)->SourceCids.Next;

                while (Entry != NULL) {
                    QUIC_CID_HASH_ENTRY *CID =
                        QUIC_CONTAINING_RECORD(
                            Entry,
                            QUIC_CID_HASH_ENTRY,
                            Link);
                    (void)QuicLookupInsertSourceConnectionID(
                        Lookup,
                        QuicHashSimple(CID->CID.Length, CID->CID.Data),
                        CID,
                        FALSE);
                    Entry = Entry->Next;
                }
            }

        } else {

            //
            // Changes the number of partitioned tables. Remove all the CIDs
            // from the old tables and insert them into the new tables.
            //

            QUIC_PARTITIONED_HASHTABLE* PreviousTable = PreviousLookup;
            for (uint8_t i = 0; i < PreviousPartitionCount; i++) {
                QUIC_HASHTABLE_ENTRY* Entry;
                QUIC_HASHTABLE_ENUMERATOR Enumerator;
                QuicHashtableEnumerateBegin(&PreviousTable[i].Table, &Enumerator);
                while (TRUE) {
                    Entry = QuicHashtableEnumerateNext(&PreviousTable[i].Table, &Enumerator);
                    if (Entry == NULL) {
                        QuicHashtableEnumerateEnd(&PreviousTable[i].Table, &Enumerator);
                        break;
                    }
                    QuicHashtableRemove(&PreviousTable[i].Table, Entry, NULL);

                    QUIC_CID_HASH_ENTRY *CID =
                        QUIC_CONTAINING_RECORD(
                            Entry,
                            QUIC_CID_HASH_ENTRY,
                            Entry);
                    (void)QuicLookupInsertSourceConnectionID(
                        Lookup,
                        QuicHashSimple(CID->CID.Length, CID->CID.Data),
                        CID,
                        FALSE);
                }
                QuicHashtableUninitialize(&PreviousTable[i].Table);
            }
            QUIC_FREE(PreviousTable);
        }
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupMaximizePartitioning(
    _In_ QUIC_LOOKUP* Lookup
    )
{
    BOOLEAN Result = TRUE;

    QuicDispatchRwLockAcquireExclusive(&Lookup->RwLock);

    if (!Lookup->MaximizePartitioning) {
        Lookup->MaximizePartitioning = TRUE;
        Result = QuicLookupRebalance(Lookup, NULL);
        if (!Result) {
            Lookup->MaximizePartitioning = FALSE;
        }
    }

    QuicDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    return Result;
}

//
// Compares the input destination connection ID to all the source connection
// IDs registered with the connection. Returns TRUE if it finds a match,
// otherwise FALSE.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCidMatchConnection(
    _In_ const QUIC_CONNECTION* const Connection,
    _In_reads_(Length)
        const uint8_t* const DestCid,
    _In_ uint8_t Length
    )
{
    for (QUIC_SINGLE_LIST_ENTRY* Link = Connection->SourceCids.Next;
        Link != NULL;
        Link = Link->Next) {

        const QUIC_CID_HASH_ENTRY* const Entry =
            QUIC_CONTAINING_RECORD(Link, const QUIC_CID_HASH_ENTRY, Link);

        if (Length == Entry->CID.Length &&
            (Length == 0 || memcmp(DestCid, Entry->CID.Data, Length) == 0)) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Uses the hash and destination connection ID to look up the connection in the
// hash table. Returns the pointer to the connection if found; NULL otherwise.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicHashLookupConnection(
    _In_ QUIC_HASHTABLE* Table,
    _In_reads_(Length)
        const uint8_t* const DestCid,
    _In_ uint8_t Length,
    _In_ uint32_t Hash
    )
{
    QUIC_HASHTABLE_LOOKUP_CONTEXT Context;
    QUIC_HASHTABLE_ENTRY* TableEntry =
        QuicHashtableLookup(Table, Hash, &Context);

    while (TableEntry != NULL) {
        QUIC_CID_HASH_ENTRY* CIDEntry =
            QUIC_CONTAINING_RECORD(TableEntry, QUIC_CID_HASH_ENTRY, Entry);

        if (CIDEntry->CID.Length == Length &&
            memcmp(DestCid, CIDEntry->CID.Data, Length) == 0) {
            return CIDEntry->Connection;
        }

        TableEntry = QuicHashtableLookupNext(Table, &Context);
    }

    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionInternal(
    _In_ QUIC_LOOKUP* Lookup,
    _In_reads_(CIDLen)
        const uint8_t* const CID,
    _In_ uint8_t CIDLen,
    _In_ uint32_t Hash
    )
{
    QUIC_CONNECTION* Connection = NULL;

    if (Lookup->PartitionCount == 0) {
        //
        // Only a single connection is on this binding. Validate that the
        // destination connection ID matches that connection.
        //
        if (Lookup->SINGLE.Connection != NULL &&
            QuicCidMatchConnection(Lookup->SINGLE.Connection, CID, CIDLen)) {
            Connection = Lookup->SINGLE.Connection;
        }

    } else {
        QUIC_DBG_ASSERT(CIDLen >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
        QUIC_DBG_ASSERT(CID != NULL);

        //
        // Use the destination connection ID to get the index into the
        // partitioned hash table array, and look up the connection in that
        // hash table.
        //
        QUIC_STATIC_ASSERT(QUIC_CID_PID_LENGTH == 1, "The code below assumes 1 byte");
        uint32_t PartitionIndex = CID[QUIC_CID_PID_INDEX];
        PartitionIndex &= MsQuicLib.PartitionMask;
        PartitionIndex %= Lookup->PartitionCount;
        QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[PartitionIndex];

        QuicDispatchRwLockAcquireShared(&Table->RwLock);
        Connection =
            QuicHashLookupConnection(
                &Table->Table,
                CID,
                CIDLen,
                Hash);
        QuicDispatchRwLockReleaseShared(&Table->RwLock);
    }

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    if (Connection != NULL) {
        QuicTraceLogVerbose(FN_lookup4d6a39f9c8572203bf3e0252c2e98686, "[bind][%p] Lookup Hash=%u found %p", Lookup, Hash, Connection);
    } else {
        QuicTraceLogVerbose(FN_lookup70420e94980f690ca12e8a277250b26e, "[bind][%p] Lookup Hash=%u not found", Lookup, Hash);
    }
#endif

    return Connection;
}

//
// Inserts a source connection ID into the lookup table. Requires the
// Lookup->RwLock to be exlusively held.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupInsertSourceConnectionID(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ uint32_t Hash,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _In_ BOOLEAN UpdateRefCount
    )
{
    if (!QuicLookupRebalance(Lookup, SourceCid->Connection)) {
        return FALSE;
    }

    if (Lookup->PartitionCount == 0) {
        //
        // Make sure the connection pointer is set.
        //
        if (Lookup->SINGLE.Connection == NULL) {
            Lookup->SINGLE.Connection = SourceCid->Connection;
        }

    } else {
        QUIC_DBG_ASSERT(SourceCid->CID.Length >= QUIC_CID_PID_INDEX + QUIC_CID_PID_LENGTH);

        //
        // Insert the source connection ID into the hash table.
        //
        QUIC_STATIC_ASSERT(QUIC_CID_PID_LENGTH == 1, "The code below assumes 1 byte");
        uint32_t PartitionIndex = SourceCid->CID.Data[QUIC_CID_PID_INDEX];
        PartitionIndex &= MsQuicLib.PartitionMask;
        PartitionIndex %= Lookup->PartitionCount;
        QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[PartitionIndex];

        QuicDispatchRwLockAcquireExclusive(&Table->RwLock);
        QuicHashtableInsert(
            &Table->Table,
            &SourceCid->Entry,
            Hash,
            NULL);
        QuicDispatchRwLockReleaseExclusive(&Table->RwLock);
    }

    if (UpdateRefCount) {
        Lookup->CidCount++;
        QuicConnAddRef(SourceCid->Connection, QUIC_CONN_REF_LOOKUP_TABLE);
    }

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    QuicTraceLogVerbose(FN_lookup08f411ebe70c98bcc531d9a1fc421691, "[bind][%p] Insert Conn=%p Hash=%u", Lookup, Connection, Hash);
#endif

    return TRUE;
}

//
// Removes a source connection ID from the lookup table. Requires the
// Lookup->RwLock to be exlusively held.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveSourceConnectionIDInt(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid
    )
{
    QUIC_DBG_ASSERT(Lookup->CidCount != 0);
    Lookup->CidCount--;

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    QuicTraceLogVerbose(FN_lookupeff24288031c85be92f7f20338b8933f, "[bind][%p] Remove Conn=%p", Lookup, SourceCid->Connection);
#endif

    if (Lookup->PartitionCount == 0) {
        QUIC_DBG_ASSERT(Lookup->SINGLE.Connection == SourceCid->Connection);
        if (Lookup->CidCount == 0) {
            //
            // This was the last CID reference, so we can clear the connection
            // pointer.
            //
            Lookup->SINGLE.Connection = NULL;
        }
    } else {
        QUIC_DBG_ASSERT(SourceCid->CID.Length >= QUIC_CID_PID_INDEX + QUIC_CID_PID_LENGTH);

        //
        // Remove the source connection ID from the multi-hash table.
        //
        QUIC_STATIC_ASSERT(QUIC_CID_PID_LENGTH == 1, "The code below assumes 1 byte");
        uint32_t PartitionIndex = SourceCid->CID.Data[QUIC_CID_PID_INDEX];
        PartitionIndex &= MsQuicLib.PartitionMask;
        PartitionIndex %= Lookup->PartitionCount;
        QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[PartitionIndex];
        QuicDispatchRwLockAcquireExclusive(&Table->RwLock);
        QuicHashtableRemove(&Table->Table, &SourceCid->Entry, NULL);
        QuicDispatchRwLockReleaseExclusive(&Table->RwLock);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnection(
    _In_ QUIC_LOOKUP* Lookup,
    _In_reads_(CIDLen)
        const uint8_t* const CID,
    _In_ uint8_t CIDLen
    )
{
    uint32_t Hash = QuicHashSimple(CIDLen, CID);

    QuicDispatchRwLockAcquireShared(&Lookup->RwLock);

    QUIC_CONNECTION* ExistingConnection =
        QuicLookupFindConnectionInternal(
            Lookup,
            CID,
            CIDLen,
            Hash);

    if (ExistingConnection != NULL) {
        QuicConnAddRef(ExistingConnection, QUIC_CONN_REF_LOOKUP_RESULT);
    }

    QuicDispatchRwLockReleaseShared(&Lookup->RwLock);

    return ExistingConnection;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByRemoteAddr(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    QUIC_CONNECTION* ExistingConnection = NULL;
    UNREFERENCED_PARAMETER(RemoteAddress); // Can't even validate this for single connection lookups right now.

    QuicDispatchRwLockAcquireShared(&Lookup->RwLock);

    if (Lookup->PartitionCount == 0) {
        //
        // Only a single connection is on this binding.
        //
        ExistingConnection = Lookup->SINGLE.Connection;
    } else {
        //
        // Not supported on server for now. We would need an efficient way
        // to do a lookup based on remote address to support this.
        //
    }

    if (ExistingConnection != NULL) {
        QuicConnAddRef(ExistingConnection, QUIC_CONN_REF_LOOKUP_RESULT);
    }

    QuicDispatchRwLockReleaseShared(&Lookup->RwLock);

    return ExistingConnection;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupAddSourceConnectionID(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _Out_opt_ QUIC_CONNECTION** Collision
    )
{
    BOOLEAN Result;
    QUIC_CONNECTION* ExistingConnection;
    uint32_t Hash = QuicHashSimple(SourceCid->CID.Length, SourceCid->CID.Data);

    QuicDispatchRwLockAcquireExclusive(&Lookup->RwLock);

    ExistingConnection =
        QuicLookupFindConnectionInternal(
            Lookup,
            SourceCid->CID.Data,
            SourceCid->CID.Length,
            Hash);

    if (ExistingConnection == NULL) {
        Result =
            QuicLookupInsertSourceConnectionID(Lookup, Hash, SourceCid, TRUE);
        if (Collision != NULL) {
            *Collision = NULL;
        }
    } else {
        Result = FALSE;
        if (Collision != NULL) {
            *Collision = ExistingConnection;
            QuicConnAddRef(ExistingConnection, QUIC_CONN_REF_LOOKUP_RESULT);
        }
    }

    QuicDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    return Result;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveSourceConnectionID(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid
    )
{
    QuicDispatchRwLockAcquireExclusive(&Lookup->RwLock);
    QuicLookupRemoveSourceConnectionIDInt(Lookup, SourceCid);
    QuicDispatchRwLockReleaseExclusive(&Lookup->RwLock);
    QuicConnRelease(SourceCid->Connection, QUIC_CONN_REF_LOOKUP_TABLE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveSourceConnectionIDs(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint8_t ReleaseRefCount = 0;

    QuicDispatchRwLockAcquireExclusive(&Lookup->RwLock);
    while (Connection->SourceCids.Next != NULL) {
        QUIC_CID_HASH_ENTRY *CID =
            QUIC_CONTAINING_RECORD(
                QuicListPopEntry(&Connection->SourceCids),
                QUIC_CID_HASH_ENTRY,
                Link);
        QUIC_DBG_ASSERT(CID->CID.IsInList);
        CID->CID.IsInList = FALSE;
        QuicLookupRemoveSourceConnectionIDInt(Lookup, CID);
        QUIC_FREE(CID);
        ReleaseRefCount++;
    }
    QuicDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    for (uint8_t i = 0; i < ReleaseRefCount; i++) {
#pragma prefast(suppress:6001, "SAL doesn't understand ref counts")
        QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_TABLE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupMoveSourceConnectionIDs(
    _In_ QUIC_LOOKUP* LookupSrc,
    _In_ QUIC_LOOKUP* LookupDest,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_SINGLE_LIST_ENTRY* Entry = Connection->SourceCids.Next;

    QuicDispatchRwLockAcquireExclusive(&LookupSrc->RwLock);
    while (Entry != NULL) {
        QUIC_CID_HASH_ENTRY *CID =
            QUIC_CONTAINING_RECORD(
                Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        QuicLookupRemoveSourceConnectionIDInt(LookupSrc, CID);
        QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_TABLE);
        Entry = Entry->Next;
    }
    QuicDispatchRwLockReleaseExclusive(&LookupSrc->RwLock);

#pragma prefast(suppress:6001, "SAL doesn't understand ref counts")
    Entry = Connection->SourceCids.Next;
    while (Entry != NULL) {
        QUIC_CID_HASH_ENTRY *CID =
            QUIC_CONTAINING_RECORD(
                Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        BOOLEAN Result =
            QuicLookupInsertSourceConnectionID(
                LookupDest,
                QuicHashSimple(CID->CID.Length, CID->CID.Data),
                CID,
                TRUE);
        QUIC_DBG_ASSERT(Result);
        UNREFERENCED_PARAMETER(Result);
        Entry = Entry->Next;
    }
}
