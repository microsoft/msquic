/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Lookup tables for connections.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "lookup.c.clog.h"
#endif

typedef struct QUIC_CACHEALIGN QUIC_PARTITIONED_HASHTABLE {

    CXPLAT_DISPATCH_RW_LOCK RwLock;
    CXPLAT_HASHTABLE Table;

} QUIC_PARTITIONED_HASHTABLE;

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupInsertLocalCid(
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
    CxPlatZeroMemory(Lookup, sizeof(QUIC_LOOKUP));
    CxPlatDispatchRwLockInitialize(&Lookup->RwLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupUninitialize(
    _In_ QUIC_LOOKUP* Lookup
    )
{
    CXPLAT_DBG_ASSERT(Lookup->CidCount == 0);

    if (Lookup->PartitionCount == 0) {
        CXPLAT_DBG_ASSERT(Lookup->SINGLE.Connection == NULL);
    } else {
        CXPLAT_DBG_ASSERT(Lookup->HASH.Tables != NULL);
        for (uint16_t i = 0; i < Lookup->PartitionCount; i++) {
            QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[i];
            CXPLAT_DBG_ASSERT(Table->Table.NumEntries == 0);
#pragma warning(push)
#pragma warning(disable:6001)
            CxPlatHashtableUninitialize(&Table->Table);
#pragma warning(pop)
            CxPlatDispatchRwLockUninitialize(&Table->RwLock);
        }
        CXPLAT_FREE(Lookup->HASH.Tables, QUIC_POOL_LOOKUP_HASHTABLE);
    }

    if (Lookup->MaximizePartitioning) {
        CXPLAT_DBG_ASSERT(Lookup->RemoteHashTable.NumEntries == 0);
        CxPlatHashtableUninitialize(&Lookup->RemoteHashTable);
    }

    CxPlatDispatchRwLockUninitialize(&Lookup->RwLock);
}

//
// Allocates and initializes a new partitioned hash table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupCreateHashTable(
    _In_ QUIC_LOOKUP* Lookup,
    _In_range_(>, 0) uint16_t PartitionCount
    )
{
    CXPLAT_DBG_ASSERT(Lookup->LookupTable == NULL);
    CXPLAT_FRE_ASSERT(PartitionCount > 0);

    Lookup->HASH.Tables =
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_PARTITIONED_HASHTABLE) * PartitionCount,
            QUIC_POOL_LOOKUP_HASHTABLE);

    if (Lookup->HASH.Tables != NULL) {

        uint16_t Cleanup = 0;
        uint8_t Failed = FALSE;
        for (uint16_t i = 0; i < PartitionCount; i++) {
            if (!CxPlatHashtableInitializeEx(&Lookup->HASH.Tables[i].Table, CXPLAT_HASH_MIN_SIZE)) {
                Cleanup = i;
                Failed = TRUE;
                break;
            }
            CxPlatDispatchRwLockInitialize(&Lookup->HASH.Tables[i].RwLock);
        }
        if (Failed) {
            for (uint16_t i = 0; i < Cleanup; i++) {
                CxPlatHashtableUninitialize(&Lookup->HASH.Tables[i].Table);
            }
            CXPLAT_FREE(Lookup->HASH.Tables, QUIC_POOL_LOOKUP_HASHTABLE);
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

    uint16_t PartitionCount;
    if (Lookup->MaximizePartitioning) {
        PartitionCount = MsQuicLib.PartitionCount;

    } else if (Lookup->PartitionCount > 0 ||
               (Lookup->PartitionCount == 0 &&
                Lookup->SINGLE.Connection != NULL &&
                Lookup->SINGLE.Connection != Connection)) {
        PartitionCount = 1;

    } else {
        PartitionCount = 0;
    }

    //
    // Rebalance the binding if the partition count increased.
    //

    if (PartitionCount > Lookup->PartitionCount) {

        uint16_t PreviousPartitionCount = Lookup->PartitionCount;
        void* PreviousLookup = Lookup->LookupTable;
        Lookup->LookupTable = NULL;

        CXPLAT_DBG_ASSERT(PartitionCount != 0);

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
                CXPLAT_SLIST_ENTRY* Entry =
                    ((QUIC_CONNECTION*)PreviousLookup)->SourceCids.Next;

                while (Entry != NULL) {
                    QUIC_CID_HASH_ENTRY *CID =
                        CXPLAT_CONTAINING_RECORD(
                            Entry,
                            QUIC_CID_HASH_ENTRY,
                            Link);
                    (void)QuicLookupInsertLocalCid(
                        Lookup,
                        CxPlatHashSimple(CID->CID.Length, CID->CID.Data),
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
            for (uint16_t i = 0; i < PreviousPartitionCount; i++) {
                CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
#pragma warning(push)
#pragma warning(disable:6001)
                CxPlatHashtableEnumerateBegin(&PreviousTable[i].Table, &Enumerator);
#pragma warning(pop)
                while (TRUE) {
                    CXPLAT_HASHTABLE_ENTRY* Entry =
                        CxPlatHashtableEnumerateNext(&PreviousTable[i].Table, &Enumerator);
                    if (Entry == NULL) {
                        CxPlatHashtableEnumerateEnd(&PreviousTable[i].Table, &Enumerator);
                        break;
                    }
                    CxPlatHashtableRemove(&PreviousTable[i].Table, Entry, NULL);

                    QUIC_CID_HASH_ENTRY *CID =
                        CXPLAT_CONTAINING_RECORD(
                            Entry,
                            QUIC_CID_HASH_ENTRY,
                            Entry);
                    (void)QuicLookupInsertLocalCid(
                        Lookup,
                        CxPlatHashSimple(CID->CID.Length, CID->CID.Data),
                        CID,
                        FALSE);
                }
#pragma warning(push)
#pragma warning(disable:6001)
                CxPlatHashtableUninitialize(&PreviousTable[i].Table);
#pragma warning(pop)
            }
            CXPLAT_FREE(PreviousTable, QUIC_POOL_LOOKUP_HASHTABLE);
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

    CxPlatDispatchRwLockAcquireExclusive(&Lookup->RwLock);

    if (!Lookup->MaximizePartitioning) {
        Result =
            CxPlatHashtableInitializeEx(
                &Lookup->RemoteHashTable, CXPLAT_HASH_MIN_SIZE);
        if (Result) {
            Lookup->MaximizePartitioning = TRUE;
            Result = QuicLookupRebalance(Lookup, NULL);
            if (!Result) {
                CxPlatHashtableUninitialize(&Lookup->RemoteHashTable);
                Lookup->MaximizePartitioning = FALSE;
            }
        }
    }

    CxPlatDispatchRwLockReleaseExclusive(&Lookup->RwLock);

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
    for (CXPLAT_SLIST_ENTRY* Link = Connection->SourceCids.Next;
        Link != NULL;
        Link = Link->Next) {

        const QUIC_CID_HASH_ENTRY* const Entry =
            CXPLAT_CONTAINING_RECORD(Link, const QUIC_CID_HASH_ENTRY, Link);

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
    _In_ CXPLAT_HASHTABLE* Table,
    _In_reads_(Length)
        const uint8_t* const DestCid,
    _In_ uint8_t Length,
    _In_ uint32_t Hash
    )
{
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* TableEntry =
        CxPlatHashtableLookup(Table, Hash, &Context);

    while (TableEntry != NULL) {
        QUIC_CID_HASH_ENTRY* CIDEntry =
            CXPLAT_CONTAINING_RECORD(TableEntry, QUIC_CID_HASH_ENTRY, Entry);

        if (CIDEntry->CID.Length == Length &&
            memcmp(DestCid, CIDEntry->CID.Data, Length) == 0) {
            return CIDEntry->Connection;
        }

        TableEntry = CxPlatHashtableLookupNext(Table, &Context);
    }

    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByLocalCidInternal(
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
        CXPLAT_DBG_ASSERT(CIDLen >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
        CXPLAT_DBG_ASSERT(CID != NULL);

        //
        // Use the destination connection ID to get the index into the
        // partitioned hash table array, and look up the connection in that
        // hash table.
        //
        CXPLAT_STATIC_ASSERT(QUIC_CID_PID_LENGTH == 2, "The code below assumes 2 bytes");
        uint16_t PartitionIndex;
        CxPlatCopyMemory(&PartitionIndex, CID + MsQuicLib.CidServerIdLength, 2);
        PartitionIndex &= MsQuicLib.PartitionMask;
        PartitionIndex %= Lookup->PartitionCount;
        QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[PartitionIndex];

        CxPlatDispatchRwLockAcquireShared(&Table->RwLock);
        Connection =
            QuicHashLookupConnection(
                &Table->Table,
                CID,
                CIDLen,
                Hash);
        CxPlatDispatchRwLockReleaseShared(&Table->RwLock);
    }

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    if (Connection != NULL) {
        QuicTraceLogVerbose(
            LookupCidFound,
            "[look][%p] Lookup Hash=%u found %p",
            Lookup,
            Hash,
            Connection);
    } else {
        QuicTraceLogVerbose(
            LookupCidNotFound,
            "[look][%p] Lookup Hash=%u not found",
            Lookup,
            Hash);
    }
#endif

    return Connection;
}

//
// Requires Lookup->RwLock to be held (shared).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByRemoteHashInternal(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ const QUIC_ADDR* const RemoteAddress,
    _In_ uint8_t RemoteCidLength,
    _In_reads_(RemoteCidLength)
        const uint8_t* const RemoteCid,
    _In_ uint32_t Hash
    )
{
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* TableEntry =
        CxPlatHashtableLookup(&Lookup->RemoteHashTable, Hash, &Context);

    while (TableEntry != NULL) {
        QUIC_REMOTE_HASH_ENTRY* Entry =
            CXPLAT_CONTAINING_RECORD(TableEntry, QUIC_REMOTE_HASH_ENTRY, Entry);

        if (QuicAddrCompare(RemoteAddress, &Entry->RemoteAddress) &&
            RemoteCidLength == Entry->RemoteCidLength &&
            memcmp(RemoteCid, Entry->RemoteCid, RemoteCidLength) == 0) {
#if QUIC_DEBUG_HASHTABLE_LOOKUP
            QuicTraceLogVerbose(
                LookupRemoteHashFound,
                "[look][%p] Lookup RemoteHash=%u found %p",
                Lookup,
                Hash,
                Entry->Connection);
#endif
            return Entry->Connection;
        }

        TableEntry = CxPlatHashtableLookupNext(&Lookup->RemoteHashTable, &Context);
    }

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    QuicTraceLogVerbose(
        LookupRemoteHashNotFound,
        "[look][%p] Lookup RemoteHash=%u not found",
        Lookup,
        Hash);
#endif

    return NULL;
}

//
// Inserts a source connection ID into the lookup table. Requires the
// Lookup->RwLock to be exlusively held.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupInsertLocalCid(
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
        CXPLAT_DBG_ASSERT(SourceCid->CID.Length >= MsQuicLib.CidServerIdLength + QUIC_CID_PID_LENGTH);

        //
        // Insert the source connection ID into the hash table.
        //
        CXPLAT_STATIC_ASSERT(QUIC_CID_PID_LENGTH == 2, "The code below assumes 2 bytes");
        uint16_t PartitionIndex;
        CxPlatCopyMemory(&PartitionIndex, SourceCid->CID.Data + MsQuicLib.CidServerIdLength, 2);
        PartitionIndex &= MsQuicLib.PartitionMask;
        PartitionIndex %= Lookup->PartitionCount;
        QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[PartitionIndex];

        CxPlatDispatchRwLockAcquireExclusive(&Table->RwLock);
        CxPlatHashtableInsert(
            &Table->Table,
            &SourceCid->Entry,
            Hash,
            NULL);
        CxPlatDispatchRwLockReleaseExclusive(&Table->RwLock);
    }

    if (UpdateRefCount) {
        Lookup->CidCount++;
        QuicConnAddRef(SourceCid->Connection, QUIC_CONN_REF_LOOKUP_TABLE);
    }

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    QuicTraceLogVerbose(
        LookupCidInsert,
        "[look][%p] Insert Conn=%p Hash=%u",
        Lookup,
        SourceCid->Connection,
        Hash);
#endif

    SourceCid->CID.IsInLookupTable = TRUE;

    return TRUE;
}

//
// Requires the Lookup->RwLock to be exlusively held.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupInsertRemoteHash(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ uint32_t Hash,
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* const RemoteAddress,
    _In_ uint8_t RemoteCidLength,
    _In_reads_(RemoteCidLength)
        const uint8_t* const RemoteCid,
    _In_ BOOLEAN UpdateRefCount
    )
{
    QUIC_REMOTE_HASH_ENTRY* Entry =
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_REMOTE_HASH_ENTRY) + RemoteCidLength,
            QUIC_POOL_REMOTE_HASH);
    if (Entry == NULL) {
        return FALSE;
    }

    Entry->Connection = Connection;
    Entry->RemoteAddress = *RemoteAddress;
    Entry->RemoteCidLength = RemoteCidLength;
    CxPlatCopyMemory(
        Entry->RemoteCid,
        RemoteCid,
        RemoteCidLength);

    CxPlatHashtableInsert(
        &Lookup->RemoteHashTable,
        &Entry->Entry,
        Hash,
        NULL);

    Connection->RemoteHashEntry = Entry;

    QuicLibraryOnHandshakeConnectionAdded();

    if (UpdateRefCount) {
        QuicConnAddRef(Connection, QUIC_CONN_REF_LOOKUP_TABLE);
    }

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    QuicTraceLogVerbose(
        LookupRemoteHashInsert,
        "[look][%p] Insert Conn=%p RemoteHash=%u",
        Lookup,
        Connection,
        Hash);
#endif

    return TRUE;
}

//
// Removes a source connection ID from the lookup table. Requires the
// Lookup->RwLock to be exlusively held.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveLocalCidInt(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid
    )
{
    CXPLAT_DBG_ASSERT(SourceCid->CID.IsInLookupTable);
    CXPLAT_DBG_ASSERT(Lookup->CidCount != 0);
    Lookup->CidCount--;

#if QUIC_DEBUG_HASHTABLE_LOOKUP
    QuicTraceLogVerbose(
        LookupCidRemoved,
        "[look][%p] Remove Conn=%p",
        Lookup,
        SourceCid->Connection);
#endif

    if (Lookup->PartitionCount == 0) {
        CXPLAT_DBG_ASSERT(Lookup->SINGLE.Connection == SourceCid->Connection);
        if (Lookup->CidCount == 0) {
            //
            // This was the last CID reference, so we can clear the connection
            // pointer.
            //
            Lookup->SINGLE.Connection = NULL;
        }
    } else {
        CXPLAT_DBG_ASSERT(SourceCid->CID.Length >= MsQuicLib.CidServerIdLength + QUIC_CID_PID_LENGTH);

        //
        // Remove the source connection ID from the multi-hash table.
        //
        CXPLAT_STATIC_ASSERT(QUIC_CID_PID_LENGTH == 2, "The code below assumes 2 bytes");
        uint16_t PartitionIndex;
        CxPlatCopyMemory(&PartitionIndex, SourceCid->CID.Data + MsQuicLib.CidServerIdLength, 2);
        PartitionIndex &= MsQuicLib.PartitionMask;
        PartitionIndex %= Lookup->PartitionCount;
        QUIC_PARTITIONED_HASHTABLE* Table = &Lookup->HASH.Tables[PartitionIndex];
        CxPlatDispatchRwLockAcquireExclusive(&Table->RwLock);
        CxPlatHashtableRemove(&Table->Table, &SourceCid->Entry, NULL);
        CxPlatDispatchRwLockReleaseExclusive(&Table->RwLock);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByLocalCid(
    _In_ QUIC_LOOKUP* Lookup,
    _In_reads_(CIDLen)
        const uint8_t* const CID,
    _In_ uint8_t CIDLen
    )
{
    uint32_t Hash = CxPlatHashSimple(CIDLen, CID);

    CxPlatDispatchRwLockAcquireShared(&Lookup->RwLock);

    QUIC_CONNECTION* ExistingConnection =
        QuicLookupFindConnectionByLocalCidInternal(
            Lookup,
            CID,
            CIDLen,
            Hash);

    if (ExistingConnection != NULL) {
        QuicConnAddRef(ExistingConnection, QUIC_CONN_REF_LOOKUP_RESULT);
    }

    CxPlatDispatchRwLockReleaseShared(&Lookup->RwLock);

    return ExistingConnection;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByRemoteHash(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ const QUIC_ADDR* const RemoteAddress,
    _In_ uint8_t RemoteCidLength,
    _In_reads_(RemoteCidLength)
        const uint8_t* const RemoteCid
    )
{
    uint32_t Hash = QuicPacketHash(RemoteAddress, RemoteCidLength, RemoteCid);

    CxPlatDispatchRwLockAcquireShared(&Lookup->RwLock);

    QUIC_CONNECTION* ExistingConnection;
    if (Lookup->MaximizePartitioning) {
        ExistingConnection =
            QuicLookupFindConnectionByRemoteHashInternal(
                Lookup,
                RemoteAddress,
                RemoteCidLength,
                RemoteCid,
                Hash);

        if (ExistingConnection != NULL) {
            QuicConnAddRef(ExistingConnection, QUIC_CONN_REF_LOOKUP_RESULT);
        }

    } else {
        ExistingConnection = NULL;
    }

    CxPlatDispatchRwLockReleaseShared(&Lookup->RwLock);

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

    CxPlatDispatchRwLockAcquireShared(&Lookup->RwLock);

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

    CxPlatDispatchRwLockReleaseShared(&Lookup->RwLock);

    return ExistingConnection;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupAddLocalCid(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _Out_opt_ QUIC_CONNECTION** Collision
    )
{
    BOOLEAN Result;
    QUIC_CONNECTION* ExistingConnection;
    uint32_t Hash = CxPlatHashSimple(SourceCid->CID.Length, SourceCid->CID.Data);

    CxPlatDispatchRwLockAcquireExclusive(&Lookup->RwLock);

    CXPLAT_DBG_ASSERT(!SourceCid->CID.IsInLookupTable);

    ExistingConnection =
        QuicLookupFindConnectionByLocalCidInternal(
            Lookup,
            SourceCid->CID.Data,
            SourceCid->CID.Length,
            Hash);

    if (ExistingConnection == NULL) {
        Result =
            QuicLookupInsertLocalCid(Lookup, Hash, SourceCid, TRUE);
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

    CxPlatDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    return Result;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupAddRemoteHash(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* const RemoteAddress,
    _In_ uint8_t RemoteCidLength,
    _In_reads_(RemoteCidLength)
        const uint8_t* const RemoteCid,
    _Out_ QUIC_CONNECTION** Collision
    )
{

    BOOLEAN Result;
    QUIC_CONNECTION* ExistingConnection;
    uint32_t Hash = QuicPacketHash(RemoteAddress, RemoteCidLength, RemoteCid);

    CxPlatDispatchRwLockAcquireExclusive(&Lookup->RwLock);

    if (Lookup->MaximizePartitioning) {
        ExistingConnection =
            QuicLookupFindConnectionByRemoteHashInternal(
                Lookup,
                RemoteAddress,
                RemoteCidLength,
                RemoteCid,
                Hash);

        if (ExistingConnection == NULL) {
            Result =
                QuicLookupInsertRemoteHash(
                    Lookup,
                    Hash,
                    Connection,
                    RemoteAddress,
                    RemoteCidLength,
                    RemoteCid,
                    TRUE);
            *Collision = NULL;
        } else {
            Result = FALSE;
            *Collision = ExistingConnection;
            QuicConnAddRef(ExistingConnection, QUIC_CONN_REF_LOOKUP_RESULT);
        }
    } else {
        Result = FALSE;
        *Collision = NULL;
    }

    CxPlatDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    return Result;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveLocalCid(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _In_ CXPLAT_SLIST_ENTRY** Entry
    )
{
    CxPlatDispatchRwLockAcquireExclusive(&Lookup->RwLock);
    QuicLookupRemoveLocalCidInt(Lookup, SourceCid);
    SourceCid->CID.IsInLookupTable = FALSE;
    *Entry = (*Entry)->Next;
    CxPlatDispatchRwLockReleaseExclusive(&Lookup->RwLock);
    QuicConnRelease(SourceCid->Connection, QUIC_CONN_REF_LOOKUP_TABLE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveRemoteHash(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_REMOTE_HASH_ENTRY* RemoteHashEntry
    )
{
    QUIC_CONNECTION* Connection = RemoteHashEntry->Connection;
    CXPLAT_DBG_ASSERT(Lookup->MaximizePartitioning);

    QuicLibraryOnHandshakeConnectionRemoved();

    CxPlatDispatchRwLockAcquireExclusive(&Lookup->RwLock);
    CXPLAT_DBG_ASSERT(Connection->RemoteHashEntry != NULL);
    CxPlatHashtableRemove(
        &Lookup->RemoteHashTable,
        &RemoteHashEntry->Entry,
        NULL);
    Connection->RemoteHashEntry = NULL;
    CxPlatDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    CXPLAT_FREE(RemoteHashEntry, QUIC_POOL_REMOTE_HASH);
    QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_TABLE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveLocalCids(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint8_t ReleaseRefCount = 0;

    CxPlatDispatchRwLockAcquireExclusive(&Lookup->RwLock);
    while (Connection->SourceCids.Next != NULL) {
        QUIC_CID_HASH_ENTRY *CID =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListPopEntry(&Connection->SourceCids),
                QUIC_CID_HASH_ENTRY,
                Link);
        if (CID->CID.IsInLookupTable) {
            QuicLookupRemoveLocalCidInt(Lookup, CID);
            CID->CID.IsInLookupTable = FALSE;
            ReleaseRefCount++;
        }
        CXPLAT_FREE(CID, QUIC_POOL_CIDHASH);
    }
    CxPlatDispatchRwLockReleaseExclusive(&Lookup->RwLock);

    for (uint8_t i = 0; i < ReleaseRefCount; i++) {
#pragma prefast(suppress:6001, "SAL doesn't understand ref counts")
        QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_TABLE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupMoveLocalConnectionIDs(
    _In_ QUIC_LOOKUP* LookupSrc,
    _In_ QUIC_LOOKUP* LookupDest,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_SLIST_ENTRY* Entry = Connection->SourceCids.Next;

    CxPlatDispatchRwLockAcquireExclusive(&LookupSrc->RwLock);
    while (Entry != NULL) {
        QUIC_CID_HASH_ENTRY *CID =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        if (CID->CID.IsInLookupTable) {
            QuicLookupRemoveLocalCidInt(LookupSrc, CID);
            QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_TABLE);
        }
        Entry = Entry->Next;
    }
    CxPlatDispatchRwLockReleaseExclusive(&LookupSrc->RwLock);

    CxPlatDispatchRwLockAcquireExclusive(&LookupDest->RwLock);
#pragma prefast(suppress:6001, "SAL doesn't understand ref counts")
    Entry = Connection->SourceCids.Next;
    while (Entry != NULL) {
        QUIC_CID_HASH_ENTRY *CID =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        if (CID->CID.IsInLookupTable) {
            BOOLEAN Result =
                QuicLookupInsertLocalCid(
                    LookupDest,
                    CxPlatHashSimple(CID->CID.Length, CID->CID.Data),
                    CID,
                    TRUE);
            CXPLAT_DBG_ASSERT(Result);
            UNREFERENCED_PARAMETER(Result);
        }
        Entry = Entry->Next;
    }
    CxPlatDispatchRwLockReleaseExclusive(&LookupDest->RwLock);
}
