/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_PARTITIONED_HASHTABLE QUIC_PARTITIONED_HASHTABLE;

typedef struct QUIC_REMOTE_HASH_ENTRY {

    CXPLAT_HASHTABLE_ENTRY Entry;
    QUIC_CONNECTION* Connection;
    QUIC_ADDR RemoteAddress;
    uint8_t RemoteCidLength;
    uint8_t RemoteCid[0];

} QUIC_REMOTE_HASH_ENTRY;

//
// Lookup table for connections.
//
typedef struct QUIC_LOOKUP {

    //
    // Indicates that maximized partitioning is needed, likely because a
    // listener is on the binding where this lookup resides.
    //
    BOOLEAN MaximizePartitioning;

    //
    // Number of connection IDs in the lookup.
    //
    uint32_t CidCount;

    //
    // Lock for accessing the lookup data.
    //
    CXPLAT_DISPATCH_RW_LOCK RwLock;

    //
    // The number of partitions used for lookup tables. Value of 0 (default)
    // indicates only a single connection (may be NULL) is bound.
    //
    uint16_t PartitionCount;

    //
    // Local CID lookup.
    //
    union {
        void* LookupTable;
        struct {
            //
            // Single client connection is bound.
            //
            QUIC_CONNECTION* Connection;
        } SINGLE;
        struct {
            //
            // Set of partitioned hash tables.
            //
            _Field_size_bytes_(PartitionCount * sizeof(QUIC_PARTITIONED_HASHTABLE))
            QUIC_PARTITIONED_HASHTABLE* Tables;
        } HASH;
    };

    //
    // Remote Hash lookup.
    //
    CXPLAT_HASHTABLE RemoteHashTable;

} QUIC_LOOKUP;

//
// Initializes a new lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupInitialize(
    _Inout_ QUIC_LOOKUP* Lookup
    );

//
// Uninitializes the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupUninitialize(
    _In_ QUIC_LOOKUP* Lookup
    );

//
// Maximize lookup table partitioning.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupMaximizePartitioning(
    _In_ QUIC_LOOKUP* Lookup
    );

//
// Returns the connection with the given local CID, or NULL.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByLocalCid(
    _In_ QUIC_LOOKUP* Lookup,
    _In_reads_(CIDLen)
        const uint8_t* const CID,
    _In_ uint8_t CIDLen
    );

//
// Returns the connection with the given remote hash, or NULL.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByRemoteHash(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ const QUIC_ADDR* const RemoteAddress,
    _In_ uint8_t RemoteCidLength,
    _In_reads_(RemoteCidLength)
        const uint8_t* const RemoteCid
    );

//
// Returns the connection with the given remote address, or NULL.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnectionByRemoteAddr(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ const QUIC_ADDR* RemoteAddress
    );

//
// Attempts to insert the local CID into the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupAddLocalCid(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _Out_opt_ QUIC_CONNECTION** Collision
    );

//
// Attempts to insert the remote hash into the lookup.
//
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
    );

//
// Removes a local CID from the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveLocalCid(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _In_ CXPLAT_SLIST_ENTRY** Entry
    );

//
// Removes a remote hash from the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveRemoteHash(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_REMOTE_HASH_ENTRY* RemoteHashEntry
    );

//
// Removes all the connection's local CIDs from the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveLocalCids(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Moves all the connection's local CIDs from the one lookup to another.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupMoveLocalConnectionIDs(
    _In_ QUIC_LOOKUP* LookupSrc,
    _In_ QUIC_LOOKUP* LookupDest,
    _In_ QUIC_CONNECTION* Connection
    );
