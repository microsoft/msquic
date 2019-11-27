/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_PARTITIONED_HASHTABLE QUIC_PARTITIONED_HASHTABLE;

//
// CID-keyed lookup table for connections.
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
    QUIC_DISPATCH_RW_LOCK RwLock;

    //
    // The number of partitions used for lookup tables. Value of 0 (default)
    // indicates only a single connection (may be NULL) is bound.
    //
    uint8_t PartitionCount;

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
            QUIC_PARTITIONED_HASHTABLE* Tables;
        } HASH;
    };

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
// Returns the connection with the given CID, or NULL.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicLookupFindConnection(
    _In_ QUIC_LOOKUP* Lookup,
    _In_reads_(CIDLen)
        const uint8_t* const CID,
    _In_ uint8_t CIDLen
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
// Attempts to insert the source CID into the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLookupAddSourceConnectionID(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCID,
    _Out_opt_ QUIC_CONNECTION** Collision
    );

//
// Removes a source CID from the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveSourceConnectionID(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CID_HASH_ENTRY* SourceCID
    );

//
// Removes all the connection's source CIDs from the lookup.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupRemoveSourceConnectionIDs(
    _In_ QUIC_LOOKUP* Lookup,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Moves all the connection's source CIDs from the one lookup to another.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLookupMoveSourceConnectionIDs(
    _In_ QUIC_LOOKUP* LookupSrc,
    _In_ QUIC_LOOKUP* LookupDest,
    _In_ QUIC_CONNECTION* Connection
    );
