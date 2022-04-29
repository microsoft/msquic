/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Definitions for connection IDs.

--*/

//
// The maximum CID server ID length used by MsQuic.
//
#define QUIC_MAX_CID_SID_LENGTH                 5

//
// The index of the byte we use for partition ID lookup, in the connection ID.
// The PID is 2 bytes. The PID immediately follows the SID.
//
#define QUIC_CID_PID_LENGTH                     2

//
// The number of bytes (and randomness) that MsQuic uses to uniquely
// identify connections for a single server / partition combination.
//
#define QUIC_CID_PAYLOAD_LENGTH                 7

//
// The minimum number of bytes that should be purely random in a CID.
//
#define QUIC_CID_MIN_RANDOM_BYTES               4

//
// The maximum number of bytes that MsQuic supports encoding for CIBIR in a CID.
//
#define QUIC_MAX_CIBIR_LENGTH                   6

//
// The minimum length CIDs that MsQuic ever will generate.
//
#define QUIC_CID_MIN_LENGTH \
    (QUIC_CID_PID_LENGTH + QUIC_CID_PAYLOAD_LENGTH)

//
// The maximum length CIDs that MsQuic ever will generate.
//
#define QUIC_CID_MAX_LENGTH \
    (QUIC_MAX_CID_SID_LENGTH + \
     QUIC_CID_PID_LENGTH + \
     QUIC_CID_PAYLOAD_LENGTH)

CXPLAT_STATIC_ASSERT(
    QUIC_CID_MIN_LENGTH >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH,
    "MsQuic CID length must be at least the minimum initial length");

CXPLAT_STATIC_ASSERT(
    QUIC_CID_MAX_LENGTH <= QUIC_MAX_CONNECTION_ID_LENGTH_V1,
    "MsQuic CID length must fit in v1");

//
// The maximum size of the prefix an app is allowed to configure is dependent on
// the values of the other defines above; essentially constituting the left over
// part of the CID buffer.
//
#define QUIC_CID_MAX_APP_PREFIX \
    (QUIC_CID_PAYLOAD_LENGTH - QUIC_CID_MIN_RANDOM_BYTES)

//
// The maximum number we will try to randomly generate a new initial CID before
// failing.
//
#define QUIC_CID_MAX_COLLISION_RETRY            8

//
// Connection ID Structures
//

typedef struct QUIC_CID {

    //
    // The CID is the original one used by the client in its first Initial
    // packet.
    //
    uint8_t IsInitial : 1;
    //
    // The CID needs to be sent in a NEW_CONNECTION_ID or RETIRE_CONNECTION_ID
    // frame. It may need to be sent either because it has never been sent
    // before or because it was previously lost and needs to be retransmitted.
    //
    uint8_t NeedsToSend : 1;
    //
    // Used for source CIDs. A NEW_CONNECTION_ID frame previously sent for this
    // CID has been acknowledged by the peer.
    //
    uint8_t Acknowledged : 1;
    //
    // Used for destination CIDs. The CID has been locally assigned to a path
    // and can't be used for any other path.
    //
    uint8_t UsedLocally : 1;
    //
    // Used for source CIDs. The peer has sent a packet that used this CID.
    //
    uint8_t UsedByPeer : 1;
    //
    // When used for destination CIDs, the CID has been locally retired. Once the
    // peer has acknowledged this, the CID can be deleted.
    // When used for source CIDs, the CID has been indicated as needing to be
    // retired. Once the peer has retired this, the CID can be deleted.
    //
    uint8_t Retired : 1;
    //
    // Used for destination CIDs. The CID has a stateless reset token associated
    // with it (given to us by the peer).
    //
    uint8_t HasResetToken : 1;
    //
    // Used for source CIDs. The CID is in the binding's lookup table.
    //
    uint8_t IsInLookupTable : 1;

    uint8_t Length;
    QUIC_VAR_INT SequenceNumber;
    _Field_size_bytes_(Length)
    uint8_t Data[0];

} QUIC_CID;

typedef struct QUIC_CID_LIST_ENTRY {

    CXPLAT_LIST_ENTRY Link;
    uint8_t ResetToken[QUIC_STATELESS_RESET_TOKEN_LENGTH];
#ifdef DEBUG
    QUIC_PATH* AssignedPath;
#endif
    QUIC_CID CID;

} QUIC_CID_LIST_ENTRY;

#if DEBUG
#define QUIC_CID_SET_PATH(Conn, Cid, Path)                                      \
    do {                                                                        \
        CXPLAT_DBG_ASSERT(!Cid->CID.Retired);                                   \
        CXPLAT_DBG_ASSERT(Cid->AssignedPath == NULL); Cid->AssignedPath = Path; \
        for (uint8_t PathIdx = Conn->PathsCount - 1; PathIdx > 0; PathIdx--) {  \
            if (Path != &Conn->Paths[PathIdx])                                  \
                CXPLAT_DBG_ASSERT(Conn->Paths[PathIdx].DestCid != Cid);         \
            }                                                                   \
        }                                                                       \
    while (0)
#define QUIC_CID_CLEAR_PATH(Cid) Cid->AssignedPath = NULL
#define QUIC_CID_VALIDATE_NULL(Conn, Cid)                                       \
    do {                                                                        \
        CXPLAT_DBG_ASSERT(Cid->AssignedPath == NULL);                           \
        for (uint8_t PathIdx = Conn->PathsCount - 1; PathIdx > 0; PathIdx--) {  \
            CXPLAT_DBG_ASSERT(Conn->Paths[PathIdx].DestCid != Cid);             \
        }                                                                       \
    } while (0)
#else
#define QUIC_CID_SET_PATH(Conn, Cid, Path) UNREFERENCED_PARAMETER(Cid)
#define QUIC_CID_CLEAR_PATH(Cid) UNREFERENCED_PARAMETER(Cid)
#define QUIC_CID_VALIDATE_NULL(Conn, Cid) UNREFERENCED_PARAMETER(Cid)
#endif

typedef struct QUIC_CID_HASH_ENTRY {

    CXPLAT_HASHTABLE_ENTRY Entry;
    CXPLAT_SLIST_ENTRY Link;
    QUIC_CONNECTION* Connection;
    QUIC_CID CID;

} QUIC_CID_HASH_ENTRY;

//
// Creates a new null/empty source connection ID, that will be used on the
// receive path.
//
inline
_Success_(return != NULL)
QUIC_CID_HASH_ENTRY*
QuicCidNewNullSource(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_CID_HASH_ENTRY* Entry =
        (QUIC_CID_HASH_ENTRY*)CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_CID_HASH_ENTRY),
            QUIC_POOL_CIDHASH);

    if (Entry != NULL) {
        Entry->Connection = Connection;
        CxPlatZeroMemory(&Entry->CID, sizeof(Entry->CID));
    }

    return Entry;
}

//
// Creates a source connection ID from a pre-existing CID buffer.
//
inline
_Success_(return != NULL)
QUIC_CID_HASH_ENTRY*
QuicCidNewSource(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Length,
    _In_reads_(Length)
        const uint8_t* const Data
    )
{
    QUIC_CID_HASH_ENTRY* Entry =
        (QUIC_CID_HASH_ENTRY*)
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_CID_HASH_ENTRY) +
            Length,
            QUIC_POOL_CIDHASH);

    if (Entry != NULL) {
        Entry->Connection = Connection;
        CxPlatZeroMemory(&Entry->CID, sizeof(Entry->CID));
        Entry->CID.Length = Length;
        if (Length != 0) {
            memcpy(Entry->CID.Data, Data, Length);
        }
    }

    return Entry;
}

//
// Used for the client's Initial packet (and 0-RTT), this creates a random
// destination connection ID.
//
inline
_Success_(return != NULL)
QUIC_CID_LIST_ENTRY*
QuicCidNewRandomDestination(
    )
{
    QUIC_CID_LIST_ENTRY* Entry =
        (QUIC_CID_LIST_ENTRY*)
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_CID_LIST_ENTRY) +
            QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH,
            QUIC_POOL_CIDLIST);

    if (Entry != NULL) {
        QUIC_CID_CLEAR_PATH(Entry);
        CxPlatZeroMemory(&Entry->CID, sizeof(Entry->CID));
        Entry->CID.Length = QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH;
        CxPlatRandom(QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH, Entry->CID.Data);
    }

    return Entry;
}

//
// Creates a destination connection ID from a pre-existing CID buffer.
//
inline
_Success_(return != NULL)
QUIC_CID_LIST_ENTRY*
QuicCidNewDestination(
    _In_ uint8_t Length,
    _In_reads_(Length)
        const uint8_t* const Data
    )
{
    QUIC_CID_LIST_ENTRY* Entry =
        (QUIC_CID_LIST_ENTRY*)
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_CID_LIST_ENTRY) +
            Length,
            QUIC_POOL_CIDLIST);

    if (Entry != NULL) {
        QUIC_CID_CLEAR_PATH(Entry);
        CxPlatZeroMemory(&Entry->CID, sizeof(Entry->CID));
        Entry->CID.Length = Length;
        if (Length != 0) {
            memcpy(Entry->CID.Data, Data, Length);
        }
    }

    return Entry;
}

//
// Helpers for logging connection IDs.
//

typedef struct QUIC_CID_STR {
    char Buffer[2 * QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT + 1];
} QUIC_CID_STR;

inline char QuicHalfByteToStr(uint8_t b)
{
    return b < 10 ? ('0' + b) : ('a' + b - 10);
}

inline
QUIC_CID_STR
QuicCidBufToStr(
    _In_reads_(Length)
        const uint8_t* const Data,
    _In_ uint8_t Length
    )
{
    QUIC_CID_STR CidStr = { 0 };
    for (uint8_t i = 0; i < Length; i++) {
        CidStr.Buffer[i * 2] = QuicHalfByteToStr(Data[i] >> 4);
        CidStr.Buffer[i * 2 + 1] = QuicHalfByteToStr(Data[i] & 0xF);
    }
    CidStr.Buffer[Length * 2] = 0;
    return CidStr;
}

inline
QUIC_CID_STR
QuicCidToStr(
    _In_ const QUIC_CID* const CID
    )
{
    return QuicCidBufToStr(CID->Data, CID->Length);
}
