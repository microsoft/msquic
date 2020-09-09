/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Definitions for connection IDs.

--*/

//
// Maximum number of bytes allowed for a connection ID.
//
#define QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT     255
#define QUIC_MAX_CONNECTION_ID_LENGTH_V1            20

//
// Minimum number of bytes required for a connection ID in the client's
// Initial packet.
//
#define QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH       8

//
// The maximum CID server ID length used by MsQuic.
//
#define MSQUIC_MAX_CID_SID_LENGTH                   5

//
// The index of the byte we use for partition ID lookup, in the connection ID.
// The PID is 2 bytes. The PID immediately follows the SID.
//
#define MSQUIC_CID_PID_LENGTH                       2

//
// The number of bytes (and randomness) that MsQuic uses to uniquely
// identify connections for a single server / partition combination.
//
#define MSQUIC_CID_PAYLOAD_LENGTH                   7

//
// The minimum number of bytes that should be purely random in a CID.
//
#define MSQUIC_CID_MIN_RANDOM_BYTES                 4

//
// The minimum length CIDs that MsQuic ever will generate.
//
#define MSQUIC_CID_MIN_LENGTH \
    (MSQUIC_CID_PID_LENGTH + MSQUIC_CID_PAYLOAD_LENGTH)

//
// The maximum length CIDs that MsQuic ever will generate.
//
#define MSQUIC_CID_MAX_LENGTH \
    (MSQUIC_MAX_CID_SID_LENGTH + \
     MSQUIC_CID_PID_LENGTH + \
     MSQUIC_CID_PAYLOAD_LENGTH)

QUIC_STATIC_ASSERT(
    MSQUIC_CID_MIN_LENGTH >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH,
    "MsQuic CID length must be at least the minimum initial length");

QUIC_STATIC_ASSERT(
    MSQUIC_CID_MAX_LENGTH <= QUIC_MAX_CONNECTION_ID_LENGTH_V1,
    "MsQuic CID length must fit in v1");

//
// The maximum size of the prefix an app is allowed to configure is dependent on
// the values of the other defines above; essentially constituting the left over
// part of the CID buffer.
//
#define MSQUIC_CID_MAX_APP_PREFIX \
    (MSQUIC_CID_PAYLOAD_LENGTH - MSQUIC_CID_MIN_RANDOM_BYTES)

//
// The maximum number we will try to randomly calculate a new initial CID before
// failing.
//
#define QUIC_CID_MAX_COLLISION_RETRY                8

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

typedef struct QUIC_CID_QUIC_LIST_ENTRY {

    QUIC_LIST_ENTRY Link;
    uint8_t ResetToken[QUIC_STATELESS_RESET_TOKEN_LENGTH];
    QUIC_CID CID;

} QUIC_CID_QUIC_LIST_ENTRY;

typedef struct QUIC_CID_HASH_ENTRY {

    QUIC_HASHTABLE_ENTRY Entry;
    QUIC_SINGLE_LIST_ENTRY Link;
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
        (QUIC_CID_HASH_ENTRY*)QUIC_ALLOC_NONPAGED(sizeof(QUIC_CID_HASH_ENTRY));

    if (Entry != NULL) {
        Entry->Connection = Connection;
        QuicZeroMemory(&Entry->CID, sizeof(Entry->CID));
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
        QUIC_ALLOC_NONPAGED(
            sizeof(QUIC_CID_HASH_ENTRY) +
            Length);

    if (Entry != NULL) {
        Entry->Connection = Connection;
        QuicZeroMemory(&Entry->CID, sizeof(Entry->CID));
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
QUIC_CID_QUIC_LIST_ENTRY*
QuicCidNewRandomDestination(
    )
{
    QUIC_CID_QUIC_LIST_ENTRY* Entry =
        (QUIC_CID_QUIC_LIST_ENTRY*)
        QUIC_ALLOC_NONPAGED(
            sizeof(QUIC_CID_QUIC_LIST_ENTRY) +
            QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);

    if (Entry != NULL) {
        QuicZeroMemory(&Entry->CID, sizeof(Entry->CID));
        Entry->CID.Length = QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH;
        QuicRandom(QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH, Entry->CID.Data);
    }

    return Entry;
}

//
// Creates a destination connection ID from a pre-existing CID buffer.
//
inline
_Success_(return != NULL)
QUIC_CID_QUIC_LIST_ENTRY*
QuicCidNewDestination(
    _In_ uint8_t Length,
    _In_reads_(Length)
        const uint8_t* const Data
    )
{
    QUIC_CID_QUIC_LIST_ENTRY* Entry =
        (QUIC_CID_QUIC_LIST_ENTRY*)
        QUIC_ALLOC_NONPAGED(
            sizeof(QUIC_CID_QUIC_LIST_ENTRY) +
            Length);

    if (Entry != NULL) {
        QuicZeroMemory(&Entry->CID, sizeof(Entry->CID));
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
