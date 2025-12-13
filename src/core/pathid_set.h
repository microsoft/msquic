/*++
    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
--*/

//
// Different flags of a stream.
// Note - Keep quictypes.h's copy up to date.
//
typedef union QUIC_PATHID_SET_FLAGS {
    uint64_t AllFlags;
    struct {
        BOOLEAN HashTableInitialized    : 1;
        BOOLEAN InitialMaxPathRecvd     : 1;
    };
} QUIC_PATHID_SET_FLAGS;

typedef struct QUIC_PATHID_SET {
    //
    // The largest MAX_PATH_ID value indicated to the peer. This MUST not ever
    // decrease once the connection has started.
    //
    uint32_t MaxPathID;

    //
    // The largest MAX_PATH_ID value indicated by the peer. This MUST not ever
    // decrease once the connection has started.
    //
    uint32_t PeerMaxPathID;

    //
    // The total number of path ids that have been opened. Includes any path ids
    // that have been closed as well.
    //
    uint32_t TotalPathIDCount;

    //
    // The maximum number of simultaneous open path ids allowed.
    //
    uint16_t MaxCurrentPathIDCount;

    //
    // The number of PathIDs. Value of less than 2
    // indicates only a single PathID (may be NULL) is bound.
    uint16_t CurrentPathIDCount;

    //
    // The current flags for path id set.
    //
    QUIC_PATHID_SET_FLAGS Flags;

    //
    // Lock for accessing the lookup data.
    //
    CXPLAT_DISPATCH_RW_LOCK RwLock;

    //
    // PathID lookup.
    //
    union {
        void* LookupTable;
        struct {
            //
            // Single PathID is bound.
            //
            QUIC_PATHID* PathID;
        } SINGLE;
        struct {
            //
            // Hash table.
            //
            CXPLAT_HASHTABLE* Table;
        } HASH;
    };
} QUIC_PATHID_SET;
//
// Initializes the path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

//
// Uninitializes the path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUninitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

BOOLEAN
QuicPathIDSetGetPathIDs(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _Out_writes_(*PathIDCount) QUIC_PATHID** PathIDs,
    _Inout_ uint8_t* PathIDCount
    );

//
// Tracing rundown for the path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetTraceRundown(
    _In_ QUIC_PATHID_SET* PathIDSet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetFree(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetFreeSourceCids(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetProcessLossDetectionTimerOperation(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetProcessPathCloseTimerOperation(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetTryFreePathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetGenerateNewSourceCids(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _In_ BOOLEAN ReplaceExistingCids
    );


_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDSetWriteNewConnectionIDFrame(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Out_ BOOLEAN* HasMoreCidsToSend,
    _Out_ BOOLEAN* MaxFrameLimitHit
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDSetWriteRetireConnectionIDFrame(
    _In_ QUIC_PATHID_SET* PathIDSet,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Out_ BOOLEAN* HasMoreCidsToSend,
    _Out_ BOOLEAN* MaxFrameLimitHit
    );

//
// Processes a received ACK frame. Returns true if the frame could be
// successfully processed. On failure, 'InvalidFrame' indicates if the frame
// was corrupt or not.
//
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
    );

//
// Invoked when the the transport parameters have been received from the peer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitializeTransportParameters(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t SourceCidLimit,
    _In_ uint32_t MaxPathID
    );

//
// Invoked when the peer sends a MAX_PATH_ID frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUpdateMaxPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t MaxPathID
    );

//
// Updates the maximum count of pathids allowed for a pathid set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDmSetUpdateMaxCount(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t Type,
    _In_ uint16_t Count
    );

//
// Returns the number of available path ids still allowed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
uint16_t
QuicPathIDSetGetCountAvailable(
    _In_ const QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t Type
    );

//
// Queries the current max Path IDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetGetMaxPathIDs(
    _In_ const QUIC_PATHID_SET* PathIDSet,
    _Out_writes_all_(NUMBER_OF_PATHID_TYPES)
        uint64_t* MaxPathIds
    );

//
// Creates a new local path id.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPathIDSetNewLocalPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _Outptr_ _At_(*NewPathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** NewPathID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != NULL)
QUIC_PATHID*
QuicPathIDSetGetPathIDForLocal(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t PathId,
    _Out_ BOOLEAN* FatalError
    );

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
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_PATHID*
QuicPathIDSetGetUnusedPathID(
    _In_ QUIC_PATHID_SET* PathIDSet
    );
