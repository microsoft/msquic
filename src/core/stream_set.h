/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Info for a particular type of stream (client/server;bidir/unidir)
//
typedef struct QUIC_STREAM_TYPE_INFO {

    //
    // The largest MAX_STREAMS value indicated to the peer. This MUST not ever
    // decrease once the connection has started.
    //
    uint64_t MaxTotalStreamCount;

    //
    // The total number of streams that have been opened. Includes any streams
    // that have been closed as well.
    //
    uint64_t TotalStreamCount;

    //
    // The maximum number of simultaneous open streams allowed.
    //
    uint16_t MaxCurrentStreamCount;

    //
    // The current count of currently open streams.
    //
    uint16_t CurrentStreamCount;

} QUIC_STREAM_TYPE_INFO;

typedef struct QUIC_STREAM_SET {

    //
    // The per-type Stream information.
    //
    QUIC_STREAM_TYPE_INFO Types[NUMBER_OF_STREAM_TYPES];

    //
    // The hash table of all active streams.
    //
    CXPLAT_HASHTABLE* StreamTable;

    //
    // The list of streams that are completely closed and need to be released.
    //
    CXPLAT_LIST_ENTRY ClosedStreams;

#if DEBUG
    //
    // The list of allocated streams for leak tracking.
    //
    CXPLAT_LIST_ENTRY AllStreams;
    CXPLAT_DISPATCH_LOCK AllStreamsLock;
#endif

} QUIC_STREAM_SET;

//
// Initializes the stream set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetInitialize(
    _Inout_ QUIC_STREAM_SET* StreamSet
    );

//
// Uninitializes the stream set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetUninitialize(
    _Inout_ QUIC_STREAM_SET* StreamSet
    );

//
// Tracing rundown for the stream set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetTraceRundown(
    _In_ QUIC_STREAM_SET* StreamSet
    );

//
// Shuts down (silent, abortive) all streams.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetShutdown(
    _Inout_ QUIC_STREAM_SET* StreamSet
    );

//
// Called to inform the stream set that the stream is ready to be cleaned up.
// The stream set queued the stream for later deletion.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetReleaseStream(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ QUIC_STREAM* Stream
    );

//
// Final clean up for all closed streams
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetDrainClosedStreams(
    _Inout_ QUIC_STREAM_SET* StreamSet
    );

//
// Invoked when the the transport parameters have been received from the peer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetInitializeTransportParameters(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint64_t BidiStreamCount,
    _In_ uint64_t UnidiStreamCount,
    _In_ BOOLEAN FlushIfUnblocked
    );

//
// Invoked when the peer sends a MAX_STREAMS frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetUpdateMaxStreams(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ BOOLEAN BidirectionalStreams,
    _In_ uint64_t MaxStreams
    );

//
// Updates the maximum count of streams allowed for a stream set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetUpdateMaxCount(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint8_t Type,
    _In_ uint16_t Count
    );

//
// Returns the number of available streams still allowed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
uint16_t
QuicStreamSetGetCountAvailable(
    _In_ const QUIC_STREAM_SET* StreamSet,
    _In_ uint8_t Type
    );

//
// Returns available flow control and send window, as a sum of all streams.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamSetGetFlowControlSummary(
    _In_ const QUIC_STREAM_SET* StreamSet,
    _Out_ uint64_t* FcAvailable,
    _Out_ uint64_t* SendWindow
    );

//
// Creates a new local stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamSetNewLocalStream(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint8_t Type,
    _In_ BOOLEAN FailOnBlocked,
    _In_ QUIC_STREAM* Stream
    );

//
// Does a look up for a peer's stream object, by the stream ID. It may create
// new streams up to StreamId if the CreateIfMissing flag is set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
QUIC_STREAM*
QuicStreamSetGetStreamForPeer(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint64_t StreamId,
    _In_ BOOLEAN FrameIn0Rtt,
    _In_ BOOLEAN CreateIfMissing,
    _Out_ BOOLEAN* FatalError
    );

//
// Queries the current max stream IDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetGetMaxStreamIDs(
    _In_ const QUIC_STREAM_SET* StreamSet,
    _Out_writes_all_(NUMBER_OF_STREAM_TYPES)
        uint64_t* MaxStreamIds
    );
