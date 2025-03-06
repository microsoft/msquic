/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A stream set manages all stream-related state for a single connection. It
    keeps track of locally and remotely initiated streams, and synchronizes max
    stream IDs with the peer.

Design:

    The stream set store streams in 3 containers: a hash-table `StreamTable`for
    open streams (need frequent lookup by ID), a sorted list `WaitingStreams`
    for streams waiting to be allowed by stream ID flow control (they will be
    inserted in order in `StreamTable` once allowed), and a list `ClosedStreams`
    for closed streams waiting for deletion.
    Each stream must be in one and only one container at a time.

    The `Types` array keeps track of the number of streams opened and allowed
    for each stream types.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "stream_set.c.clog.h"
#endif

#if DEBUG
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamSetValidate(
    _In_ QUIC_STREAM_SET* StreamSet
    )
{
    const QUIC_CONNECTION* Connection = QuicStreamSetGetConnection(StreamSet);

    if (StreamSet->StreamTable != NULL) {
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(StreamSet->StreamTable, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(StreamSet->StreamTable, &Enumerator)) != NULL) {
            const QUIC_STREAM* Stream = CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, TableEntry);
            CXPLAT_DBG_ASSERT(Stream->Type == QUIC_HANDLE_TYPE_STREAM);
            CXPLAT_DBG_ASSERT(Stream->Connection == Connection);
            CXPLAT_DBG_ASSERT(Stream->Flags.InStreamTable);
            UNREFERENCED_PARAMETER(Stream);
        }
        CxPlatHashtableEnumerateEnd(StreamSet->StreamTable, &Enumerator);
    }

    for (CXPLAT_LIST_ENTRY* Link = StreamSet->WaitingStreams.Flink;
         Link != &StreamSet->WaitingStreams;
         Link = Link->Flink) {
        const QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_STREAM, WaitingLink);
        CXPLAT_DBG_ASSERT(Stream->Type == QUIC_HANDLE_TYPE_STREAM);
        CXPLAT_DBG_ASSERT(Stream->Connection == Connection);
        CXPLAT_DBG_ASSERT(Stream->Flags.InWaitingList);
        UNREFERENCED_PARAMETER(Stream);
    }
}
#else
#define QuicStreamSetValidate(StreamSet)
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetInitialize(
    _Inout_ QUIC_STREAM_SET* StreamSet
    )
{
    CxPlatListInitializeHead(&StreamSet->ClosedStreams);
    CxPlatListInitializeHead(&StreamSet->WaitingStreams);
#if DEBUG
    CxPlatListInitializeHead(&StreamSet->AllStreams);
    CxPlatDispatchLockInitialize(&StreamSet->AllStreamsLock);
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetUninitialize(
    _Inout_ QUIC_STREAM_SET* StreamSet
    )
{
    if (StreamSet->StreamTable != NULL) {
        CxPlatHashtableUninitialize(StreamSet->StreamTable);
    }
#if DEBUG
    CxPlatDispatchLockUninitialize(&StreamSet->AllStreamsLock);
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetTraceRundown(
    _In_ QUIC_STREAM_SET* StreamSet
    )
{
    if (StreamSet->StreamTable != NULL) {
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(StreamSet->StreamTable, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(StreamSet->StreamTable, &Enumerator)) != NULL) {
            QuicStreamTraceRundown(
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, TableEntry));
        }
        CxPlatHashtableEnumerateEnd(StreamSet->StreamTable, &Enumerator);
    }

    for (CXPLAT_LIST_ENTRY *Link = StreamSet->WaitingStreams.Flink;
         Link != &StreamSet->WaitingStreams;
         Link = Link->Flink) {
        QuicStreamTraceRundown(
            CXPLAT_CONTAINING_RECORD(Link, QUIC_STREAM, WaitingLink));
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicStreamSetLazyInitStreamTable(
    _Inout_ QUIC_STREAM_SET* StreamSet
    )
{
    if (StreamSet->StreamTable == NULL) {
        //
        // Lazily initialize the hash table.
        //
        if (!CxPlatHashtableInitialize(&StreamSet->StreamTable, CXPLAT_HASH_MIN_SIZE)) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "streamset hash table",
                0);
            return FALSE;
        }
    }
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicStreamSetInsertStream(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ QUIC_STREAM* Stream
    )
{
    if (!QuicStreamSetLazyInitStreamTable(StreamSet)) {
        return FALSE;
    }
    Stream->Flags.InStreamTable = TRUE;
    CxPlatHashtableInsert(
        StreamSet->StreamTable,
        &Stream->TableEntry,
        (uint32_t)Stream->ID,
        NULL);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
QUIC_STREAM*
QuicStreamSetLookupStream(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint64_t ID
    )
{
    if (StreamSet->StreamTable == NULL) {
        return NULL; // No streams have been created yet.
    }

    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry =
        CxPlatHashtableLookup(StreamSet->StreamTable, (uint32_t)ID, &Context);
    while (Entry != NULL) {
        QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, TableEntry);
        if (Stream->ID == ID) {
            return Stream;
        }
        Entry = CxPlatHashtableLookupNext(StreamSet->StreamTable, &Context);
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetShutdown(
    _Inout_ QUIC_STREAM_SET* StreamSet
    )
{
    if (StreamSet->StreamTable != NULL) {
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(StreamSet->StreamTable, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(StreamSet->StreamTable, &Enumerator)) != NULL) {
            QUIC_STREAM* Stream = CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, TableEntry);
            QuicStreamShutdown(
                Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                QUIC_STREAM_SHUTDOWN_SILENT,
                0);
        }
        CxPlatHashtableEnumerateEnd(StreamSet->StreamTable, &Enumerator);
    }

    //
    // Warning: `QuicStreamShutdown` may call back into the stream set and remove the stream
    // from the list. Make sure to get the next link before calling it.
    //
    CXPLAT_LIST_ENTRY* Link = StreamSet->WaitingStreams.Flink;
    while (Link != &StreamSet->WaitingStreams) {
        QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_STREAM, WaitingLink);
        Link = Link->Flink;
        QuicStreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
            QUIC_STREAM_SHUTDOWN_SILENT,
            0);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetReleaseStream(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ QUIC_STREAM* Stream
    )
{
    //
    // Remove the stream from the list of open streams.
    //
    if (Stream->Flags.InStreamTable) {
        CxPlatHashtableRemove(StreamSet->StreamTable, &Stream->TableEntry, NULL);
        Stream->Flags.InStreamTable = FALSE;
    } else if (Stream->Flags.InWaitingList) {
        CxPlatListEntryRemove(&Stream->WaitingLink);
        Stream->Flags.InWaitingList = FALSE;
    } else {
        //
        // Nothing to do, the stream was already released.
        //
        return;
    }

    CxPlatListInsertTail(&StreamSet->ClosedStreams, &Stream->ClosedLink);

    uint8_t Flags = (uint8_t)(Stream->ID & STREAM_ID_MASK);
    QUIC_STREAM_TYPE_INFO* Info = &StreamSet->Types[Flags];

    CXPLAT_DBG_ASSERT(Info->CurrentStreamCount != 0);
    Info->CurrentStreamCount--;

    if ((Flags & STREAM_ID_FLAG_IS_SERVER) == QuicConnIsServer(Stream->Connection)) {
        //
        // Our own stream was cleaned up, no need to update anything more.
        //
        return;
    }

    if (Info->CurrentStreamCount < Info->MaxCurrentStreamCount) {
        //
        // Since a peer's stream was just closed we should allow the peer to
        // create more streams.
        //
        Info->MaxTotalStreamCount++;
        QuicSendSetSendFlag(
            &QuicStreamSetGetConnection(StreamSet)->Send,
            (Flags & STREAM_ID_FLAG_IS_UNI_DIR) ?
                QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI :
                QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetDrainClosedStreams(
    _Inout_ QUIC_STREAM_SET* StreamSet
    )
{
    while (!CxPlatListIsEmpty(&StreamSet->ClosedStreams)) {
        QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&StreamSet->ClosedStreams),
                    QUIC_STREAM,
                    ClosedLink);
        Stream->ClosedLink.Flink = NULL;
        QuicStreamRelease(Stream, QUIC_STREAM_REF_STREAM_SET);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetIndicateStreamsAvailable(
    _Inout_ QUIC_STREAM_SET* StreamSet
    )
{
    QUIC_CONNECTION* Connection = QuicStreamSetGetConnection(StreamSet);
    uint8_t Type =
        QuicConnIsServer(Connection) ?
        STREAM_ID_FLAG_IS_SERVER : STREAM_ID_FLAG_IS_CLIENT;

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE;
    Event.STREAMS_AVAILABLE.BidirectionalCount =
        QuicStreamSetGetCountAvailable(StreamSet, Type | STREAM_ID_FLAG_IS_BI_DIR);
    Event.STREAMS_AVAILABLE.UnidirectionalCount =
        QuicStreamSetGetCountAvailable(StreamSet, Type | STREAM_ID_FLAG_IS_UNI_DIR);

    QuicTraceLogConnVerbose(
        IndicateStreamsAvailable,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE [bi=%hu uni=%hu]",
        Event.STREAMS_AVAILABLE.BidirectionalCount,
        Event.STREAMS_AVAILABLE.UnidirectionalCount);
    (void)QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicatePeerAccepted(
    _In_ QUIC_STREAM* Stream
    )
{
    if (Stream->Flags.IndicatePeerAccepted) {
        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_PEER_ACCEPTED;
        QuicTraceLogStreamVerbose(
            IndicatePeerAccepted,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_ACCEPTED");
        (void)QuicStreamIndicateEvent(Stream, &Event);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetInitializeTransportParameters(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint64_t BidiStreamCount,
    _In_ uint64_t UnidiStreamCount,
    _In_ BOOLEAN FlushIfUnblocked
    )
{
    QUIC_CONNECTION* Connection = QuicStreamSetGetConnection(StreamSet);
    uint8_t Type =
        QuicConnIsServer(Connection) ?
        STREAM_ID_FLAG_IS_SERVER : STREAM_ID_FLAG_IS_CLIENT;

    BOOLEAN UpdateAvailableStreams = FALSE;
    BOOLEAN MightBeUnblocked = FALSE;

    if (BidiStreamCount != 0) {
        StreamSet->Types[Type | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount = BidiStreamCount;
        UpdateAvailableStreams = TRUE;
    }

    if (UnidiStreamCount != 0) {
        StreamSet->Types[Type | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount = UnidiStreamCount;
        UpdateAvailableStreams = TRUE;
    }

    CXPLAT_LIST_ENTRY* Link = StreamSet->WaitingStreams.Flink;
    while (Link != &StreamSet->WaitingStreams) {
        QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_STREAM, WaitingLink);
        Link = Link->Flink;

        const uint64_t StreamType = Stream->ID & STREAM_ID_MASK;
        const uint64_t StreamIndex = (Stream->ID >> 2);
        const QUIC_STREAM_TYPE_INFO* Info = &Stream->Connection->Streams.Types[StreamType];

        CXPLAT_DBG_ASSERT(Stream->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL);

        uint8_t FlowBlockedFlagsToRemove = 0;
        if (StreamIndex < Info->MaxTotalStreamCount) {
            FlowBlockedFlagsToRemove |= QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL;
            CxPlatListEntryRemove(&Stream->WaitingLink);
            Stream->Flags.InWaitingList = FALSE;

            //
            // The stream hash-table should have been initialized
            // already when inserting stream in `WaitingStreams`
            //
            CXPLAT_DBG_ASSERT(StreamSet->StreamTable != NULL);
            CXPLAT_FRE_ASSERTMSG(
                QuicStreamSetInsertStream(StreamSet, Stream),
                "Steam table lazy intialization failed");

            QuicStreamIndicatePeerAccepted(Stream);
        } else {
            QuicSendSetSendFlag(
                &Stream->Connection->Send,
                STREAM_ID_IS_UNI_DIR(Stream->ID) ?
                    QUIC_CONN_SEND_FLAG_UNI_STREAMS_BLOCKED : QUIC_CONN_SEND_FLAG_BIDI_STREAMS_BLOCKED);
        }

        uint64_t NewMaxAllowedSendOffset =
            QuicStreamGetInitialMaxDataFromTP(
                Stream->ID,
                QuicConnIsServer(Connection),
                &Connection->PeerTransportParams);

        if (Stream->MaxAllowedSendOffset < NewMaxAllowedSendOffset) {
            Stream->MaxAllowedSendOffset = NewMaxAllowedSendOffset;
            FlowBlockedFlagsToRemove |= QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL;
            Stream->SendWindow = (uint32_t)CXPLAT_MIN(Stream->MaxAllowedSendOffset, UINT32_MAX);
        }

        if (FlowBlockedFlagsToRemove) {
            QuicStreamRemoveOutFlowBlockedReason(
                Stream, FlowBlockedFlagsToRemove);
            QuicStreamSendDumpState(Stream);
            MightBeUnblocked = TRUE;
        }
    }

    if (UpdateAvailableStreams) {
        QuicStreamSetIndicateStreamsAvailable(StreamSet);
    }

    if (MightBeUnblocked && FlushIfUnblocked) {
        //
        // We opened the window, so start send. Rather than checking
        // the streams to see if one is actually unblocked, we risk starting
        // the send worker with no actual work to do.
        //
        QuicSendQueueFlush(&Connection->Send, REASON_TRANSPORT_PARAMETERS);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetUpdateMaxStreams(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ BOOLEAN BidirectionalStreams,
    _In_ uint64_t MaxStreams
    )
{
    QUIC_CONNECTION* Connection = QuicStreamSetGetConnection(StreamSet);
    uint64_t Mask;
    QUIC_STREAM_TYPE_INFO* Info;

    if (QuicConnIsServer(Connection)) {
        if (BidirectionalStreams) {
            Mask = STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR;
        } else {
            Mask = STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR;
        }
    } else {
        if (BidirectionalStreams) {
            Mask = STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR;
        } else {
            Mask = STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR;
        }
    }

    Info = &StreamSet->Types[Mask];

    if (MaxStreams > Info->MaxTotalStreamCount) {

        QuicTraceLogConnVerbose(
            PeerStreamCountsUpdated,
            Connection,
            "Peer updated max stream count (%hhu, %llu).",
            BidirectionalStreams,
            MaxStreams);

        BOOLEAN FlushSend = FALSE;

        //
        // Unblock streams that now fit in the new peer limits.
        // The list is ordered so we can exit as soon as we reach the limits.
        //
        CXPLAT_LIST_ENTRY *Link = StreamSet->WaitingStreams.Flink;
        while (Link != &StreamSet->WaitingStreams) {
            QUIC_STREAM* Stream =
                CXPLAT_CONTAINING_RECORD(Link, QUIC_STREAM, WaitingLink);
            Link = Link->Flink;

            uint64_t Index = (Stream->ID >> 2);
            if (Index >= MaxStreams) {
                break;
            }

            if ((Stream->ID & STREAM_ID_MASK) != Mask) {
                continue;
            }

            //
            // Any stream in the waiting list was blocked by the previous stream ID flow control.
            //
            CXPLAT_DBG_ASSERT(Index >= Info->MaxTotalStreamCount);
            if (!QuicStreamRemoveOutFlowBlockedReason(
                    Stream, QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL)) {
                CXPLAT_DBG_ASSERTMSG(FALSE, "Stream should be blocked by id flow control");
            }
            CxPlatListEntryRemove(&Stream->WaitingLink);
            Stream->Flags.InWaitingList = FALSE;
            //
            // The stream hash-table should have been initialized
            // already when inserting stream in `WaitingStreams`
            //
            CXPLAT_DBG_ASSERT(StreamSet->StreamTable != NULL);
            CXPLAT_FRE_ASSERTMSG(
                QuicStreamSetInsertStream(StreamSet, Stream),
                "Steam table lazy intialization failed");
            QuicStreamIndicatePeerAccepted(Stream);
            FlushSend = TRUE;
        }

        Info->MaxTotalStreamCount = MaxStreams;

        QuicStreamSetIndicateStreamsAvailable(StreamSet);

        if (FlushSend) {
            //
            // Queue a flush, as we have unblocked a stream.
            //
            QuicSendQueueFlush(&Connection->Send, REASON_STREAM_ID_FLOW_CONTROL);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetUpdateMaxCount(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint8_t Type,
    _In_ uint16_t Count
    )
{
    QUIC_CONNECTION* Connection = QuicStreamSetGetConnection(StreamSet);
    QUIC_STREAM_TYPE_INFO* Info = &StreamSet->Types[Type];

    QuicTraceLogConnInfo(
        MaxStreamCountUpdated,
        Connection,
        "App configured max stream count of %hu (type=%hhu).",
        Count,
        Type);

    if (!Connection->State.Started) {
        Info->MaxTotalStreamCount = Count;

    } else {
        if (Count >= Info->MaxCurrentStreamCount) {
            Info->MaxTotalStreamCount += (Count - Info->MaxCurrentStreamCount);
            QuicSendSetSendFlag(
                &Connection->Send,
                (Type & STREAM_ID_FLAG_IS_UNI_DIR) ?
                    QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI :
                    QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI);
        }
    }

    Info->MaxCurrentStreamCount = Count;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
uint16_t
QuicStreamSetGetCountAvailable(
    _In_ const QUIC_STREAM_SET* StreamSet,
    _In_ uint8_t Type
    )
{
    const QUIC_STREAM_TYPE_INFO* Info = &StreamSet->Types[Type];
    if (Info->TotalStreamCount >= Info->MaxTotalStreamCount) {
        return 0;
    }
    uint64_t Count = Info->MaxTotalStreamCount - Info->TotalStreamCount;
    return (Count > UINT16_MAX) ? UINT16_MAX : (uint16_t)Count;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamSetGetFlowControlSummary(
    _In_ const QUIC_STREAM_SET* StreamSet,
    _Out_ uint64_t* FcAvailable,
    _Out_ uint64_t* SendWindow
    )
{
    *FcAvailable = 0;
    *SendWindow = 0;

    if (StreamSet->StreamTable != NULL) {
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CxPlatHashtableEnumerateBegin(StreamSet->StreamTable, &Enumerator);
        while ((Entry = CxPlatHashtableEnumerateNext(StreamSet->StreamTable, &Enumerator)) != NULL) {
            QUIC_STREAM* Stream = CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, TableEntry);

            if ((UINT64_MAX - *FcAvailable) >= (Stream->MaxAllowedSendOffset - Stream->NextSendOffset)) {
                *FcAvailable += Stream->MaxAllowedSendOffset - Stream->NextSendOffset;
            } else {
                *FcAvailable = UINT64_MAX;
            }

            if ((UINT64_MAX - *SendWindow) >= Stream->SendWindow) {
                *SendWindow += Stream->SendWindow;
            } else {
                *SendWindow = UINT64_MAX;
            }
        }
        CxPlatHashtableEnumerateEnd(StreamSet->StreamTable, &Enumerator);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamSetNewLocalStream(
    _Inout_ QUIC_STREAM_SET* StreamSet,
    _In_ uint8_t Type,
    _In_ BOOLEAN FailOnBlocked,
    _In_ QUIC_STREAM* Stream
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_STREAM_TYPE_INFO* Info = &StreamSet->Types[Type];
    uint64_t NewStreamId = Type + (Info->TotalStreamCount << 2);
    BOOLEAN NewStreamBlocked = Info->TotalStreamCount >= Info->MaxTotalStreamCount;

    if (FailOnBlocked && NewStreamBlocked) {
        if (Stream->Connection->State.PeerTransportParameterValid) {
            QuicSendSetSendFlag(
                &Stream->Connection->Send,
                STREAM_ID_IS_UNI_DIR(Type) ?
                    QUIC_CONN_SEND_FLAG_UNI_STREAMS_BLOCKED : QUIC_CONN_SEND_FLAG_BIDI_STREAMS_BLOCKED);
        }
        Status = QUIC_STATUS_STREAM_LIMIT_REACHED;
        goto Exit;
    }

    Stream->ID = NewStreamId;

    if (!NewStreamBlocked) {
        if (!QuicStreamSetInsertStream(StreamSet, Stream)) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            Stream->ID = UINT64_MAX;
            goto Exit;
        }
    } else {
        //
        // Initialize the stream table now: we will need it soon and don't want to fail
        // when the stream is unblocked and gets inserted in the table.
        //
        if (!QuicStreamSetLazyInitStreamTable(StreamSet)) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            Stream->ID = UINT64_MAX;
            goto Exit;
        }

        //
        // Insert the stream into the list of streams waiting for stream id flow control.
        // Make sure to keep the list ordered by stream ID.
        //
        CXPLAT_LIST_ENTRY* Link = StreamSet->WaitingStreams.Blink;
        while (Link != &StreamSet->WaitingStreams) {
            QUIC_STREAM* StreamIt =
                CXPLAT_CONTAINING_RECORD(Link, QUIC_STREAM, WaitingLink);
            if (StreamIt->ID < NewStreamId) {
                break;
            }
            Link = Link->Blink;
        }
        CxPlatListInsertAfter(Link, &Stream->WaitingLink);
        Stream->Flags.InWaitingList = TRUE;

        //
        // We don't call QuicStreamAddOutFlowBlockedReason here because we haven't
        // logged the stream created event yet at this point. We will log the event
        // after that.
        //
        Stream->OutFlowBlockedReasons |= QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL;
        Stream->BlockedTimings.StreamIdFlowControl.LastStartTimeUs = CxPlatTimeUs64();
        if (Stream->Connection->State.PeerTransportParameterValid) {
            QuicSendSetSendFlag(
                &Stream->Connection->Send,
                STREAM_ID_IS_UNI_DIR(Stream->ID) ?
                    QUIC_CONN_SEND_FLAG_UNI_STREAMS_BLOCKED : QUIC_CONN_SEND_FLAG_BIDI_STREAMS_BLOCKED);
        }
    }

    Info->CurrentStreamCount++;
    Info->TotalStreamCount++;

    QuicStreamAddRef(Stream, QUIC_STREAM_REF_STREAM_SET);

Exit:

    return Status;
}

#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't double ref count semantics
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
    )
{
    QUIC_CONNECTION* Connection = QuicStreamSetGetConnection(StreamSet);

    *FatalError = FALSE;

    //
    // Connection is closed. No more streams are open.
    //
    if (QuicConnIsClosed(Connection)) {
        return NULL;
    }

    uint64_t StreamType = StreamId & STREAM_ID_MASK;
    uint64_t StreamCount = (StreamId >> 2) + 1;
    QUIC_STREAM_TYPE_INFO* Info = &StreamSet->Types[StreamType];

    uint32_t StreamFlags = 0;
    if (STREAM_ID_IS_UNI_DIR(StreamId)) {
        StreamFlags |= QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
    }
    if (FrameIn0Rtt) {
        StreamFlags |= QUIC_STREAM_OPEN_FLAG_0_RTT;
    }

    //
    // Validate the stream ID isn't above the allowed max.
    //
    if (StreamCount > Info->MaxTotalStreamCount) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer used more streams than allowed");
        QuicConnTransportError(Connection, QUIC_ERROR_STREAM_LIMIT_ERROR);
        *FatalError = TRUE;
        return NULL;
    }

    QUIC_STREAM* Stream = NULL;

    //
    // Debug Validation.
    //
    QuicStreamSetValidate(StreamSet);

    //
    // If the stream ID is in the acceptable range of already opened streams,
    // look for it; but note it could be missing because it has been closed.
    //
    if (StreamCount <= Info->TotalStreamCount) {

        //
        // Find the stream for the ID.
        //
        Stream = QuicStreamSetLookupStream(StreamSet, StreamId);

    } else if (CreateIfMissing) {

        do {

            //
            // Calculate the next Stream ID.
            //
            uint64_t NewStreamId = StreamType + (Info->TotalStreamCount << 2);
            QUIC_STREAM_OPEN_FLAGS OpenFlags = QUIC_STREAM_OPEN_FLAG_NONE;
            if (STREAM_ID_IS_UNI_DIR(StreamId)) {
                OpenFlags |= QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
            }
            if (FrameIn0Rtt) {
                OpenFlags |= QUIC_STREAM_OPEN_FLAG_0_RTT;
            }

            QUIC_STATUS Status =
                QuicStreamInitialize(Connection, TRUE, OpenFlags, &Stream);
            if (QUIC_FAILED(Status)) {
                *FatalError = TRUE;
                QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
                goto Exit;
            }

            Stream->ID = NewStreamId;
            Status = QuicStreamStart(Stream, QUIC_STREAM_START_FLAG_NONE, TRUE);
            if (QUIC_FAILED(Status)) {
                *FatalError = TRUE;
                QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
                QuicStreamRelease(Stream, QUIC_STREAM_REF_APP);
                Stream = NULL;
                break;
            }

            if (!QuicStreamSetInsertStream(StreamSet, Stream)) {
                *FatalError = TRUE;
                QuicConnTransportError(Connection, QUIC_ERROR_INTERNAL_ERROR);
                QuicStreamRelease(Stream, QUIC_STREAM_REF_APP);
                Stream = NULL;
                break;
            }
            Info->CurrentStreamCount++;
            Info->TotalStreamCount++;

            QuicStreamAddRef(Stream, QUIC_STREAM_REF_STREAM_SET);

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
            Event.PEER_STREAM_STARTED.Stream = (HQUIC)Stream;
            Event.PEER_STREAM_STARTED.Flags = StreamFlags;

            QuicTraceLogConnVerbose(
                IndicatePeerStreamStarted,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED [%p, 0x%x]",
                Event.PEER_STREAM_STARTED.Stream,
                Event.PEER_STREAM_STARTED.Flags);

            Stream->Flags.PeerStreamStartEventActive = TRUE;
            Status = QuicConnIndicateEvent(Connection, &Event);
            Stream->Flags.PeerStreamStartEventActive = FALSE;

            if (QUIC_FAILED(Status)) {
                QuicTraceLogStreamWarning(
                    NotAccepted,
                    Stream,
                    "New stream wasn't accepted, 0x%x",
                    Status);
                QuicStreamClose(Stream);
                Stream = NULL;
            } else if (Stream->Flags.HandleClosed) {
                Stream = NULL; // App accepted but immediately closed the stream.
            } else {
                CXPLAT_FRE_ASSERTMSG(
                    Stream->ClientCallbackHandler != NULL,
                    "App MUST set callback handler!");
                if (Event.PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES) {
                    Stream->Flags.DelayIdFcUpdate = TRUE;
                    QuicTraceLogStreamVerbose(
                        ConfiguredForDelayedIDFC,
                        Stream,
                        "Configured for delayed ID FC updates");
                }
            }

        } while (Info->TotalStreamCount != StreamCount);

    } else {

        //
        // Remote tried to open stream that it wasn't allowed to.
        //
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Remote tried to open stream it wasn't allowed to open.");
        QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
        *FatalError = TRUE;
    }

Exit:

    if (Stream != NULL) {
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_LOOKUP);
    }

    return Stream;
}
#pragma warning(pop)

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSetGetMaxStreamIDs(
    _In_ const QUIC_STREAM_SET* StreamSet,
    _Out_writes_all_(NUMBER_OF_STREAM_TYPES)
        uint64_t* MaxStreamIds
    )
{
    for (uint64_t i = 0; i < NUMBER_OF_STREAM_TYPES; ++i) {
        MaxStreamIds[i] = (StreamSet->Types[i].MaxTotalStreamCount << 2) | i;
    }
}
