/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

OBJECT_SET Streams = {0};

STREAM*
NewStream(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_STREAM* EvData = (QUIC_EVENT_DATA_STREAM*)ev->UserData;

    // Move the old stream out of the set if this pointer is being reused.
    (void)ObjectSetRemoveActive(&Streams, EvData->StreamPtr);

    STREAM* Stream = malloc(sizeof(STREAM));
    if (Stream == NULL) {
        printf("out of memory\n");
        exit(1);
    }
    memset(Stream, 0, sizeof(*Stream));
    Stream->Id = Streams.NextId++;
    Stream->Ptr = EvData->StreamPtr;
    Stream->InitialTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicStreamCreated ||
        GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicStreamRundown) {
        Stream->StreamId = EvData->Created.ID;
        Stream->CxnPtr = EvData->Created.ConnectionPtr;
        Stream->Cxn = (CXN*)ObjectSetGetActive(&Cxns, Stream->CxnPtr);
        if (Stream->Cxn != NULL) {
            Stream->Cxn->StreamCount++;
            Stream->Next = Stream->Cxn->Streams;
            Stream->Cxn->Streams = Stream;
        }
    } else {
        Stream->StreamId = ULLONG_MAX;
    }
    ObjectSetAddActive(&Streams, (OBJECT*)Stream);
    return Stream;
}

STREAM* GetStreamFromEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_STREAM* EvData = (QUIC_EVENT_DATA_STREAM*)ev->UserData;

    STREAM* Stream;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicStreamCreated ||
        GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicStreamRundown) {
        Stream = NewStream(ev);
    } else if (GetEventId(ev->EventHeader.EventDescriptor.Id)== EventId_QuicStreamDestroyed) {
        Stream = (STREAM*)ObjectSetRemoveActive(&Streams, EvData->StreamPtr);
    } else {
        Stream = (STREAM*)ObjectSetGetActive(&Streams, EvData->StreamPtr);
    }

    if (Stream == NULL) {
        Stream = NewStream(ev);
    }

    Stream->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;

    return Stream;
}

void
StreamEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    STREAM* Stream = GetStreamFromEvent(ev);
    *ObjectId = Stream->Id;

    if (Cmd.Command == COMMAND_STREAM_TRACE && Stream->Id == Cmd.SelectedId) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Stream->InitialTimestamp;
    } else if(Cmd.Command == COMMAND_CONN_TRACE && Stream->Cxn != NULL &&
            Stream->Cxn->Id == Cmd.SelectedId) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Stream->Cxn->InitialTimestamp;
    } else if(Cmd.Command == COMMAND_WORKER_TRACE && Stream->Cxn != NULL &&
            Stream->Cxn->Worker != NULL && Stream->Cxn->Worker->Id == Cmd.SelectedId) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Stream->Cxn->Worker->InitialTimestamp;
    }
}
