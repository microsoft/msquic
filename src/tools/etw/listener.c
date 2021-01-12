/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

OBJECT_SET Listeners = {0};

LISTENER*
NewListener(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_LISTENER* EvData = (QUIC_EVENT_DATA_LISTENER*)ev->UserData;

    // Move the old listener out of the set if this pointer is being reused.
    (void)ObjectSetRemoveActive(&Listeners, EvData->ListenerPtr);

    LISTENER* Listener = malloc(sizeof(LISTENER));
    if (Listener == NULL) {
        printf("out of memory\n");
        exit(1);
    }
    memset(Listener, 0, sizeof(*Listener));
    Listener->Id = Listeners.NextId++;
    Listener->Ptr = EvData->ListenerPtr;
    Listener->InitialTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    ObjectSetAddActive(&Listeners, (OBJECT*)Listener);
    return Listener;
}

LISTENER* GetListenerFromEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_LISTENER* EvData = (QUIC_EVENT_DATA_LISTENER*)ev->UserData;

    LISTENER* Listener;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicListenerCreated ||
        GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicListenerRundown) {
        Listener = NewListener(ev);
    } else if (GetEventId(ev->EventHeader.EventDescriptor.Id)== EventId_QuicListenerDestroyed) {
        Listener = (LISTENER*)ObjectSetRemoveActive(&Listeners, EvData->ListenerPtr);
    } else {
        if ((Listener = (LISTENER*)ObjectSetGetActive(&Listeners, EvData->ListenerPtr)) == NULL) {
            Listener = NewListener(ev);
        }
    }

    if (Listener != NULL) {
        Listener->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    }

    return Listener;
}

void
ListenerEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    LISTENER* Listener = GetListenerFromEvent(ev);
    *ObjectId = Listener->Id;

    UNREFERENCED_PARAMETER(TraceEvent);
    UNREFERENCED_PARAMETER(InitialTimestamp);
}
