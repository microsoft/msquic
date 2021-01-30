/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

OBJECT_SET Bindings = {0};

BINDING*
NewBinding(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_BINDING* EvData = (QUIC_EVENT_DATA_BINDING*)ev->UserData;

    // Move the old binding out of the set if this pointer is being reused.
    (void)ObjectSetRemoveActive(&Bindings, EvData->BindingPtr);

    BINDING* Binding = malloc(sizeof(BINDING));
    if (Binding == NULL) {
        printf("out of memory\n");
        exit(1);
    }
    memset(Binding, 0, sizeof(*Binding));
    Binding->Id = Bindings.NextId++;
    Binding->Ptr = EvData->BindingPtr;
    Binding->InitialTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    ObjectSetAddActive(&Bindings, (OBJECT*)Binding);
    return Binding;
}

BINDING* GetBindingFromEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_BINDING* EvData = (QUIC_EVENT_DATA_BINDING*)ev->UserData;

    BINDING* Binding;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicBindingCreated ||
        GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicBindingRundown) {
        Binding = NewBinding(ev);
    } else if (GetEventId(ev->EventHeader.EventDescriptor.Id)== EventId_QuicBindingDestroyed) {
        Binding = (BINDING*)ObjectSetRemoveActive(&Bindings, EvData->BindingPtr);
    } else {
        if ((Binding = (BINDING*)ObjectSetGetActive(&Bindings, EvData->BindingPtr)) == NULL) {
            Binding = NewBinding(ev);
        }
    }

    if (Binding != NULL) {
        Binding->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    }

    return Binding;
}

void
BindingEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    BINDING* Binding = GetBindingFromEvent(ev);
    *ObjectId = Binding->Id;

    UNREFERENCED_PARAMETER(TraceEvent);
    UNREFERENCED_PARAMETER(InitialTimestamp);
}
