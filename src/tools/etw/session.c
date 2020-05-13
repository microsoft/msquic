/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

OBJECT_SET Sessions = {0};

SESSION*
NewSession(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_SESSION* EvData = (QUIC_EVENT_DATA_SESSION*)ev->UserData;

    // Move the old session out of the set if this pointer is being reused.
    (void)ObjectSetRemoveActive(&Sessions, EvData->SessionPtr);

    SESSION* Session = malloc(sizeof(SESSION));
    if (Session == NULL) {
        printf("out of memory\n");
        exit(1);
    }
    memset(Session, 0, sizeof(*Session));
    Session->Id = Sessions.NextId++;
    Session->Ptr = EvData->SessionPtr;
    Session->InitialTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    ObjectSetAddActive(&Sessions, (OBJECT*)Session);
    return Session;
}

SESSION* GetSessionFromEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_SESSION* EvData = (QUIC_EVENT_DATA_SESSION*)ev->UserData;

    SESSION* Session;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicSessionCreated) {
        Session = NewSession(ev);
    } else if (GetEventId(ev->EventHeader.EventDescriptor.Id)== EventId_QuicSessionDestroyed) {
        Session = (SESSION*)ObjectSetRemoveActive(&Sessions, EvData->SessionPtr);
    } else {
        if ((Session = (SESSION*)ObjectSetGetActive(&Sessions, EvData->SessionPtr)) == NULL) {
            Session = NewSession(ev);
        }
    }

    if (Session != NULL) {
        Session->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    }

    return Session;
}

void
SessionEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    SESSION* Session = GetSessionFromEvent(ev);
    *ObjectId = Session->Id;
    UNREFERENCED_PARAMETER(TraceEvent);
    UNREFERENCED_PARAMETER(InitialTimestamp);
}
