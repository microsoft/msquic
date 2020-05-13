/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "MsQuicEventCollection.h"
#include "QuicEvents.h"
#include "ObjectSet.h"

class QuicEventCollection;

const uint8_t PointerSizeBytes[] = {
    4,  // FourBytePointer
    8   // EightBytePointer
};

uint64_t ReadPointer(uint32_t PointerSize, const void* Buffer) {
    if (PointerSize == FourBytePointer) {
        return *(uint32_t*)Buffer;
    } else {
        return *(uint64_t*)Buffer;
    }
}

uint64_t ReadPointer(const QuicEvent* Event) {
    return ReadPointer(Event->PointerSize, Event->Payload);
}

const QuicGlobalEventPayload* GetGlobalPayload(const QuicEvent* Event) {
    return (const QuicGlobalEventPayload*)Event->Payload;
}

const QuicWorkerEventPayload* GetWorkerPayload(const QuicEvent* Event) {
    return (const QuicWorkerEventPayload*)(Event->Payload + PointerSizeBytes[Event->PointerSize]);
}

const QuicConnEventPayload* GetConnPayload(const QuicEvent* Event) {
    return (const QuicConnEventPayload*)(Event->Payload + PointerSizeBytes[Event->PointerSize]);
}

const QuicStreamEventPayload* GetStreamPayload(const QuicEvent* Event) {
    return (const QuicStreamEventPayload*)(Event->Payload + PointerSizeBytes[Event->PointerSize]);
}

class QuicWorker : public QuicWorkerData {
public:

    std::vector<const QuicEvent*> Events;

    static const uint16_t CreatedEventId = EventId_QuicWorkerCreated;
    static const uint16_t DestroyedEventId = EventId_QuicWorkerDestroyed;

    QuicWorker(uint64_t _Ptr, uint32_t _ProcessId) {
        static uint32_t NextId = 1;
        Id = NextId++;

        Ptr = _Ptr;
        ProcessId = _ProcessId;
        ThreadId = UINT32_UNKNOWN;
        IdealProcessor = UINT8_UNKNOWN;
        ProcessorBitmap = 0;

        InitialTimeStamp = UINT64_UNKNOWN;
        FinalTimeStamp = UINT64_UNKNOWN;
        LastActiveTimeStamp = UINT64_UNKNOWN;
        TotalActiveTime = 0;

        TotalConnections = 0;
        CurrentConnections = 0;
    }

    void AddEvent(const QuicEvent* Event, QuicEventCollection* EventCollection);

    void OnConnectionAdded(const QuicConnectionData* /* Connection */) {
        TotalConnections++;
        CurrentConnections++;
    }

    void OnConnectionRemoved(const QuicConnectionData* /* Connection */) {
        CurrentConnections--;
    }

    void OnConnectionEvent(const QuicConnectionData* Connection, const QuicEvent* Event);

    void GetActivityEvents(std::vector<QuicActivityData> &ActivityEvents) const {
        const QuicEvent* LastEvent = nullptr;
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            const auto Event = *it;
            if (Event->Id != EventId_QuicWorkerActivityStateUpdated) {
                continue;
            }
            auto Payload = GetWorkerPayload(Event);
            if (!Payload->ActivityStateUpdated.IsActive) {
                if (LastEvent != nullptr) {
                    ActivityEvents.push_back({
                        LastEvent->TimeStamp,
                        Event->TimeStamp - LastEvent->TimeStamp});
                    LastEvent = nullptr;
                }
            } else if (LastEvent == nullptr) {
                LastEvent = Event;
            }
        }
    }
};

class QuicConnection : public QuicConnectionData {
public:

    std::vector<const QuicEvent*> Events;

    static const uint16_t CreatedEventId = EventId_QuicConnCreated;
    static const uint16_t DestroyedEventId = EventId_QuicConnDestroyed;

    QuicWorker* GetWorker() const { return (QuicWorker*)Worker; }

    QuicConnection(uint64_t _Ptr, uint32_t _ProcessId) {
        static uint32_t NextId = 1;
        Id = NextId++;

        Ptr = _Ptr;
        ProcessId = _ProcessId;
        CorrelationId = UINT64_UNKNOWN;
        ProcessorBitmap = 0;
        State = ConnStateUnknown;
        IsServer = TriUnknown;
        IsHandshakeComplete = TriUnknown;
        IsAppShutdown = TriUnknown;
        IsShutdownRemote = TriUnknown;

        InitialTimeStamp = UINT64_UNKNOWN;
        FinalTimeStamp = UINT64_UNKNOWN;
        ShutdownTimeStamp = UINT64_UNKNOWN;

        BytesSent = 0;
        BytesReceived = 0;

        Worker = nullptr;
    }

    void AddEvent(const QuicEvent* Event, QuicEventCollection* EventCollection);

    void GetScheduleEvents(std::vector<QuicScheduleData> &ScheduleEvents) const {
        const QuicEvent* LastEvent = nullptr;
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            const auto Event = *it;
            if (Event->Id != EventId_QuicConnScheduleState) {
                continue;
            }
            if (LastEvent != nullptr) {
                ScheduleEvents.push_back({
                    LastEvent->TimeStamp,
                    LastEvent->ThreadId,
                    Event->TimeStamp - LastEvent->TimeStamp,
                    (QuicScheduleState)GetConnPayload(LastEvent)->ScheduleState.State});
            }
            LastEvent = Event;
        }
    }

    void GetFlowBlockedEvents(std::vector<QuicFlowBlockedData> &FlowBlockedEvents) const {
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            const auto Event = *it;
            if (Event->Id != EventId_QuicConnOutFlowBlocked) {
                continue;
            }
            FlowBlockedEvents.push_back({
                Event->TimeStamp,
                (QuicFlowBlockedFlags)GetConnPayload(Event)->OutFlowBlocked.ReasonFlags});
        }
    }

    void GetMergedFlowBlockedEvents(std::vector<QuicFlowBlockedData> &FlowBlockedEvents) const {
        GetFlowBlockedEvents(FlowBlockedEvents); // TODO - Merge with streams' flow blocked events.
    }

    void GetExecEvents(std::vector<QuicExecutionData> &ExecEvents) const {
        const QuicEvent* LastEvent = nullptr;
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            const auto Event = *it;
            if (LastEvent != nullptr &&
                (Event->Id == EventId_QuicConnScheduleState ||
                 Event->Id == EventId_QuicConnExecOper ||
                 Event->Id == EventId_QuicConnExecApiOper/* ||
                 Event->Id == EventId_QuicConnExecTimerOper*/)) {
                QuicExecutionType Type;
                switch (LastEvent->Id) {
                case EventId_QuicConnExecOper:
                    Type = (QuicExecutionType)(ConnExecOperApi + GetConnPayload(LastEvent)->ExecOper.Type);
                    break;
                case EventId_QuicConnExecApiOper:
                    Type = (QuicExecutionType)(ConnExecApiConnClose + GetConnPayload(LastEvent)->ExecApiOper.Type);
                    break;
                case EventId_QuicConnExecTimerOper:
                    Type = (QuicExecutionType)(ConnExecTimerPacing + GetConnPayload(LastEvent)->ExecTimerOper.Type);
                    break;
                default:
                    Type = ConnExecUnknown;
                    break;
                }
                ExecEvents.push_back({
                    LastEvent->TimeStamp,
                    LastEvent->ThreadId,
                    (uint8_t)LastEvent->Processor,
                    Event->TimeStamp - LastEvent->TimeStamp,
                    Type});
            }
            if (Event->Id == EventId_QuicConnScheduleState) {
                LastEvent = nullptr;
            } else if (Event->Id == EventId_QuicConnExecOper ||
                Event->Id == EventId_QuicConnExecApiOper/* ||
                Event->Id == EventId_QuicConnExecTimerOper*/) {
                LastEvent = Event;
            }
        }
    }

    void GetTputEvents(uint32_t ResolutionNs, std::vector<QuicThroughputData> &TputEvents) const {
        bool InitialTxRateSampled = false, InitialRxRateSampled = false;
        QuicThroughputData Sample = {0};
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            const auto Event = *it;
            auto Payload = GetConnPayload(Event);

            if (it == Events.begin()) {
                Sample.TimeStamp = Event->TimeStamp;
            }

            if (Event->Id == EventId_QuicConnOutFlowStats) {
                Sample.RttUs = Payload->OutFlowStats.SmoothedRtt;
                Sample.BytesSent = Payload->OutFlowStats.BytesSent;
                Sample.BytesInFlight = Payload->OutFlowStats.BytesInFlight;
                Sample.CongestionWindow = Payload->OutFlowStats.CongestionWindow;
                Sample.BytesBufferedForSend = Payload->OutFlowStats.PostedBytes;
                Sample.FlowControlAvailable = Payload->OutFlowStats.ConnectionFlowControl;
                if (!InitialTxRateSampled) {
                    InitialTxRateSampled = true;
                    Sample.TxRate = Sample.BytesSent;
                }
            } else if (Event->Id == EventId_QuicConnInFlowStats) {
                Sample.BytesReceived = Payload->InFlowStats.BytesRecv;
                if (!InitialRxRateSampled) {
                    InitialRxRateSampled = true;
                    Sample.RxRate = Sample.BytesReceived;
                }
            } else if (Event->Id == EventId_QuicConnCongestion) {
                Sample.CongestionEvents++;
            } else if (Event->Id == EventId_QuicConnStats && Sample.TimeStamp == 0) {
                Sample.RttUs = Payload->Stats.SmoothedRtt;
                Sample.BytesSent = Payload->Stats.SendTotalBytes;
                Sample.BytesReceived = Payload->Stats.RecvTotalBytes;
                Sample.CongestionEvents = Payload->Stats.CongestionCount;
            } else if (Event->Id == EventId_QuicConnOutFlowStreamStats) {
                Sample.StreamFlowControlAvailable = Payload->OutFlowStreamStats.StreamFlowControl;
            } else {
                continue;
            }

            if ((Sample.TimeStamp + (uint64_t)ResolutionNs) <= Event->TimeStamp ||
                (it + 1) == Events.end()) {

                Sample.Duration = Event->TimeStamp - Sample.TimeStamp;
                Sample.TxRate = ((Sample.BytesSent - Sample.TxRate) * 8 * 1000 * 1000 * 1000) / Sample.Duration;
                Sample.RxRate = ((Sample.BytesReceived - Sample.RxRate) * 8 * 1000 * 1000 * 1000) / Sample.Duration;

                TputEvents.push_back(Sample);

                Sample.TimeStamp = Event->TimeStamp;
                Sample.TxRate = Sample.BytesSent;
                Sample.RxRate = Sample.BytesReceived;
                Sample.CongestionEvents = 0;
            }
        }
    }
};

class QuicStream : public QuicStreamData {
public:

    std::vector<const QuicEvent*> Events;

    static const uint16_t CreatedEventId = EventId_QuicStreamCreated;
    static const uint16_t DestroyedEventId = EventId_QuicStreamDestroyed;

    QuicStream(uint64_t _Ptr, uint32_t _ProcessId) {
        static uint32_t NextId = 1;
        Id = NextId++;

        Ptr = _Ptr;
        ProcessId = _ProcessId;
        StreamId = UINT64_UNKNOWN;

        InitialTimeStamp = UINT64_UNKNOWN;
        FinalTimeStamp = UINT64_UNKNOWN;
    }

    void AddEvent(const QuicEvent* Event, QuicEventCollection* EventCollection);

    void GetFlowBlockedEvents(std::vector<QuicFlowBlockedData> &FlowBlockedEvents) const {
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            const auto Event = *it;
            if (Event->Id != EventId_QuicStreamOutFlowBlocked) {
                continue;
            }
            FlowBlockedEvents.push_back({
                Event->TimeStamp,
                (QuicFlowBlockedFlags)GetStreamPayload(Event)->OutFlowBlocked.ReasonFlags});
        }
    }
};

class QuicEventCollection : public IQuicEventCollection {
public:

    bool Finalized = true;
    QuicDataAvailableFlags DataAvailableFlags = QuicDataAvailableNone;
    std::vector<const QuicEvent*> Events;
    ObjectSet<QuicWorker> WorkerSet;
    ObjectSet<QuicConnection> ConnectionSet;
    ObjectSet<QuicStream> StreamSet;

    ~QuicEventCollection() {
        for (auto it = Events.begin(); it != Events.end(); ++it) {
            free((void*)*it);
        }
    }

    void ProcessEvent(const QuicEvent* Event) {
        switch (Event->Type) {
        case EventType_Global:
            if (Event->Id >= EventId_QuicApiEnter &&
                Event->Id <= EventId_QuicApiExitStatus) {
                DataAvailableFlags |= QuicDataAvailableApi;
            }
            break;
        case EventType_Worker: {
            DataAvailableFlags |= QuicDataAvailableWorker;
            ObjectKey Key(PointerSizeBytes[Event->PointerSize], ReadPointer(Event), Event->ProcessId);
            auto Obj = WorkerSet.FindOrCreateActive(Event->Id, Key);
            Obj->AddEvent(Event, this);
            break;
        }
        case EventType_Connection: {
            DataAvailableFlags |= QuicDataAvailableConnection;
            ObjectKey Key(PointerSizeBytes[Event->PointerSize], ReadPointer(Event), Event->ProcessId);
            auto Obj = ConnectionSet.FindOrCreateActive(Event->Id, Key);
            Obj->AddEvent(Event, this);
            break;
        }
        case EventType_Stream: {
            DataAvailableFlags |= QuicDataAvailableStream;
            ObjectKey Key(PointerSizeBytes[Event->PointerSize], ReadPointer(Event), Event->ProcessId);
            auto Obj = StreamSet.FindOrCreateActive(Event->Id, Key);
            Obj->AddEvent(Event, this);
            break;
        }
        default:
            break;
        }
        Events.push_back(Event);
        Finalized = false;
    }

    void Finalize() {
        if (!Finalized) {
            Finalized = true;
            WorkerSet.Finalize();
            ConnectionSet.Finalize();
        }
    }

    void Finalize() const {
        //
        // Even when called on a const 'this' we support finalizing internal
        // state.
        //
        ((QuicEventCollection*)this)->Finalize();
    }

    QuicDataAvailableFlags IsDataAvailable() const {
        return DataAvailableFlags;
    }

    //
    // Searches through the current set of workers by thread ID.
    //
    QuicWorker* GetWorkerFromThread(uint32_t ThreadId) {
        for (auto it = WorkerSet.ActiveTable.begin(); it != WorkerSet.ActiveTable.end(); ++it) {
            if (it->second->ThreadId == ThreadId) {
                return it->second;
            }
        }
        for (auto it = WorkerSet.InactiveList.begin(); it != WorkerSet.InactiveList.end(); ++it) {
            if ((*it)->ThreadId == ThreadId) {
                return *it;
            }
        }
        return nullptr;
    }

    void GetWorkers(
        uint64_t BeginTimeStamp,
        uint64_t EndTimeStamp,
        std::vector<const QuicWorkerData*> &Workers
        ) const {
        Finalize();
        WorkerSet.GetObjects(BeginTimeStamp, EndTimeStamp, Workers);
    }

    void GetConnections(
        uint64_t BeginTimeStamp,
        uint64_t EndTimeStamp,
        std::vector<const QuicConnectionData*> &Connections
        ) const {
        Finalize();
        ConnectionSet.GetObjects(BeginTimeStamp, EndTimeStamp, Connections);
    }

    void GetApiCalls(
        uint64_t /* BeginTimeStamp */,
        uint64_t /* EndTimeStamp */,
        std::vector<QuicApiData> &Apis
        ) const {
        Finalize();

        //
        // The following is a hash table of {process|thread} and vector of start
        // events for API calls. Because API calls can result in inline
        // callbacks to the app, which can then call another API, we need to
        // maintain a stack of the current API calls, per thread (per process),
        // in order to know which "api start" event matches an "api end" event.
        //
        class PerThreadEventQueue : public std::unordered_map<uint64_t,std::vector<const QuicEvent*>> {
            std::vector<const QuicEvent*>& GetEventQueue(uint32_t ProcessId, uint32_t ThreadId) {
                uint64_t HashId = (((uint64_t)ProcessId) << 32) | ((uint64_t)ThreadId);
                auto pair = emplace(HashId, std::vector<const QuicEvent*>());
                return pair.first->second;
            }
        public:
            void Push(const QuicEvent* Event) {
                GetEventQueue(Event->ProcessId, Event->ThreadId).push_back(Event);
            }
            const QuicEvent* Pop(uint32_t ProcessId, uint32_t ThreadId) {
                auto& Queue = GetEventQueue(ProcessId, ThreadId);
                if (Queue.empty()) {
                    return nullptr;
                }
                auto Event = Queue.back();
                Queue.pop_back();
                return Event;
            }
        } ApiStartEvents;

        for (auto it = Events.begin(); it != Events.end(); ++it) {
            auto Event = *it;
            if (Event->Type != EventType_Global) {
                continue;
            }
            if (Event->Id == EventId_QuicApiEnter) {
                ApiStartEvents.Push(Event);
            } else if (Event->Id == EventId_QuicApiExit ||
                Event->Id == EventId_QuicApiExitStatus) {
                const QuicEvent* StartEvent = ApiStartEvents.Pop(Event->ProcessId, Event->ThreadId);
                if (StartEvent) {
                    auto StartPayload = GetGlobalPayload(StartEvent);
                    auto EndPayload = GetGlobalPayload(Event);
                    // TODO - Only push back if in time range.
                    Apis.push_back({
                        (QuicApiType)StartPayload->ApiEnter.Type,
                        (uint8_t)StartEvent->Processor, // What if end is different?
                        StartEvent->ProcessId,
                        StartEvent->ThreadId,
                        StartEvent->TimeStamp,
                        Event->TimeStamp - StartEvent->TimeStamp,
                        ReadPointer(StartEvent->PointerSize, StartPayload->ApiEnter.Handle),
                        (Event->Id == EventId_QuicApiExitStatus) ? EndPayload->ApiExitStatus.Status : 0,
                    });
                }
            }
        }
    }
};

IQuicEventCollection* NewQuicEventCollection() {
    return new QuicEventCollection;
}

void QuicWorker::AddEvent(const QuicEvent* Event, QuicEventCollection* EventCollection) {
    auto Payload = GetWorkerPayload(Event);

    if (InitialTimeStamp == UINT64_UNKNOWN) {
        InitialTimeStamp = Event->TimeStamp;
    }

    switch (Event->Id) {
    case EventId_QuicWorkerCreated:
        IdealProcessor = Payload->Created.IdealProcessor;
        break;
    case EventId_QuicWorkerActivityStateUpdated:
        EventCollection->DataAvailableFlags |= QuicDataAvailableWorkerActivity;
        if (ThreadId == UINT32_UNKNOWN) {
            ThreadId = Event->ThreadId;
        }
        if (Event->Processor < 64) {
            ProcessorBitmap |= (1ull << Event->Processor);
        }
        if (!Payload->ActivityStateUpdated.IsActive) {
            if (LastActiveTimeStamp != UINT64_UNKNOWN) {
                TotalActiveTime += Event->TimeStamp - LastActiveTimeStamp;
            }
        } else {
            LastActiveTimeStamp = Event->TimeStamp;
        }
        break;
    default:
        break;
    }

    FinalTimeStamp = Event->TimeStamp;

    Events.push_back(Event);
}

void QuicWorker::OnConnectionEvent(const QuicConnectionData* /* Connection */, const QuicEvent* Event) {
    if (Event->Id == EventId_QuicConnScheduleState &&
        GetConnPayload(Event)->ScheduleState.State == QuicScheduleProcessing) {
        if (ThreadId == UINT32_UNKNOWN) {
            ThreadId = Event->ThreadId;
        }
        if (Event->Processor < 64) {
            ProcessorBitmap |= (1ull << Event->Processor);
        }
        // TODO - Scheduling state?
        FinalTimeStamp = Event->TimeStamp;
    }
}

void QuicConnection::AddEvent(const QuicEvent* Event, QuicEventCollection* EventCollection) {
    auto Payload = GetConnPayload(Event);

    if (InitialTimeStamp == UINT64_UNKNOWN) {
        InitialTimeStamp = Event->TimeStamp;
    }

    switch (Event->Id) {
    case EventId_QuicConnCreated:
    case EventId_QuicConnRundown:
        CorrelationId = Payload->Rundown.CorrelationId;
        State = ConnStateAllocated;
        IsServer = Payload->Rundown.IsServer ? TriTrue : TriFalse;
        IsHandshakeComplete = TriFalse;
        break;
    case EventId_QuicConnHandshakeComplete:
        State = ConnStateHandshakeComplete;
        IsHandshakeComplete = TriTrue;
        break;
    case EventId_QuicConnScheduleState:
        EventCollection->DataAvailableFlags |= QuicDataAvailableConnectionSchedule;
        if (Payload->ScheduleState.State == QuicScheduleProcessing) {
            if (Event->Processor < 64) {
                ProcessorBitmap |= (1ull << Event->Processor);
            }
            if (Worker != nullptr) {
                Worker = EventCollection->GetWorkerFromThread(Event->ThreadId);
                if (Worker != nullptr) {
                    GetWorker()->OnConnectionAdded(this);
                }
            }
        }
        break;
    case EventId_QuicConnExecOper:
    case EventId_QuicConnExecApiOper:
    //case EventId_QuicConnExecTimerOper:
        EventCollection->DataAvailableFlags |= QuicDataAvailableConnectionExec;
        break;
    case EventId_QuicConnAssignWorker: {
        if (Worker != nullptr) {
            GetWorker()->OnConnectionRemoved(this);
        }
        ObjectKey WorkerKey(
            PointerSizeBytes[Event->PointerSize],
            ReadPointer(Event->PointerSize, Payload->AssignWorker.WorkerPtr),
            Event->ProcessId);
        Worker = EventCollection->WorkerSet.FindOrCreateActive(WorkerKey);
        GetWorker()->OnConnectionAdded(this);
        break;
    }
    case EventId_QuicConnTransportShutdown:
        State = ConnStateShutdown;
        IsAppShutdown = TriFalse;
        IsShutdownRemote = Payload->TransportShutdown.IsRemoteShutdown ? TriTrue : TriFalse;
        ShutdownTimeStamp = Event->TimeStamp;
        break;
    case EventId_QuicConnAppShutdown:
        State = ConnStateShutdown;
        IsAppShutdown = TriTrue;
        IsShutdownRemote = Payload->AppShutdown.IsRemoteShutdown ? TriTrue : TriFalse;
        ShutdownTimeStamp = Event->TimeStamp;
        break;
    case EventId_QuicConnHandleClosed:
        State = ConnStateClosed;
        break;
    case EventId_QuicConnOutFlowStats:
        EventCollection->DataAvailableFlags |= QuicDataAvailableConnectionTput;
        BytesSent = Payload->OutFlowStats.BytesSent;
        break;
    case EventId_QuicConnOutFlowBlocked:
        EventCollection->DataAvailableFlags |= QuicDataAvailableConnectionFlowBlocked;
        break;
    case EventId_QuicConnInFlowStats:
        EventCollection->DataAvailableFlags |= QuicDataAvailableConnectionTput;
        BytesReceived = Payload->InFlowStats.BytesRecv;
        break;
    case EventId_QuicConnStats:
        BytesReceived = Payload->Stats.SendTotalBytes;
        BytesReceived = Payload->Stats.RecvTotalBytes;
        break;
    default:
        break;
    }

    FinalTimeStamp = Event->TimeStamp;

    if (Worker != nullptr) {
        GetWorker()->OnConnectionEvent(this, Event);
    }

    Events.push_back(Event);
}

void QuicStream::AddEvent(const QuicEvent* Event, QuicEventCollection* EventCollection) {
    auto Payload = GetStreamPayload(Event);

    if (InitialTimeStamp == UINT64_UNKNOWN) {
        InitialTimeStamp = Event->TimeStamp;
    }

    switch (Event->Id) {
    case EventId_QuicStreamCreated:
    case EventId_QuicStreamRundown: {
        ObjectKey ConnectionKey(
            PointerSizeBytes[Event->PointerSize],
            ReadPointer(Event->PointerSize, Payload->Created.ConnectionPtr),
            Event->ProcessId);
        Connection = EventCollection->ConnectionSet.FindOrCreateActive(ConnectionKey);
        StreamId = *(uint64_t*)(Payload->Created.ConnectionPtr + PointerSizeBytes[Event->PointerSize]);
        break;
    }
    case EventId_QuicStreamOutFlowBlocked:
        EventCollection->DataAvailableFlags |= QuicDataAvailableStreamFlowBlocked;
        break;
    default:
        break;
    }

    FinalTimeStamp = Event->TimeStamp;

    Events.push_back(Event);
}
