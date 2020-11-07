//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using System.Linq;
using MsQuicTracing.DataModel.ETW;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicState
    {
        public IReadOnlyList<QuicWorker> Workers => WorkerSet.GetObjects();

        public IReadOnlyList<QuicConnection> Connections => ConnectionSet.GetObjects();

        private QuicObjectSet<QuicWorker> WorkerSet { get; } =
            new QuicObjectSet<QuicWorker>(QuicWorker.CreateEventId, QuicWorker.DestroyedEventId, QuicWorker.New);

        private QuicObjectSet<QuicConnection> ConnectionSet { get; } =
            new QuicObjectSet<QuicConnection>(QuicConnection.CreateEventId, QuicConnection.DestroyedEventId, QuicConnection.New);

        private readonly List<QuicEvent> Events = new List<QuicEvent>();

        internal void AddEvent(QuicEvent evt)
        {
            switch (evt.ObjectType)
            {
                case QuicObjectType.Worker:
                    WorkerSet.FindOrCreateActive(new QuicObjectKey(evt)).AddEvent(evt);
                    break;
                case QuicObjectType.Connection:
                    ConnectionSet.FindOrCreateActive(new QuicObjectKey(evt)).AddEvent(evt, this);
                    break;
                default:
                    break;
            }

            Events.Add(evt);
        }

        internal void OnTraceComplete()
        {
            WorkerSet.FinalizeObjects();
            ConnectionSet.FinalizeObjects();
        }

        internal QuicWorker FindOrCreateWorker(QuicObjectKey key)
        {
            return WorkerSet.FindOrCreateActive(key);
        }

        internal QuicWorker? GetWorkerFromThread(uint threadId)
        {
            var worker = WorkerSet.activeTable.Where(x => x.Value.ThreadId == threadId).Select(x => x.Value).FirstOrDefault();
            if (worker is null)
            {
                worker = WorkerSet.inactiveList.Where(x => x.ThreadId == threadId).FirstOrDefault();
            }
            return worker;
        }

        public IReadOnlyList<QuicApiData> GetApiCalls()
        {
            var apiEvents = new List<QuicApiData>();

            Dictionary<ulong, Queue<QuicEvent>> ApiStartEvents = new Dictionary<ulong, Queue<QuicEvent>>();

            Queue<QuicEvent> GetEventQueue(uint processId, uint threadId)
            {
                var hash = (((ulong)processId) << 32) | ((ulong)threadId);
                if (!ApiStartEvents.TryGetValue(hash, out var queue)) {
                    queue = new Queue<QuicEvent>();
                    ApiStartEvents.Add(hash, queue);
                }
                return queue;
            }

            void Push(QuicEvent evt)
            {
                GetEventQueue(evt.ProcessId, evt.ThreadId).Enqueue(evt);
            }

            QuicEvent? Pop(uint processId, uint threadId)
            {
                var queue = GetEventQueue(processId, threadId);
                return queue.TryDequeue(out var evt) ? evt : null;
            }

            foreach (var evt in Events)
            {
                if (evt.ObjectType != QuicObjectType.Global)
                {
                    continue;
                }

                if (evt.ID == QuicEventId.ApiEnter)
                {
                    Push(evt);
                }
                else if (evt.ID == QuicEventId.ApiExit || evt.ID == QuicEventId.ApiExitStatus)
                {
                    var startEvent = Pop(evt.ProcessId, evt.ThreadId);
                    if (startEvent != null)
                    {
                        var startPayload = startEvent.Payload as QuicApiEnterEtwPayload;
                        var endPayload = evt.Payload as QuicApiExitStatusEtwPayload;
                        apiEvents.Add(new QuicApiData(
                            (QuicApiType)startPayload!.Type,
                            startEvent.Processor, // What if end is on a different processor
                            startEvent.ProcessId,
                            startEvent.ThreadId,
                            startEvent.TimeStamp,
                            evt.TimeStamp - startEvent.TimeStamp,
                            startPayload.Handle,
                            (evt.ID == QuicEventId.ApiExitStatus) ? endPayload!.Status : 0));
                    }
                }
            }

            return apiEvents;
        }
    }
}
