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
        public QuicDataAvailableFlags DataAvailableFlags { get; internal set; } = QuicDataAvailableFlags.None;

        public IReadOnlyList<QuicWorker> Workers => WorkerSet.GetObjects();

        public IReadOnlyList<QuicConnection> Connections => ConnectionSet.GetObjects();

        public IReadOnlyList<QuicStream> Streams => StreamSet.GetObjects();

        public IReadOnlyList<QuicDatapath> Datapaths => DatapathSet.GetObjects();

        private QuicObjectSet<QuicWorker> WorkerSet { get; } =
            new QuicObjectSet<QuicWorker>(QuicWorker.CreateEventId, QuicWorker.DestroyedEventId, QuicWorker.New);

        private QuicObjectSet<QuicConnection> ConnectionSet { get; } =
            new QuicObjectSet<QuicConnection>(QuicConnection.CreateEventId, QuicConnection.DestroyedEventId, QuicConnection.New);

        private QuicObjectSet<QuicStream> StreamSet { get; } =
            new QuicObjectSet<QuicStream>(QuicStream.CreateEventId, QuicStream.DestroyedEventId, QuicStream.New);

        private QuicObjectSet<QuicDatapath> DatapathSet { get; } =
            new QuicObjectSet<QuicDatapath>(QuicDatapath.CreateEventId, QuicDatapath.DestroyedEventId, QuicDatapath.New);

        public List<QuicEvent> Events { get; } = new List<QuicEvent>();

        internal void AddEvent(QuicEvent evt)
        {
            switch (evt.ObjectType)
            {
                case QuicObjectType.Global:
                    if (evt.ID >= QuicEventId.ApiEnter &&
                        evt.ID <= QuicEventId.ApiExitStatus)
                    {
                        DataAvailableFlags |= QuicDataAvailableFlags.Api;
                    }
                    break;
                case QuicObjectType.Worker:
                    DataAvailableFlags |= QuicDataAvailableFlags.Worker;
                    WorkerSet.FindOrCreateActive(new QuicObjectKey(evt)).AddEvent(evt, this);
                    break;
                case QuicObjectType.Connection:
                    DataAvailableFlags |= QuicDataAvailableFlags.Connection;
                    ConnectionSet.FindOrCreateActive(new QuicObjectKey(evt)).AddEvent(evt, this);
                    break;
                case QuicObjectType.Stream:
                    DataAvailableFlags |= QuicDataAvailableFlags.Stream;
                    StreamSet.FindOrCreateActive(new QuicObjectKey(evt)).AddEvent(evt, this);
                    break;
                case QuicObjectType.Datapath:
                    DatapathSet.FindOrCreateActive(new QuicObjectKey(evt)).AddEvent(evt, this);
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
            StreamSet.FinalizeObjects();
            DatapathSet.FinalizeObjects();
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

        internal QuicConnection FindOrCreateConnection(QuicObjectKey key)
        {
            return ConnectionSet.FindOrCreateActive(key);
        }

        public IReadOnlyList<QuicApiData> GetApiCalls()
        {
            var apiEvents = new List<QuicApiData>();

            var ApiStartEvents = new Dictionary<ulong, Queue<QuicEvent>>();
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
                            startEvent.Processor, // What if end is on a different processor?
                            startEvent.ProcessId,
                            startEvent.ThreadId,
                            startEvent.TimeStamp,
                            evt.TimeStamp - startEvent.TimeStamp,
                            startPayload.Handle,
                            endPayload?.Status ?? 0));
                    }
                }
            }

            return apiEvents;
        }
    }
}
