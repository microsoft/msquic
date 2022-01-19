//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using System.Linq;

namespace QuicTrace.DataModel
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

        private Dictionary<uint, QuicConnection> LastConnections = new Dictionary<uint, QuicConnection>();

        public List<QuicEvent> Events { get; } = new List<QuicEvent>();

        internal void AddEvent(QuicEvent evt)
        {
            switch (evt.ObjectType)
            {
                case QuicObjectType.Global:
                    if (evt.EventId >= QuicEventId.ApiEnter &&
                        evt.EventId <= QuicEventId.ApiExitStatus)
                    {
                        DataAvailableFlags |= QuicDataAvailableFlags.Api;
                    }
                    break;
                case QuicObjectType.Worker:
                    DataAvailableFlags |= QuicDataAvailableFlags.Worker;
                    WorkerSet.FindOrCreateActive(evt).AddEvent(evt, this);
                    break;
                case QuicObjectType.Connection:
                    DataAvailableFlags |= QuicDataAvailableFlags.Connection;
                    var Conn = ConnectionSet.FindOrCreateActive(evt);
                    Conn.AddEvent(evt, this);
                    LastConnections[evt.ThreadId] = Conn;
                    break;
                case QuicObjectType.Stream:
                    DataAvailableFlags |= QuicDataAvailableFlags.Stream;
                    StreamSet.FindOrCreateActive(evt).AddEvent(evt, this);
                    break;
                case QuicObjectType.Datapath:
                    DatapathSet.FindOrCreateActive(evt).AddEvent(evt, this);
                    if (evt.EventId == QuicEventId.DatapathSend &&
                        LastConnections.TryGetValue(evt.ThreadId, out var LastConn))
                    {
                        LastConn.AddEvent(evt, this);
                    }
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

        internal QuicWorker? GetWorkerFromThread(uint processId, uint threadId)
        {
            var worker =
                WorkerSet.activeTable
                    .Where(x => x.Value.ProcessId == processId &&
                                x.Value.ThreadId == threadId)
                    .Select(x => x.Value).FirstOrDefault();
            if (worker is null)
            {
                worker =
                    WorkerSet.inactiveList
                        .Where(x => x.ProcessId == processId &&
                                    x.ThreadId == threadId)
                        .FirstOrDefault();
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
                if (evt.EventId == QuicEventId.ApiEnter)
                {
                    Push(evt);
                }
                else if (evt.EventId == QuicEventId.ApiExit || evt.EventId == QuicEventId.ApiExitStatus)
                {
                    var startEvent = Pop(evt.ProcessId, evt.ThreadId);
                    if (startEvent != null)
                    {
                        var _startEvent = startEvent as QuicApiEnterEvent;
                        var _endEvent = evt as QuicApiExitStatusEvent;
                        apiEvents.Add(new QuicApiData(
                            _startEvent!.ApiType,
                            startEvent.Processor, // What if end is on a different processor?
                            startEvent.ProcessId,
                            startEvent.ThreadId,
                            startEvent.TimeStamp,
                            evt.TimeStamp - startEvent.TimeStamp,
                            _startEvent.Handle,
                            _endEvent?.Status ?? 0));
                    }
                }
            }

            return apiEvents;
        }
    }
}
