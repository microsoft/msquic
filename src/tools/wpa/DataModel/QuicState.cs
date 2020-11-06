//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using System.Linq;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicState
    {
        public List<QuicWorker> Workers => WorkerSet.GetObjects();

        public List<QuicConnection> Connections => ConnectionSet.GetObjects();

        private QuicObjectSet<QuicWorker> WorkerSet { get; } =
            new QuicObjectSet<QuicWorker>(QuicWorker.CreateEventId, QuicWorker.DestroyedEventId, QuicWorker.New);

        private QuicObjectSet<QuicConnection> ConnectionSet { get; } =
            new QuicObjectSet<QuicConnection>(QuicConnection.CreateEventId, QuicConnection.DestroyedEventId, QuicConnection.New);

        private List<QuicEvent> Events = new List<QuicEvent>();

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
    }
}
