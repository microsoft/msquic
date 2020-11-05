//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicState
    {
        public Dictionary<QuicObjectType, ulong> ObjectEventCounts { get; } = new Dictionary<QuicObjectType, ulong>();

        public QuicObjectSet<QuicWorker> Workers { get; } =
            new QuicObjectSet<QuicWorker>(QuicWorker.CreateEventId, QuicWorker.DestroyedEventId, QuicWorker.New);

        private List<QuicEvent> Events = new List<QuicEvent>();

        internal void AddEvent(QuicEvent quicEvent)
        {
            if (!ObjectEventCounts.ContainsKey(quicEvent.ObjectType))
            {
                ObjectEventCounts.Add(quicEvent.ObjectType, 1);
            }
            else
            {
                ObjectEventCounts[quicEvent.ObjectType]++;
            }

            switch (quicEvent.ObjectType)
            {
                case QuicObjectType.Worker:
                    var key = new QuicObjectKey(quicEvent.PointerSize, quicEvent.ObjectPointer, quicEvent.ProcessId);
                    var value = Workers.FindOrCreateActive(key);
                    value.AddEvent(quicEvent);
                    break;
                default:
                    break;
            }

            Events.Add(quicEvent);
        }

        internal void OnTraceComplete()
        {
            Workers.FinalizeObjects();
        }
    }
}
