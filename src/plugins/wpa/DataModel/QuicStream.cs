//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicStream : IQuicObject
    {
        public static QuicStream New(ulong pointer, uint processId) => new QuicStream(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.StreamCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.StreamDestroyed;

        public ulong Id { get; }

        private static ulong NextId = 1;

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public ulong StreamId { get; private set; }

        public Timestamp InitialTimeStamp { get; private set; }

        public Timestamp FinalTimeStamp { get; private set; }

        public QuicConnection? Connection { get; private set; }

        private readonly List<QuicEvent> Events = new List<QuicEvent>();

        public IReadOnlyList<QuicFlowBlockedData> GetFlowBlockedEvents()
        {
            var flowBlockedEvents = new List<QuicFlowBlockedData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (evt.ID == QuicEventId.StreamOutFlowBlocked)
                {
                    if (lastEvent != null)
                    {
                        var payload = lastEvent.Payload as QuicStreamOutFlowBlockedPayload;
                        flowBlockedEvents.Add(
                            new QuicFlowBlockedData(
                                lastEvent.TimeStamp,
                                evt.TimeStamp - lastEvent.TimeStamp,
                                (QuicFlowBlockedFlags)payload!.ReasonFlags));
                    }
                    lastEvent = evt;
                }
            }
            if (lastEvent != null)
            {
                var payload = lastEvent.Payload as QuicStreamOutFlowBlockedPayload;
                flowBlockedEvents.Add(
                    new QuicFlowBlockedData(
                        lastEvent.TimeStamp,
                        FinalTimeStamp - lastEvent.TimeStamp,
                        (QuicFlowBlockedFlags)payload!.ReasonFlags));
            }
            return flowBlockedEvents;
        }

        internal QuicStream(ulong pointer, uint processId)
        {
            Id = NextId++;
            Pointer = pointer;
            ProcessId = processId;
            StreamId = ulong.MaxValue;

            InitialTimeStamp = Timestamp.MaxValue;
            FinalTimeStamp = Timestamp.MaxValue;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            if (InitialTimeStamp == Timestamp.MaxValue)
            {
                InitialTimeStamp = evt.TimeStamp;
            }

            switch (evt.ID)
            {
                case QuicEventId.StreamCreated:
                case QuicEventId.StreamRundown:
                    {
                        var payload = (evt.Payload as QuicStreamCreatedPayload);
                        StreamId = payload!.ID;
                        Connection = state.FindOrCreateConnection(new QuicObjectKey(evt.PointerSize, payload!.Connection, evt.ProcessId));
                        Connection.OnStreamAdded(this);
                    }
                    break;
                case QuicEventId.StreamOutFlowBlocked:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.StreamFlowBlocked;
                        break;
                    }
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            Events.Add(evt);
        }
    }
}
