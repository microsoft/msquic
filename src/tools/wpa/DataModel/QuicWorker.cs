//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicWorker : IQuicObject
    {
        public static QuicWorker New(ulong pointer, uint processId) => new QuicWorker(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.WorkerCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.WorkerDestroyed;

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public uint ThreadId { get; private set; }

        public ushort IdealProcessor { get; private set; }

        public ulong Id { get; }

        private static ulong NextId = 1;

        public ulong InitialTimeStamp { get; private set; }

        public ulong FinalTimeStamp { get; private set; }

        public ulong LastActiveTimeStamp { get; private set; }

        public ulong TotalActiveTime { get; private set; }

        public uint TotalConnections { get; private set; }

        public uint CurrentConnections { get; private set; }

        private List<QuicEvent> Events = new List<QuicEvent>();

        public IReadOnlyList<QuicActivityData> ActivityEvents
        {
            get
            {
                var activityEvents = new List<QuicActivityData>();
                QuicEvent? lastEvent = null;
                foreach (var evt in Events)
                {
                    if (evt.ID == QuicEventId.WorkerActivityStateUpdated)
                    {
                        var payload = evt.Payload as QuicWorkerActivityStateUpdatedPayload;
                        if (payload!.IsActive == 0)
                        {
                            if (!(lastEvent is null))
                            {
                                activityEvents.Add(new QuicActivityData(lastEvent.TimeStamp, evt.TimeStamp - lastEvent.TimeStamp));
                                lastEvent = null;
                            }
                        }
                        else if (lastEvent is null)
                        {
                            lastEvent = evt;
                        }
                    }
                }
                return activityEvents;
            }
        }

        internal QuicWorker(ulong pointer, uint processId)
        {
            Id = NextId++;
            Pointer = pointer;
            ProcessId = processId;
            ThreadId = uint.MaxValue;
            IdealProcessor = ushort.MaxValue;
            // TODO - ProcessorBitmap?

            InitialTimeStamp = ulong.MaxValue;
            FinalTimeStamp = ulong.MaxValue;
            LastActiveTimeStamp = ulong.MaxValue;
            TotalActiveTime = 0;
        }

        internal void AddEvent(QuicEvent evt)
        {
            if (InitialTimeStamp == ulong.MaxValue)
            {
                InitialTimeStamp = evt.TimeStamp;
            }

            switch (evt.ID)
            {
                case QuicEventId.WorkerCreated:
                    IdealProcessor = (evt.Payload as QuicWorkerCreatedPayload)!.IdealProcessor;
                    break;
                case QuicEventId.WorkerActivityStateUpdated:
                    if (ThreadId == uint.MaxValue)
                    {
                        ThreadId = evt.ThreadId;
                    }
                    var payload = evt.Payload as QuicWorkerActivityStateUpdatedPayload;
                    if (payload!.IsActive != 0)
                    {
                        if (LastActiveTimeStamp != ulong.MaxValue)
                        {
                            TotalActiveTime += evt.TimeStamp - LastActiveTimeStamp;
                        }
                    }
                    else
                    {
                        LastActiveTimeStamp = evt.TimeStamp;
                    }
                    break;
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            Events.Add(evt);
        }

        /*internal void OnConnectionEvent(QuicEventBase quicEvent)
        {
        }*/
    }
}
