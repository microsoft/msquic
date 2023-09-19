//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public sealed class QuicWorker : IQuicObject
    {
        public static QuicWorker New(ulong pointer, uint processId) => new QuicWorker(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.WorkerCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.WorkerDestroyed;

        public ulong Id { get; }

        private static ulong NextId = 1;

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public uint ThreadId { get; private set; }

        public ushort IdealProcessor { get; private set; }

        public Timestamp InitialTimeStamp { get; private set; }

        public Timestamp FinalTimeStamp { get; private set; }

        public TimestampDelta ElapsedTimeDelta { get { return FinalTimeStamp - InitialTimeStamp; } }

        public Timestamp LastActiveTimeStamp { get; private set; }

        public TimestampDelta TotalActiveTime { get; private set; }

        public uint TotalConnections { get; private set; }

        public uint CurrentConnections { get; private set; }

        public QuicSchedulingStats SchedulingStats { get; private set; }

        public uint AverageQueueDelayUs { get { return SchedulingStats.GetStats(QuicScheduleState.Queued).AverageCpuTimeUs; } }

        public ulong TotalProcessingTimeUs { get { return SchedulingStats.GetStats(QuicScheduleState.Processing).TotalCpuTimeUs; } }

        public uint ActivePercent
        {
            get
            {
                var elapsedTime = (ulong)ElapsedTimeDelta.ToMicroseconds;
                return (uint)(elapsedTime == 0 ? 0 : (100 * TotalProcessingTimeUs / elapsedTime));
            }
        }

        internal QuicConnection? LastConnection { get; private set; }

        private readonly List<QuicEvent> Events = new List<QuicEvent>();

        public IReadOnlyList<QuicActivityData> GetActivityEvents()
        {
            var activityEvents = new List<QuicActivityData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (evt.EventId == QuicEventId.WorkerActivityStateUpdated)
                {
                    var _evt = evt as QuicWorkerActivityStateUpdatedEvent;
                    if (_evt!.IsActive == 0)
                    {
                        if (!(lastEvent is null))
                        {
                            activityEvents.Add(
                                new QuicActivityData(
                                    lastEvent.TimeStamp,
                                    evt.TimeStamp - lastEvent.TimeStamp,
                                    lastEvent.Processor));
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

        internal QuicWorker(ulong pointer, uint processId)
        {
            Id = NextId++;
            Pointer = pointer;
            ProcessId = processId;
            ThreadId = uint.MaxValue;
            IdealProcessor = ushort.MaxValue;

            InitialTimeStamp = Timestamp.MaxValue;
            FinalTimeStamp = Timestamp.MaxValue;
            LastActiveTimeStamp = Timestamp.MaxValue;
            TotalActiveTime = TimestampDelta.Zero;

            SchedulingStats = new QuicSchedulingStats();

            LastConnection = null;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            if (InitialTimeStamp == Timestamp.MaxValue)
            {
                InitialTimeStamp = evt.TimeStamp;
            }

            switch (evt.EventId)
            {
                case QuicEventId.WorkerCreated:
                    IdealProcessor = (evt as QuicWorkerCreatedEvent)!.IdealProcessor;
                    break;
                case QuicEventId.WorkerActivityStateUpdated:
                    state.DataAvailableFlags |= QuicDataAvailableFlags.WorkerActivity;
                    if (ThreadId == uint.MaxValue)
                    {
                        ThreadId = evt.ThreadId;
                    }
                    var _evt = evt as QuicWorkerActivityStateUpdatedEvent;
                    if (_evt!.IsActive != 0)
                    {
                        if (LastActiveTimeStamp != Timestamp.MaxValue)
                        {
                            TotalActiveTime += evt.TimeStamp - LastActiveTimeStamp;
                        }
                    }
                    else
                    {
                        LastActiveTimeStamp = evt.TimeStamp;
                        LastConnection = null;
                    }
                    break;
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            Events.Add(evt);
        }

        internal void OnConnectionEvent(QuicConnection connection, QuicEvent evt)
        {
            if (evt.EventId == QuicEventId.ConnScheduleState)
            {
                var _evt = evt as QuicConnectionScheduleStateEvent;
                if (_evt!.ScheduleState == QuicScheduleState.Processing)
                {
                    if (ThreadId == uint.MaxValue)
                    {
                        ThreadId = evt.ThreadId;
                    }

                    FinalTimeStamp = evt.TimeStamp;
                    LastConnection = connection;
                }
                else
                {
                    LastConnection = null;
                }
            }
            else if (evt.EventId == QuicEventId.ConnOutFlowStats ||
                     evt.EventId == QuicEventId.ConnOutFlowStatsV2)
            {
                LastConnection = connection;
            }
        }

        internal void AddSchedulingCpuTime(QuicScheduleState state, TimestampDelta delta)
        {
            SchedulingStats.AddCpuTime(state, delta);
        }

        internal void OnConnectionAdded()
        {
            TotalConnections++;
            CurrentConnections++;
        }

        internal void OnConnectionRemoved()
        {
            CurrentConnections--;
        }
    }
}
