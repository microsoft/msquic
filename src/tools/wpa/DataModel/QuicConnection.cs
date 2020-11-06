//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicConnection : IQuicObject
    {
        public static QuicConnection New(ulong pointer, uint processId) => new QuicConnection(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.ConnCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.ConnDestroyed;

        public ulong Id { get; }

        private static ulong NextId = 1;

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public ulong CorrelationId { get; private set; }

        public QuicConnectionState State { get; private set; }

        public bool? IsServer { get; private set; }

        public bool? IsHandshakeComplete { get; private set; }

        public bool? IsAppShutdown { get; private set; }

        public bool? IsShutdownRemote { get; private set; }

        public Timestamp InitialTimeStamp { get; private set; }

        public Timestamp FinalTimeStamp { get; private set; }

        public Timestamp ShutdownTimeStamp { get; private set; }

        public ulong BytesSent { get; private set; }

        public ulong BytesReceived { get; private set; }

        public QuicWorker? Worker { get; private set; }

        //public List<QuicStream> Streams { get; } = new List<QuicStream>();

        private List<QuicEvent> Events = new List<QuicEvent>();

        public IReadOnlyList<QuicScheduleData> ScheduleEvents
        {
            get
            {
                var scheduleEvents = new List<QuicScheduleData>();
                QuicEvent? lastEvent = null;
                foreach (var evt in Events)
                {
                    if (evt.ID == QuicEventId.ConnScheduleState)
                    {
                        if (lastEvent != null)
                        {
                            var payload = evt.Payload as QuicConnectionScheduleStatePayload;
                            scheduleEvents.Add(
                                new QuicScheduleData(
                                    lastEvent.TimeStamp,
                                    evt.TimeStamp - lastEvent.TimeStamp,
                                    lastEvent.ThreadId,
                                    (QuicScheduleState)payload!.State));
                        }
                        lastEvent = evt;
                    }
                }
                return scheduleEvents;
            }
        }

        public IReadOnlyList<QuicFlowBlockedData> FlowBlockedEvents
        {
            get
            {
                var flowBlockedEvents = new List<QuicFlowBlockedData>();
                foreach (var evt in Events)
                {
                    if (evt.ID == QuicEventId.ConnOutFlowBlocked)
                    {
                        var payload = evt.Payload as QuicConnectionOutFlowBlockedPayload;
                        flowBlockedEvents.Add(
                            new QuicFlowBlockedData(
                                evt.TimeStamp,
                                (QuicFlowBlockedFlags)payload!.ReasonFlags));
                    }
                }
                return flowBlockedEvents;
            }
        }

        internal QuicConnection(ulong pointer, uint processId)
        {
            Id = NextId++;
            Pointer = pointer;
            ProcessId = processId;
            CorrelationId = ulong.MaxValue;
            State = QuicConnectionState.Unknown;

            InitialTimeStamp = Timestamp.MaxValue;
            FinalTimeStamp = Timestamp.MaxValue;
            ShutdownTimeStamp = Timestamp.MaxValue;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            if (InitialTimeStamp == Timestamp.MaxValue)
            {
                InitialTimeStamp = evt.TimeStamp;
            }

            switch (evt.ID)
            {
                case QuicEventId.ConnCreated:
                case QuicEventId.ConnRundown:
                    {
                        var Payload = (evt.Payload as QuicConnectionCreatedPayload);
                        CorrelationId = Payload!.CorrelationId;
                        State = QuicConnectionState.Allocated;
                        IsServer = Payload!.IsServer != 0;
                        IsHandshakeComplete = false;
                    }
                    break;
                case QuicEventId.ConnHandshakeComplete:
                    {
                        State = QuicConnectionState.HandshakeComplete;
                        IsHandshakeComplete = true;
                        break;
                    }
                case QuicEventId.ConnScheduleState:
                    {
                        var Payload = (evt.Payload as QuicConnectionScheduleStatePayload);
                        if (Payload!.State == (uint)QuicScheduleState.Processing)
                        {
                            if (Worker == null)
                            {
                                Worker = state.GetWorkerFromThread(evt.ThreadId);
                                if (Worker != null)
                                {
                                    Worker.OnConnectionAdded();
                                }
                            }
                        }
                        break;
                    }
                case QuicEventId.ConnExecOper:
                case QuicEventId.ConnExecApiOper:
                //case QuicEventId.ConnExecTimerOper:
                    {
                        break;
                    }
                case QuicEventId.ConnAssignWorker:
                    {
                        if (Worker != null)
                        {
                            Worker.OnConnectionRemoved();
                        }
                        var payload = evt.Payload as QuicConnectionAssignWorkerPayload;
                        var key = new QuicObjectKey(evt.PointerSize, payload!.WorkerPointer, evt.ProcessId);
                        Worker = state.FindOrCreateWorker(key);
                        Worker.OnConnectionAdded();
                        break;
                    }
                case QuicEventId.ConnTransportShutdown:
                    {
                        var payload = evt.Payload as QuicConnectionTransportShutdownPayload;
                        State = QuicConnectionState.Shutdown;
                        IsAppShutdown = false;
                        IsShutdownRemote = payload!.IsRemoteShutdown != 0;
                        ShutdownTimeStamp = evt.TimeStamp;
                        break;
                    }
                case QuicEventId.ConnAppShutdown:
                    {
                        var payload = evt.Payload as QuicConnectionAppShutdownPayload;
                        State = QuicConnectionState.Shutdown;
                        IsAppShutdown = true;
                        IsShutdownRemote = payload!.IsRemoteShutdown != 0;
                        ShutdownTimeStamp = evt.TimeStamp;
                        break;
                    }
                case QuicEventId.ConnHandleClosed:
                    {
                        State = QuicConnectionState.Closed;
                        break;
                    }
                case QuicEventId.ConnOutFlowStats:
                    {
                        var payload = evt.Payload as QuicConnectionOutFlowStatsPayload;
                        BytesSent = payload!.BytesSent;
                        break;
                    }
                case QuicEventId.ConnOutFlowBlocked:
                    {
                        break;
                    }
                case QuicEventId.ConnInFlowStats:
                    {
                        var payload = evt.Payload as QuicConnectionInFlowStatsPayload;
                        BytesReceived = payload!.BytesRecv;
                        break;
                    }
                case QuicEventId.ConnStats:
                    {
                        var payload = evt.Payload as QuicConnectionStatsPayload;
                        BytesSent = payload!.SendTotalBytes;
                        BytesReceived = payload!.RecvTotalBytes;
                        break;
                    }
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            if (Worker != null)
            {
                Worker.OnConnectionEvent(evt);
            }

            Events.Add(evt);
        }
    }
}
