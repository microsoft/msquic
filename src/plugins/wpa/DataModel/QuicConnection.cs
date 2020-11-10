﻿//
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

        public List<QuicStream> Streams { get; } = new List<QuicStream>();

        private readonly List<QuicEvent> Events = new List<QuicEvent>();

        public IReadOnlyList<QuicScheduleData> GetScheduleEvents()
        {
            var scheduleEvents = new List<QuicScheduleData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (evt.ID == QuicEventId.ConnScheduleState)
                {
                    if (lastEvent != null)
                    {
                        var payload = lastEvent.Payload as QuicConnectionScheduleStatePayload;
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

        public IReadOnlyList<QuicFlowBlockedData> GetFlowBlockedEvents()
        {
            var flowBlockedEvents = new List<QuicFlowBlockedData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (evt.ID == QuicEventId.ConnOutFlowBlocked)
                {
                    if (lastEvent != null)
                    {
                        var payload = lastEvent.Payload as QuicConnectionOutFlowBlockedPayload;
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
                var payload = lastEvent.Payload as QuicConnectionOutFlowBlockedPayload;
                flowBlockedEvents.Add(
                    new QuicFlowBlockedData(
                        lastEvent.TimeStamp,
                        FinalTimeStamp - lastEvent.TimeStamp,
                        (QuicFlowBlockedFlags)payload!.ReasonFlags));
            }
            return flowBlockedEvents;
        }

        public IReadOnlyList<QuicExecutionData> GetExecutionEvents()
        {
            var execEvents = new List<QuicExecutionData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (lastEvent != null &&
                    (evt.ID == QuicEventId.ConnScheduleState ||
                        evt.ID == QuicEventId.ConnExecOper ||
                        evt.ID == QuicEventId.ConnExecApiOper ||
                        evt.ID == QuicEventId.ConnExecTimerOper))
                {
                    QuicExecutionType type = QuicExecutionType.Unknown;
                    switch (lastEvent.ID)
                    {
                        case QuicEventId.ConnExecOper:
                            {
                                var payload = lastEvent.Payload as QuicConnectionExecOperPayload;
                                type = (QuicExecutionType)((uint)QuicExecutionType.OperApi + payload!.Type);
                                break;
                            }
                        case QuicEventId.ConnExecApiOper:
                            {
                                var payload = lastEvent.Payload as QuicConnectionExecApiOperPayload;
                                type = (QuicExecutionType)((uint)QuicExecutionType.ApiConnClose + payload!.Type);
                                break;
                            }
                        case QuicEventId.ConnExecTimerOper:
                            {
                                var payload = lastEvent.Payload as QuicConnectionExecTimerOperPayload;
                                type = (QuicExecutionType)((uint)QuicExecutionType.TimerPacing + payload!.Type);
                                break;
                            }
                    }
                    execEvents.Add(
                        new QuicExecutionData(
                            lastEvent.TimeStamp,
                            lastEvent.ThreadId,
                            lastEvent.Processor,
                            evt.TimeStamp - lastEvent.TimeStamp,
                            type));
                }
                if (evt.ID == QuicEventId.ConnScheduleState)
                {
                    lastEvent = null;
                }
                else if (evt.ID == QuicEventId.ConnExecOper ||
                        evt.ID == QuicEventId.ConnExecApiOper ||
                        evt.ID == QuicEventId.ConnExecTimerOper)
                {
                    lastEvent = evt;
                }
            }
            return execEvents;
        }

        public IReadOnlyList<QuicThroughputData> GetThroughputEvents(long resolutionNanoSec = 25 * 1000 * 1000) // 25 ms default
        {
            var Resolution = new TimestampDelta(resolutionNanoSec);
            bool initialTxRateSampled = false;
            bool initialRxRateSampled = false;
            var sample = new QuicThroughputData();

            int eventCount = Events.Count;
            int eventIndex = 0;

            var tputEvents = new List<QuicThroughputData>();
            foreach (var evt in Events)
            {
                if (eventIndex == 0)
                {
                    sample.TimeStamp = evt.TimeStamp;
                }
                eventIndex++;

                if (evt.ID == QuicEventId.ConnOutFlowStats)
                {
                    var payload = evt.Payload as QuicConnectionOutFlowStatsPayload;
                    sample.RttUs = payload!.SmoothedRtt;
                    sample.BytesSent = payload!.BytesSent;
                    sample.BytesInFlight = payload!.BytesInFlight;
                    sample.CongestionWindow = payload!.CongestionWindow;
                    sample.BytesBufferedForSend = payload!.PostedBytes;
                    sample.FlowControlAvailable = payload!.ConnectionFlowControl;
                    if (!initialTxRateSampled)
                    {
                        initialTxRateSampled = true;
                        sample.TxRate = sample.BytesSent;
                    }
                }
                else if (evt.ID == QuicEventId.ConnInFlowStats)
                {
                    var payload = evt.Payload as QuicConnectionInFlowStatsPayload;
                    sample.BytesReceived = payload!.BytesRecv;
                    if (!initialRxRateSampled)
                    {
                        initialRxRateSampled = true;
                        sample.RxRate = sample.BytesReceived;
                    }
                }
                else if (evt.ID == QuicEventId.ConnCongestion)
                {
                    sample.CongestionEvents++;
                }
                else if (evt.ID == QuicEventId.ConnStats && sample.TimeStamp == Timestamp.Zero)
                {
                    var payload = evt.Payload as QuicConnectionStatsPayload;
                    sample.RttUs = payload!.SmoothedRtt;
                    sample.BytesSent = payload!.SendTotalBytes;
                    sample.BytesReceived = payload!.RecvTotalBytes;
                    sample.CongestionEvents = payload!.CongestionCount;
                }
                else if (evt.ID == QuicEventId.ConnOutFlowStreamStats)
                {
                    var payload = evt.Payload as QuicConnectionOutFlowStreamStatsPayload;
                    sample.StreamFlowControlAvailable = payload!.StreamFlowControl;
                }
                else
                {
                    continue;
                }

                if (sample.TimeStamp + Resolution <= evt.TimeStamp || eventIndex == eventCount)
                {
                    sample.Duration = evt.TimeStamp - sample.TimeStamp;
                    sample.TxRate = ((sample.BytesSent - sample.TxRate) * 8 * 1000 * 1000 * 1000) / (ulong)sample.Duration.ToNanoseconds;
                    sample.RxRate = ((sample.BytesReceived - sample.RxRate) * 8 * 1000 * 1000 * 1000) / (ulong)sample.Duration.ToNanoseconds;

                    tputEvents.Add(sample);

                    sample.TimeStamp = evt.TimeStamp;
                    sample.TxRate = sample.BytesSent;
                    sample.RxRate = sample.BytesReceived;
                    sample.CongestionEvents = 0;
                }
            }
            return tputEvents;
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
                        state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionSchedule;
                        var Payload = (evt.Payload as QuicConnectionScheduleStatePayload);
                        if (Payload!.State == (uint)QuicScheduleState.Processing)
                        {
                            if (Worker == null)
                            {
                                Worker = state.GetWorkerFromThread(evt.ThreadId);
                                Worker?.OnConnectionAdded();
                            }
                        }
                        break;
                    }
                case QuicEventId.ConnExecOper:
                case QuicEventId.ConnExecApiOper:
                case QuicEventId.ConnExecTimerOper:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionExec;
                        break;
                    }
                case QuicEventId.ConnAssignWorker:
                    {
                        Worker?.OnConnectionRemoved();
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
                        state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionTput;
                        var payload = evt.Payload as QuicConnectionOutFlowStatsPayload;
                        BytesSent = payload!.BytesSent;
                        break;
                    }
                case QuicEventId.ConnOutFlowBlocked:
                    {
                        var payload = evt.Payload as QuicConnectionOutFlowBlockedPayload;
                        if (payload!.ReasonFlags != 0)
                        {
                            state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionFlowBlocked;
                        }
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
                        state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionTput;
                        var payload = evt.Payload as QuicConnectionStatsPayload;
                        BytesSent = payload!.SendTotalBytes;
                        BytesReceived = payload!.RecvTotalBytes;
                        break;
                    }
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            Worker?.OnConnectionEvent(evt);

            Events.Add(evt);
        }

        internal void OnStreamAdded(QuicStream stream)
        {
            Streams.Add(stream);
        }
    }
}
