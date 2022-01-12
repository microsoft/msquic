//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
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

        public Timestamp LastScheduleStateTimeStamp { get; private set; }

        public ulong BytesSent { get; private set; }

        public ulong BytesReceived { get; private set; }

        public QuicWorker? Worker { get; private set; }

        public List<QuicStream> Streams { get; } = new List<QuicStream>();

        public List<QuicEvent> Events { get; } = new List<QuicEvent>();

        public IReadOnlyList<QuicScheduleData> GetScheduleEvents()
        {
            var scheduleEvents = new List<QuicScheduleData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (evt.EventId == QuicEventId.ConnScheduleState)
                {
                    if (lastEvent != null)
                    {
                        var _evt = lastEvent as QuicConnectionScheduleStateEvent;
                        scheduleEvents.Add(
                            new QuicScheduleData(
                                lastEvent.TimeStamp,
                                evt.TimeStamp - lastEvent.TimeStamp,
                                lastEvent.ThreadId,
                                (QuicScheduleState)_evt!.State));
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
                if (evt.EventId == QuicEventId.ConnOutFlowBlocked)
                {
                    if (lastEvent != null)
                    {
                        var _evt = lastEvent as QuicConnectionOutFlowBlockedEvent;
                        flowBlockedEvents.Add(
                            new QuicFlowBlockedData(
                                lastEvent.TimeStamp,
                                evt.TimeStamp - lastEvent.TimeStamp,
                                (QuicFlowBlockedFlags)_evt!.ReasonFlags));
                    }
                    lastEvent = evt;
                }
            }
            if (lastEvent != null)
            {
                var _evt = lastEvent as QuicConnectionOutFlowBlockedEvent;
                flowBlockedEvents.Add(
                    new QuicFlowBlockedData(
                        lastEvent.TimeStamp,
                        FinalTimeStamp - lastEvent.TimeStamp,
                        (QuicFlowBlockedFlags)_evt!.ReasonFlags));
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
                    (evt.EventId == QuicEventId.ConnScheduleState ||
                        evt.EventId == QuicEventId.ConnExecOper ||
                        evt.EventId == QuicEventId.ConnExecApiOper ||
                        evt.EventId == QuicEventId.ConnExecTimerOper))
                {
                    QuicExecutionType type = QuicExecutionType.Unknown;
                    switch (lastEvent.EventId)
                    {
                        case QuicEventId.ConnExecOper:
                            type = (lastEvent as QuicConnectionExecOperEvent)!.ExecutionType;
                            break;
                        case QuicEventId.ConnExecApiOper:
                            type = (lastEvent as QuicConnectionExecApiOperEvent)!.ExecutionType;
                            break;
                        case QuicEventId.ConnExecTimerOper:
                            type = (lastEvent as QuicConnectionExecTimerOperEvent)!.ExecutionType;
                            break;
                    }
                    execEvents.Add(
                        new QuicExecutionData(
                            lastEvent.TimeStamp,
                            lastEvent.ThreadId,
                            lastEvent.Processor,
                            evt.TimeStamp - lastEvent.TimeStamp,
                            type));
                }
                if (evt.EventId == QuicEventId.ConnScheduleState)
                {
                    lastEvent = null;
                }
                else if (evt.EventId == QuicEventId.ConnExecOper ||
                        evt.EventId == QuicEventId.ConnExecApiOper ||
                        evt.EventId == QuicEventId.ConnExecTimerOper)
                {
                    lastEvent = evt;
                }
            }
            return execEvents;
        }

        internal enum QuicSampleMode
        {
            Value,
            Diff,
            DiffTime,
            Drop
        }

        internal struct QuicRawTputSample
        {
            QuicRawTputData Data;
            ulong LastValue;
            bool LastValueSet;
            bool IncludeDuplicates;
            QuicSampleMode SampleMode;
            internal QuicRawTputSample(QuicTputDataType type, QuicSampleMode sampleMode = QuicSampleMode.Value, bool includeDuplicates = false)
            {
                Data = new QuicRawTputData() { Type = type };
                LastValue = 0;
                LastValueSet = false;
                IncludeDuplicates = includeDuplicates;
                SampleMode = sampleMode;
            }
            internal void Update(ulong NewValue, Timestamp NewTimestamp, ref List<QuicRawTputData> Events)
            {
                if (LastValueSet && NewValue == LastValue && !IncludeDuplicates) return;
                if (SampleMode == QuicSampleMode.Drop)
                {
                    if (NewValue > LastValue)
                    {
                        LastValue = NewValue;
                        return;
                    }
                }

                if (LastValueSet)
                {
                    Data.Duration = NewTimestamp - Data.TimeStamp;
                    Events.Add(Data);
                }

                Data.TimeStamp = NewTimestamp;
                if (SampleMode == QuicSampleMode.Value)
                {
                    Data.Value = NewValue;
                }
                else if (SampleMode == QuicSampleMode.Diff)
                {
                    Data.Value = NewValue - LastValue;
                }
                else if (SampleMode == QuicSampleMode.DiffTime)
                {
                    if (LastValueSet)
                    {
                        Data.Value = NewValue - LastValue;
                    }
                    else
                    {
                        Data.Value = 0;
                    }
                }
                else // QuicSampleMode.Drop
                {
                    Data.Value = LastValue - NewValue;
                }
                LastValue = NewValue;
                LastValueSet = true;
            }
            internal void Finalize(Timestamp FinalTimestamp, ref List<QuicRawTputData> Events)
            {
                if (LastValueSet)
                {
                    Data.Duration = FinalTimestamp - Data.TimeStamp;
                    Events.Add(Data);
                }
            }
        }

        public IReadOnlyList<QuicRawTputData> GetRawTputEvents()
        {
            if (Events.Count == 0) return new List<QuicRawTputData>();

            var tx = new QuicRawTputSample(QuicTputDataType.Tx, QuicSampleMode.Value, true);
            var pktCreate = new QuicRawTputSample(QuicTputDataType.PktCreate, QuicSampleMode.Diff, true);
            var txAck = new QuicRawTputSample(QuicTputDataType.TxAck, QuicSampleMode.Drop, true);
            var txDelay = new QuicRawTputSample(QuicTputDataType.TxDelay, QuicSampleMode.DiffTime, true);
            var rx = new QuicRawTputSample(QuicTputDataType.Rx, QuicSampleMode.Diff, true);
            var rtt = new QuicRawTputSample(QuicTputDataType.Rtt);
            var inFlight = new QuicRawTputSample(QuicTputDataType.InFlight);
            var cwnd = new QuicRawTputSample(QuicTputDataType.CWnd);
            var posted = new QuicRawTputSample(QuicTputDataType.Bufferred);
            var connFC = new QuicRawTputSample(QuicTputDataType.ConnFC);
            var streamFC = new QuicRawTputSample(QuicTputDataType.StreamFC);

            var tputEvents = new List<QuicRawTputData>();
            foreach (var evt in Events)
            {
                if (evt.EventId == QuicEventId.ConnOutFlowStats)
                {
                    var _evt = evt as QuicConnectionOutFlowStatsEvent;
                    pktCreate.Update(_evt!.BytesSent, evt.TimeStamp, ref tputEvents);
                    txAck.Update(_evt!.BytesInFlight, evt.TimeStamp, ref tputEvents);
                    rtt.Update(_evt!.SmoothedRtt, evt.TimeStamp, ref tputEvents);
                    inFlight.Update(_evt!.BytesInFlight, evt.TimeStamp, ref tputEvents);
                    cwnd.Update(_evt!.CongestionWindow, evt.TimeStamp, ref tputEvents);
                    posted.Update(_evt!.PostedBytes, evt.TimeStamp, ref tputEvents);
                    connFC.Update(_evt!.ConnectionFlowControl, evt.TimeStamp, ref tputEvents);
                }
                else if (evt.EventId == QuicEventId.ConnInFlowStats)
                {
                    var _evt = evt as QuicConnectionInFlowStatsEvent;
                    rx.Update(_evt!.BytesRecv, evt.TimeStamp, ref tputEvents);
                }
                else if (evt.EventId == QuicEventId.ConnOutFlowStreamStats)
                {
                    var _evt = evt as QuicConnectionOutFlowStreamStatsEvent;
                    streamFC.Update(_evt!.StreamFlowControl, evt.TimeStamp, ref tputEvents);
                }
                else if (evt.EventId == QuicEventId.DatapathSend)
                {
                    var _evt = evt as QuicDatapathSendEvent;
                    tx.Update(_evt!.TotalSize, evt.TimeStamp, ref tputEvents);
                    txDelay.Update((ulong)evt.TimeStamp.ToMicroseconds, evt.TimeStamp, ref tputEvents);
                }
            }

            var FinalTimeStamp = Events[Events.Count - 1].TimeStamp;

            tx.Finalize(FinalTimeStamp, ref tputEvents);
            pktCreate.Finalize(FinalTimeStamp, ref tputEvents);
            txAck.Finalize(FinalTimeStamp, ref tputEvents);
            txDelay.Finalize(FinalTimeStamp, ref tputEvents);
            rx.Finalize(FinalTimeStamp, ref tputEvents);
            rtt.Finalize(FinalTimeStamp, ref tputEvents);
            inFlight.Finalize(FinalTimeStamp, ref tputEvents);
            cwnd.Finalize(FinalTimeStamp, ref tputEvents);
            posted.Finalize(FinalTimeStamp, ref tputEvents);
            connFC.Finalize(FinalTimeStamp, ref tputEvents);
            streamFC.Finalize(FinalTimeStamp, ref tputEvents);

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
            LastScheduleStateTimeStamp = Timestamp.MinValue;
        }

        private void TrySetWorker(QuicEvent evt, QuicState state)
        {
            if (Worker == null)
            {
                Worker = state.GetWorkerFromThread(evt.ProcessId, evt.ThreadId);
                Worker?.OnConnectionAdded();
            }
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            if (InitialTimeStamp == Timestamp.MaxValue)
            {
                InitialTimeStamp = evt.TimeStamp;
            }

            switch (evt.EventId)
            {
                case QuicEventId.ConnCreated:
                case QuicEventId.ConnRundown:
                    {
                        var _evt = evt as QuicConnectionCreatedEvent;
                        CorrelationId = _evt!.CorrelationId;
                        State = QuicConnectionState.Allocated;
                        IsServer = _evt!.IsServer != 0;
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
                        var _evt = evt as QuicConnectionScheduleStateEvent;
                        if (_evt!.ScheduleState == QuicScheduleState.Processing)
                        {
                            TrySetWorker(evt, state);
                        }
                        if (LastScheduleStateTimeStamp != Timestamp.MinValue)
                        {
                            Worker?.AddSchedulingCpuTime(_evt!.ScheduleState, _evt.TimeStamp - LastScheduleStateTimeStamp);
                        }
                        LastScheduleStateTimeStamp = _evt.TimeStamp;
                        break;
                    }
                case QuicEventId.ConnExecOper:
                case QuicEventId.ConnExecApiOper:
                case QuicEventId.ConnExecTimerOper:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionExec;
                        TrySetWorker(evt, state);
                        break;
                    }
                case QuicEventId.ConnAssignWorker:
                    {
                        Worker?.OnConnectionRemoved();
                        var _evt = evt as QuicConnectionAssignWorkerEvent;
                        var key = new QuicObjectKey(evt.PointerSize, _evt!.WorkerPointer, evt.ProcessId);
                        Worker = state.FindOrCreateWorker(key);
                        Worker.OnConnectionAdded();
                        break;
                    }
                case QuicEventId.ConnTransportShutdown:
                    {
                        var _evt = evt as QuicConnectionTransportShutdownEvent;
                        State = QuicConnectionState.Shutdown;
                        IsAppShutdown = false;
                        IsShutdownRemote = _evt!.IsRemoteShutdown != 0;
                        ShutdownTimeStamp = evt.TimeStamp;
                        break;
                    }
                case QuicEventId.ConnAppShutdown:
                    {
                        var _evt = evt as QuicConnectionAppShutdownEvent;
                        State = QuicConnectionState.Shutdown;
                        IsAppShutdown = true;
                        IsShutdownRemote = _evt!.IsRemoteShutdown != 0;
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
                        var _evt = evt as QuicConnectionOutFlowStatsEvent;
                        BytesSent = _evt!.BytesSent;
                        TrySetWorker(evt, state);
                        break;
                    }
                case QuicEventId.ConnOutFlowBlocked:
                    {
                        var _evt = evt as QuicConnectionOutFlowBlockedEvent;
                        if (_evt!.ReasonFlags != 0)
                        {
                            state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionFlowBlocked;
                        }
                        break;
                    }
                case QuicEventId.ConnInFlowStats:
                    {
                        var _evt = evt as QuicConnectionInFlowStatsEvent;
                        BytesReceived = _evt!.BytesRecv;
                        TrySetWorker(evt, state);
                        break;
                    }
                case QuicEventId.ConnStats:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.ConnectionTput;
                        var _evt = evt as QuicConnectionStatsEvent;
                        BytesSent = _evt!.SendTotalBytes;
                        BytesReceived = _evt!.RecvTotalBytes;
                        break;
                    }
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            Worker?.OnConnectionEvent(this, evt);

            Events.Add(evt);
        }

        internal void OnStreamAdded(QuicStream stream)
        {
            Streams.Add(stream);
        }
    }
}
