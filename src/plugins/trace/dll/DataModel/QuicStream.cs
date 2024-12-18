//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public sealed class QuicStream : IQuicObject
    {
        public static QuicStream New(ulong pointer, uint processId) => new QuicStream(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.StreamAlloc;

        public static ushort DestroyedEventId => (ushort)QuicEventId.StreamDestroyed;

        public ulong Id { get; }

        private static ulong NextId = 1;

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public ulong StreamId { get; private set; } = ulong.MaxValue;

        public Timestamp InitialTimeStamp { get; private set; }

        public Timestamp FinalTimeStamp { get; private set; }

        public QuicStreamTiming Timings { get; } = new QuicStreamTiming();

        public QuicConnection? Connection { get; private set; }

        private readonly List<QuicEvent> Events = new List<QuicEvent>();

        public IReadOnlyList<QuicFlowBlockedData> GetFlowBlockedEvents()
        {
            var flowBlockedEvents = new List<QuicFlowBlockedData>();
            QuicEvent? lastEvent = null;
            foreach (var evt in Events)
            {
                if (evt.EventId == QuicEventId.StreamOutFlowBlocked)
                {
                    if (lastEvent != null)
                    {
                        var _evt = lastEvent as QuicStreamOutFlowBlockedEvent;
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
                var _evt = lastEvent as QuicStreamOutFlowBlockedEvent;
                flowBlockedEvents.Add(
                    new QuicFlowBlockedData(
                        lastEvent.TimeStamp,
                        FinalTimeStamp - lastEvent.TimeStamp,
                        (QuicFlowBlockedFlags)_evt!.ReasonFlags));
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
                Timings.InitialStateTime = evt.TimeStamp;
                Timings.LastStateChangeTime = evt.TimeStamp;
            }

            switch (evt.EventId)
            {
                case QuicEventId.StreamCreated:
                case QuicEventId.StreamRundown:
                    {
                        var _evt = evt as QuicStreamCreatedEvent;
                        StreamId = _evt!.StreamID;
                        Timings.IsServer = _evt!.IsLocalOwned == 0; // TODO - Rename to IsCreator?
                        if (Connection == null)
                        {
                            Connection = state.FindOrCreateConnection(new QuicObjectKey(evt.PointerSize, _evt!.Connection, evt.ProcessId));
                            Connection.OnStreamAdded(this);
                        }
                    }
                    break;
                case QuicEventId.StreamDestroyed:
                    Timings.FinalizeState(evt.TimeStamp);
                    break;
                case QuicEventId.StreamOutFlowBlocked:
                    state.DataAvailableFlags |= QuicDataAvailableFlags.StreamFlowBlocked;
                    break;
                case QuicEventId.StreamSendState:
                    {
                        var sendState = (evt as QuicStreamSendStateEvent)!.SendState;
                        if (sendState == QuicSendState.Disabled || sendState == QuicSendState.FinAcked || sendState == QuicSendState.ResetAcked || sendState == QuicSendState.ReliableResetAcked)
                        {
                            Timings.SendShutdown = true;
                            if (Timings.RecvShutdown && Timings.State == QuicStreamState.IdleBoth)
                            {
                                Timings.UpdateToIdle(evt.TimeStamp);
                            }
                        }
                    }
                    break;
                case QuicEventId.StreamRecvState:
                    {
                        var recvState = (evt as QuicStreamRecvStateEvent)!.ReceiveState;
                        if (recvState == QuicReceiveState.Disabled || recvState == QuicReceiveState.Fin || recvState == QuicReceiveState.Reset || recvState == QuicReceiveState.ReliableReset)
                        {
                            Timings.RecvShutdown = true;
                            if (Timings.SendShutdown && Timings.State == QuicStreamState.IdleBoth)
                            {
                                Timings.UpdateToIdle(evt.TimeStamp);
                            }
                        }
                    }
                    break;
                case QuicEventId.StreamAlloc:
                    {
                        var _evt = evt as QuicStreamAllocEvent;
                        if (Connection == null)
                        {
                            Connection = state.FindOrCreateConnection(new QuicObjectKey(evt.PointerSize, _evt!.Connection, evt.ProcessId));
                            Connection.OnStreamAdded(this);
                        }
                    }
                    break;
                case QuicEventId.StreamWriteFrames:
                    {
                        var OldSendPacket = Timings.SendPacket;
                        Timings.SendPacket = state.SendPacketSet.FindActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamWriteFramesEvent)!.ID, evt.ProcessId));
                        if (Timings.SendPacket == null)
                        {
                            //Console.WriteLine("No SendPacket Error!");
                            Timings.EncounteredError = true;
                            break;
                        }

                        if (Timings.SendPacket != OldSendPacket)
                        {
                            if (Connection != null)
                            {
                                Timings.UpdateToState(QuicStreamState.ProcessSend, Connection.LastScheduleStateTimeStamp, true);
                            }
                            Timings.UpdateToState(QuicStreamState.Frame, Timings.SendPacket.PacketCreate);

                            if (Timings.SendPacket.PacketFirstWrite == Timestamp.Zero)
                            {
                                Timings.SendPacket.PacketFirstWrite = evt.TimeStamp;
                            }
                            else
                            {
                                foreach (var Stream in Timings.SendPacket.Streams)
                                {
                                    Stream.Timings.UpdateToState(QuicStreamState.WriteOther, evt.TimeStamp);
                                }
                                Timings.UpdateToState(QuicStreamState.WriteOther, Timings.SendPacket.PacketFirstWrite);
                            }

                            Timings.SendPacket.Streams.Add(this);
                        }

                        Timings.UpdateToState(QuicStreamState.Write, evt.TimeStamp);
                    }
                    break;
                case QuicEventId.StreamReceiveFrame:
                    {
                        var OldRecvPacket = Timings.RecvPacket;
                        Timings.RecvPacket = state.ReceivePacketSet.FindActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamReceiveFrameEvent)!.ID, evt.ProcessId));
                        if (Timings.RecvPacket == null)
                        {
                            //Console.WriteLine("No RecvPacket Error!");
                            Timings.EncounteredError = true;
                            break;
                        }

                        if (Timings.FirstPacketRecv == Timestamp.Zero)
                        {
                            Timings.FirstPacketRecv = Timings.RecvPacket.PacketReceive;
                        }

                        if (OldRecvPacket != Timings.RecvPacket)
                        {
                            Timings.UpdateToState(QuicStreamState.QueueRecv, Timings.RecvPacket.PacketReceive, true);
                            if (Connection != null)
                            {
                                Timings.UpdateToState(QuicStreamState.ProcessRecv, Connection.LastScheduleStateTimeStamp, true);
                            }
                            if (Timings.RecvPacket.PacketDecrypt != Timestamp.Zero) {
                                Timings.UpdateToState(QuicStreamState.Decrypt, Timings.RecvPacket.PacketDecrypt);

                                if (Timings.RecvPacket.PacketDecryptComplete == Timestamp.Zero)
                                {
                                    Timings.RecvPacket.PacketDecryptComplete = evt.TimeStamp;
                                }
                                else
                                {
                                    Timings.UpdateToState(QuicStreamState.ReadOther, Timings.RecvPacket.PacketDecryptComplete);
                                }
                            }
                        }

                        if (InitialTimeStamp > Timings.RecvPacket.PacketReceive && !Timings.IsAllocated)
                        {
                            // Stream was created after packet recieved
                            Timings.UpdateToState(QuicStreamState.Alloc, InitialTimeStamp);
                        }

                        if (FinalTimeStamp > Timings.LastStateChangeTime)
                        {
                            // Other events between Decrypt and StreamReceiveFrame
                            Timings.UpdateToState(QuicStreamState.ProcessRecv, FinalTimeStamp);
                        }

                        Timings.UpdateToState(QuicStreamState.Read, evt.TimeStamp);
                    }
                    break;
                case QuicEventId.StreamAppSend:
                    if (Connection?.SchedulingState == QuicScheduleState.Processing)
                    {
                        Timings.UpdateToState(QuicStreamState.ProcessSend, evt.TimeStamp);
                    }
                    else
                    {
                        Timings.UpdateToState(QuicStreamState.QueueSend, evt.TimeStamp);
                    }
                    break;
                case QuicEventId.StreamReceiveFrameComplete:
                    if (Timings.InAppRecv)
                    {
                        Timings.UpdateToState(QuicStreamState.AppRecv, evt.TimeStamp);
                    }
                    else
                    {
                        Timings.UpdateToIdle(evt.TimeStamp);
                    }
                    break;
                case QuicEventId.StreamAppReceive:
                    Timings.InAppRecv = true;
                    Timings.UpdateToState(QuicStreamState.AppRecv, evt.TimeStamp);
                    Timings.AppRecvCompletion = Timestamp.Zero;
                    break;
                case QuicEventId.StreamAppReceiveComplete:
                    Timings.InAppRecv = false;
                    if (Timings.State == QuicStreamState.AppRecv)
                    {
                        if (Timings.AppRecvCompletion != Timestamp.Zero)
                        {
                            Timings.UpdateToState(QuicStreamState.ProcessAppRecv, Timings.AppRecvCompletion);
                        }
                        Timings.UpdateToIdle(evt.TimeStamp);
                    }
                    Timings.AppRecvCompletion = Timestamp.Zero;
                    break;
                case QuicEventId.StreamAppReceiveCompleteCall:
                    Timings.AppRecvCompletion = evt.TimeStamp;
                    break;
                default:
                    break;
            }

            FinalTimeStamp = evt.TimeStamp;

            Events.Add(evt);
        }
    }
}
