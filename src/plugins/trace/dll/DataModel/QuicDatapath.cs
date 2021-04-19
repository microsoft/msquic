//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public sealed class QuicDatapath : IQuicObject
    {
        public static QuicDatapath New(ulong pointer, uint processId) => new QuicDatapath(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.DatapathCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.DatapathDestroyed;

        public ulong Id { get; }

        private static ulong NextId = 1;

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public ulong BytesSent { get; private set; }

        public ulong BytesReceived { get; private set; }

        public ulong SendEventCount { get; private set; }

        public ulong ReceiveEventCount { get; private set; }

        public double AverageSendBatchSize => BytesSent / (double)SendEventCount;

        public double AverageReceiveBatchSize => BytesReceived / (double)ReceiveEventCount;

        private readonly List<QuicEvent> Events = new List<QuicEvent>();

        internal QuicDatapath(ulong pointer, uint processId)
        {
            Id = NextId++;
            Pointer = pointer;
            ProcessId = processId;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            switch (evt.EventId)
            {
                case QuicEventId.DatapathSend:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.Datapath;
                        var _evt = evt as QuicDatapathSendEvent;
                        BytesSent += _evt!.TotalSize;
                        SendEventCount++;

                        var worker = state.GetWorkerFromThread(evt.ProcessId, evt.ThreadId);
                        if (worker != null && worker.LastConnection != null)
                        {
                            worker.LastConnection.AddEvent(evt, state);
                        }
                        break;
                    }
                case QuicEventId.DatapathRecv:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.Datapath;
                        var _evt = evt as QuicDatapathRecvEvent;
                        BytesReceived += _evt!.TotalSize;
                        ReceiveEventCount++;
                        break;
                    }
                default:
                    break;
            }

            Events.Add(evt);
        }
    }
}
