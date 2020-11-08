//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace MsQuicTracing.DataModel
{
    public sealed class QuicDatapath : IQuicObject
    {
        public static QuicDatapath New(ulong pointer, uint processId) => new QuicDatapath(pointer, processId);

        public static ushort CreateEventId => (ushort)0; // None

        public static ushort DestroyedEventId => (ushort)0; // None

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

        public IReadOnlyList<QuicDatapathData> GetDatapathEvents(long resolutionNanoSec = 25 * 1000 * 1000) // 25 ms default
        {
            var Resolution = new TimestampDelta(resolutionNanoSec);

            int eventCount = Events.Count;
            int eventIndex = 0;

            var sample = new QuicDatapathData();
            var datapathEvents = new List<QuicDatapathData>();
            foreach (var evt in Events)
            {
                if (eventIndex == 0)
                {
                    sample.TimeStamp = evt.TimeStamp;
                }
                eventIndex++;

                if (evt.ID == QuicEventId.DatapathSend)
                {
                    var payload = evt.Payload as QuicDatapathSendPayload;
                    sample.BytesSent += payload!.TotalSize;
                    sample.SendEventCount++;
                }
                else if (evt.ID == QuicEventId.DatapathRecv)
                {
                    var payload = evt.Payload as QuicDatapathRecvPayload;
                    sample.BytesReceived += payload!.TotalSize;
                    sample.ReceiveEventCount++;
                }
                else
                {
                    continue;
                }

                if (sample.TimeStamp + Resolution <= evt.TimeStamp || eventIndex == eventCount)
                {
                    sample.Duration = evt.TimeStamp - sample.TimeStamp;
                    sample.TxRate = (sample.BytesSent * 8 * 1000 * 1000 * 1000) / (ulong)sample.Duration.ToNanoseconds;
                    sample.RxRate = (sample.BytesReceived * 8 * 1000 * 1000 * 1000) / (ulong)sample.Duration.ToNanoseconds;

                    datapathEvents.Add(sample);

                    sample.TimeStamp = evt.TimeStamp;
                    sample.BytesSent = 0;
                    sample.BytesReceived = 0;
                    sample.SendEventCount = 0;
                    sample.ReceiveEventCount = 0;
                }
            }
            return datapathEvents;
        }

        internal QuicDatapath(ulong pointer, uint processId)
        {
            Id = NextId++;
            Pointer = pointer;
            ProcessId = processId;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            switch (evt.ID)
            {
                case QuicEventId.DatapathSend:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.Datapath;
                        var payload = (evt.Payload as QuicDatapathSendPayload);
                        BytesSent += payload!.TotalSize;
                        SendEventCount++;
                        break;
                    }
                case QuicEventId.DatapathRecv:
                    {
                        state.DataAvailableFlags |= QuicDataAvailableFlags.Datapath;
                        var payload = (evt.Payload as QuicDatapathRecvPayload);
                        BytesReceived += payload!.TotalSize;
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
