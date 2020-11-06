//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using Microsoft.Performance.SDK;

namespace MsQuicTracing.DataModel
{
    public readonly struct QuicActivityData
    {
        public Timestamp TimeStamp { get; }

        public TimestampDelta Duration { get; }

        internal QuicActivityData(Timestamp timeStamp, TimestampDelta duration)
        {
            TimeStamp = timeStamp;
            Duration = duration;
        }
    }

    public readonly struct QuicExecutionData
    {
        public Timestamp TimeStamp { get; }

        public uint ThreadId { get; }

        public ushort Processor { get; }

        public TimestampDelta Duration { get; }

        public QuicExecutionType Type { get; }

        internal QuicExecutionData(Timestamp timeStamp, uint threadId, ushort procesor, TimestampDelta duration, QuicExecutionType type)
        {
            TimeStamp = timeStamp;
            ThreadId = threadId;
            Processor = procesor;
            Duration = duration;
            Type = type;
        }
    }

    public readonly struct QuicFlowBlockedData
    {
        public Timestamp TimeStamp { get; }

        public QuicFlowBlockedFlags Flags { get; }

        internal QuicFlowBlockedData(Timestamp timeStamp, QuicFlowBlockedFlags flags)
        {
            TimeStamp = timeStamp;
            Flags = flags;
        }
    }

    public readonly struct QuicScheduleData
    {
        public Timestamp TimeStamp { get; }

        public TimestampDelta Duration { get; }

        public uint ThreadId { get; }

        public QuicScheduleState State { get; }

        internal QuicScheduleData(Timestamp timeStamp, TimestampDelta duration, uint threadId, QuicScheduleState state)
        {
            TimeStamp = timeStamp;
            Duration = duration;
            ThreadId = threadId;
            State = state;
        }
    }

    public struct QuicThroughputData
    {
        public Timestamp TimeStamp { get; internal set; }

        public TimestampDelta Duration { get; internal set; }

        public uint RttUs { get; internal set; }

        public ulong TxRate { get; internal set; } // bps

        public ulong RxRate { get; internal set; } // bps

        public ulong BytesSent { get; internal set; }

        public ulong BytesReceived { get; internal set; }

        public uint CongestionEvents { get; internal set; }

        public ulong BytesInFlight { get; internal set; }

        public uint CongestionWindow { get; internal set; }

        public ulong BytesBufferedForSend { get; internal set; }

        public ulong FlowControlAvailable { get; internal set; }

        public ulong StreamFlowControlAvailable { get; internal set; }
    }
}
