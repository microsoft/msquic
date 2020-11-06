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
}
