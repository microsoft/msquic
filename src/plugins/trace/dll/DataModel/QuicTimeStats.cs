//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public sealed class QuicTimeStats
    {
        public uint Count { get; private set; }

        public uint MinCpuTimeUs { get; private set; }

        public uint MaxCpuTimeUs { get; private set; }

        public ulong TotalCpuTimeUs { get; private set; }

        public uint AverageCpuTimeUs
        {
            get { return Count == 0 ? 0 : (uint)(TotalCpuTimeUs / Count); }
        }

        internal QuicTimeStats()
        {
            Count = 0;
            MinCpuTimeUs = uint.MaxValue;
            MaxCpuTimeUs = 0;
            TotalCpuTimeUs = 0;
        }

        internal void AddCpuTime(uint cpuTimeUs)
        {
            Count++;
            TotalCpuTimeUs += (ulong)cpuTimeUs;
            if (cpuTimeUs < MinCpuTimeUs)
            {
                MinCpuTimeUs = cpuTimeUs;
            }
            if (cpuTimeUs > MaxCpuTimeUs)
            {
                MaxCpuTimeUs = cpuTimeUs;
            }
        }

        internal void AddCpuTime(TimestampDelta delta)
        {
            AddCpuTime((uint)delta.ToMicroseconds);
        }
    }

    public sealed class QuicSchedulingStats
    {
        readonly QuicTimeStats[] Stats = new QuicTimeStats[(int)QuicScheduleState.Max];

        internal QuicSchedulingStats()
        {
            for (var i = 0; i < (int)QuicScheduleState.Max; ++i)
            {
                Stats[i] = new QuicTimeStats();
            }
        }

        internal void AddCpuTime(QuicScheduleState state, TimestampDelta delta)
        {
            Stats[(int)state].AddCpuTime(delta);
        }

        public QuicTimeStats GetStats(QuicScheduleState state)
        {
            return Stats[(int)state];
        }
    }
}
