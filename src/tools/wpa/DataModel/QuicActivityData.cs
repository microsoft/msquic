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
}
