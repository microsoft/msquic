//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

namespace MsQuicTracing.DataModel
{
    public readonly struct QuicActivityData
    {
        public ulong TimeStamp { get; }

        public ulong Duration { get; }

        internal QuicActivityData(ulong timeStamp, ulong duration)
        {
            TimeStamp = timeStamp;
            Duration = duration;
        }
    }
}
