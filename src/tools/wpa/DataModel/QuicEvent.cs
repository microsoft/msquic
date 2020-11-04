//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK.Extensibility;

namespace MsQuicTracing.DataModel
{
    public readonly struct QuicEvent : IKeyedDataType<Guid>
    {
        public TraceEvent Event { get; }

        public QuicEvent(TraceEvent evt)
        {
            Event = evt;
        }

        public int CompareTo(Guid other)
        {
            return this.Event.ProviderGuid.CompareTo(other);
        }

        public Guid GetKey() => this.Event.ProviderGuid;
    }
}
