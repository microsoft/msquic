//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK.Extensibility;

namespace MsQuicTracing
{
    public struct ETWTraceEvent : IKeyedDataType<Guid>
    {
        public TraceEvent Event { get; private set; }

        public ETWTraceEvent(TraceEvent evt)
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
