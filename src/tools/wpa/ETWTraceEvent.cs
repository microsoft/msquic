//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK.Extensibility;

namespace MsQuicEtw
{
#pragma warning disable CA1036 // Override methods on comparable types
#pragma warning disable CA1815 // Override equals and operator equals on value types
    public struct ETWTraceEvent : IKeyedDataType<Guid>
#pragma warning restore CA1815 // Override equals and operator equals on value types
#pragma warning restore CA1036 // Override methods on comparable types
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
