//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK.Extensibility;

namespace MsQuicTracing.DataModel
{
    public class QuicEtwEvent : QuicEventBase
    {
        public TraceEvent Event { get; set; }

        public override Guid Provider => Event.ProviderGuid;

        public override ushort ID => (ushort)Event.ID;

        public QuicEtwEvent(TraceEvent evt)
        {
            Event = evt;
        }
    }
}
