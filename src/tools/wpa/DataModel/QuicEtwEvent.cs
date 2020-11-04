//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Diagnostics.Tracing;

namespace MsQuicTracing.DataModel
{
    public class QuicEtwEvent : QuicEventBase
    {
#pragma warning disable CS8618
        public TraceEvent Event { get; set; }
#pragma warning restore CS8618

        public override Guid Provider => Event.ProviderGuid;

        public override ushort ID => (ushort)Event.ID;
    }
}
