//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Diagnostics;
using System.Threading;
using Microsoft.Performance.SDK.Extensibility;
using QuicTrace.DataModel;

namespace QuicTrace.Cookers
{
    public sealed class QuicEtwEventCooker : BaseEventCooker<QuicEvent, object, Guid>
    {
        public static readonly DataCookerPath CookerPath = DataCookerPath.ForSource(QuicEventParser.SourceId, "QUIC");
        public override string Description => "MsQuic ETW Event Cooker";

        public QuicEtwEventCooker() : base(CookerPath)
        {
        }

        public override DataProcessingResult CookDataElement(QuicEvent data, object context, CancellationToken cancellationToken)
        {
            Debug.Assert(!(data is null));
            State.AddEvent(data);
            return DataProcessingResult.Processed;
        }
    }
}
