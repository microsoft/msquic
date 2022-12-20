//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using LTTngCds.CookerData;
using Microsoft.Performance.SDK.Extensibility;
using System.Threading;
using QuicTrace.DataModel.LTTng;
using System.Diagnostics;

namespace QuicTrace.Cookers
{
    public sealed class QuicLTTngEventCooker : BaseEventCooker<LTTngEvent, LTTngContext, string>
    {
        public static readonly DataCookerPath CookerPath = DataCookerPath.ForSource(LTTngConstants.SourceId, "QUIC");
        public override string Description => "MsQuic Event Cooker";

        public QuicLTTngEventCooker() : base(CookerPath)
        {
        }

        public override DataProcessingResult CookDataElement(
            LTTngEvent data,
            LTTngContext context,
            CancellationToken cancellationToken)
        {
            Debug.Assert(!(data is null));
            var evt = QuicLTTngEvent.TryCreate(data, context);
            if (evt != null)
            {
                State.AddEvent(evt);
            }

            return DataProcessingResult.Processed;
        }
    }
}
