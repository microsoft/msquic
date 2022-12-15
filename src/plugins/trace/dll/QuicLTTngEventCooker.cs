using System;
using System.Collections.Generic;
using System.Text;
using CtfPlayback;
using LTTngCds.CookerData;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Processing;
using Microsoft.Performance.SDK;
using System.Threading;
using QuicTrace.DataModel;
using Dia2Lib;
using QuicTrace.DataModel.ETW;
using System.Diagnostics;

namespace QuicTrace
{
    public class LTTngGenericEventDataCooker : LTTngBaseSourceCooker
    {
        public const string Identifier = "QUIC";

        public override string Description => "All events reported in the source.";

        public LTTngGenericEventDataCooker()
            : base(Identifier)
        {
            //this.Events = new ProcessedEventData<LTTngGenericEvent>();
        }

        /// <summary>
        /// No specific data keys for generic events, rather, the ReceiveAllEvents option is set.
        /// </summary>
        public override ReadOnlyHashSet<string> DataKeys => EmptyDataKeys;

        /// <summary>
        /// This data cooker receives all data elements.
        /// </summary>
        public override SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        [DataOutput]
        public QuicState State { get; } = new QuicState();

        public override DataProcessingResult CookDataElement(
            LTTngEvent data,
            LTTngContext context,
            CancellationToken cancellationToken)
        {

            Debug.Assert(!(data is null));
            var evt = QuicEtwEvent.TryCreate(data);
            if (evt != null)
            {
                State.AddEvent(evt);
            }

            return DataProcessingResult.Processed;
        }

        public override void EndDataCooking(CancellationToken cancellationToken)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                State.OnTraceComplete();
            }
        }
    }
}
