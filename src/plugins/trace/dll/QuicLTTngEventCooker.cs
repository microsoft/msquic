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
    public sealed class QuicLTTngEventCooker : CookedDataReflector, ISourceDataCooker<LTTngEvent, LTTngContext, string>
    {
        public static readonly DataCookerPath CookerPath = DataCookerPath.ForSource(LTTngConstants.SourceId, "QUIC");

        public ReadOnlyHashSet<string> DataKeys => new ReadOnlyHashSet<string>(new HashSet<string>());

        public DataCookerPath Path => CookerPath;

        public string Description => "MsQuic Event Cooker";

        public IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public DataProductionStrategy DataProductionStrategy { get; }

        public SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        [DataOutput]
        public QuicState State { get; } = new QuicState();

        public QuicLTTngEventCooker() : base(CookerPath)
        {
        }

        public void BeginDataCooking(ICookedDataRetrieval dependencyRetrieval, CancellationToken cancellationToken)
        {
        }

        public DataProcessingResult CookDataElement(
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

        public void EndDataCooking(CancellationToken cancellationToken)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                State.OnTraceComplete();
            }
        }
    }
}
