//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;
using QuicTrace.DataModel;

namespace QuicTrace
{
    public sealed class QuicEventCooker : CookedDataReflector, ISourceDataCooker<QuicEvent, object, Guid>
    {
        public static readonly DataCookerPath CookerPath = DataCookerPath.ForSource(QuicEventParser.SourceId, "QUIC");

        public ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>());

        public DataCookerPath Path => CookerPath;

        public string Description => "MsQuic Event Cooker";

        public IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public DataProductionStrategy DataProductionStrategy { get; }

        public SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        [DataOutput]
        public QuicState State { get; } = new QuicState();

        public QuicEventCooker() : base(CookerPath)
        {
        }

        public void BeginDataCooking(ICookedDataRetrieval dependencyRetrieval, CancellationToken cancellationToken)
        {
        }

        public DataProcessingResult CookDataElement(QuicEvent data, object context, CancellationToken cancellationToken)
        {
            Debug.Assert(!(data is null));
            State.AddEvent(data);
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
