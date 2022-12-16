//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;
using QuicTrace.DataModel;

namespace QuicTrace.Cookers
{
    public abstract class BaseEventCooker<T, TContext, TKey> : CookedDataReflector, ISourceDataCooker<T, TContext, TKey> where T : IKeyedDataType<TKey>
    {
        public ReadOnlyHashSet<TKey> DataKeys => new ReadOnlyHashSet<TKey>(new HashSet<TKey>());

        public virtual DataCookerPath Path { get; }

        public virtual string Description => "MsQuic Base Event Cooker";

        public IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public DataProductionStrategy DataProductionStrategy { get; }

        public SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        [DataOutput]
        public QuicState State { get; } = new QuicState();

        public BaseEventCooker(DataCookerPath dataCookerPath) : base(dataCookerPath)
        {
            Path = dataCookerPath;
        }

        public void BeginDataCooking(ICookedDataRetrieval dependencyRetrieval, CancellationToken cancellationToken) { }
        public virtual DataProcessingResult CookDataElement(T data, TContext context, CancellationToken cancellationToken) => throw new NotImplementedException();
        public void EndDataCooking(CancellationToken cancellationToken)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                State.OnTraceComplete();
            }
        }
    }
}
