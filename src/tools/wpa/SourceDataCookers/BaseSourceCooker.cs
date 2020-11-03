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

namespace QuicEventDataSource.SourceDataCookers
{
    public abstract class BaseSourceCooker : CookedDataReflector, ISourceDataCooker<ETWTraceEvent, IQuicEventContext, Guid>
    {
        protected BaseSourceCooker(string cookerID) : this(new DataCookerPath(QuicEventSourceParser.SourceId, cookerID))
        {
        }

        private BaseSourceCooker(DataCookerPath path) : base(path)
        {
            this.Path = path;
        }

        public abstract ReadOnlyHashSet<Guid> DataKeys { get; }

        public virtual SourceDataCookerOptions Options => SourceDataCookerOptions.None;

        public abstract string Description { get; }

        public virtual DataCookerPath Path { get; }

        public virtual IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public virtual IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public virtual DataProductionStrategy DataProductionStrategy { get; }

        public virtual void BeginDataCooking(ICookedDataRetrieval dataRetrieval, CancellationToken cancellationToken)
        {
        }

        public abstract DataProcessingResult CookDataElement(ETWTraceEvent data, IQuicEventContext context, CancellationToken cancellationToken);

        public virtual void EndDataCooking(CancellationToken cancellationToken)
        {
        }
    }
}
