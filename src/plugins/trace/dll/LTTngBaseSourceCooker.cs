// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System.Collections.Generic;
using System.Threading;
using LTTngCds.CookerData;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;

namespace QuicTrace
{
    public abstract class LTTngBaseSourceCooker
        : CookedDataReflector,
          ISourceDataCooker<LTTngEvent, LTTngContext, string>
    {
        private static readonly HashSet<string> emptyDataKeys = new HashSet<string>();
        protected static readonly ReadOnlyHashSet<string> EmptyDataKeys = new ReadOnlyHashSet<string>(emptyDataKeys);

        protected LTTngBaseSourceCooker(string cookerId)
        : this(DataCookerPath.ForSource(LTTngConstants.SourceId, cookerId))
        //: this(DataCookerPath.ForSource("QUIC", cookerId))
        {
        }

        protected LTTngBaseSourceCooker(DataCookerPath dataCookerPath)
            : base(dataCookerPath)
        {
            this.Path = dataCookerPath;
        }

        protected long computeTime = 0;

        /// <summary>
        /// All source data cookers that inherit from this reference the LTTng source parser.
        /// </summary>
        public string SourceParserId => Path.SourceParserId;

        /// <summary>
        /// The data cooker identifier.
        /// </summary>
        public string DataCookerId => Path.DataCookerId;

        /// <summary>
        /// Combines the SourceId and the cooker Id.
        /// </summary>
        public virtual DataCookerPath Path { get; }

        /// <summary>
        /// No additional options by default.
        /// </summary>
        public virtual SourceDataCookerOptions Options => SourceDataCookerOptions.None;

        /// <summary>
        /// Default to no dependencies.
        /// </summary>
        public virtual IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        /// <summary>
        /// Default consumption types - by default.
        /// </summary>
        public virtual IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public abstract string Description { get; }

        public virtual DataProductionStrategy DataProductionStrategy { get; }

        public abstract ReadOnlyHashSet<string> DataKeys { get; }

        public virtual void BeginDataCooking(ICookedDataRetrieval dependencyRetrieval, CancellationToken cancellationToken)
        {

        }

        public virtual void EndDataCooking(CancellationToken cancellationToken)
        {
        }

        public abstract DataProcessingResult CookDataElement(
            LTTngEvent data,
            LTTngContext context,
            CancellationToken cancellationToken);
    }
}
