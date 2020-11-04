//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;

namespace MsQuicTracing.SourceDataCookers
{
    public sealed class QuicDataCooker : CookedDataReflector, ISourceDataCooker<ETWTraceEvent, ETWTraceEventSource, Guid>
    {
        public const string CookerId = "QUIC";

        public static readonly DataCookerPath CookerPath = new DataCookerPath(QuicSourceParser.SourceId, CookerId);

        public ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>(new Guid[] { new Guid("ff15e657-4f26-570e-88ab-0796b258d11c") }));

        public DataCookerPath Path { get; }

        public IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public DataProductionStrategy DataProductionStrategy { get; }

        public string Description => "QUIC Events";

        public SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        [DataOutput]
        public IReadOnlyDictionary<ushort, ulong> EventCounts => new ReadOnlyDictionary<ushort, ulong>(this.eventCounts);

        public QuicDataCooker() : this(CookerPath)
        {
        }

        private QuicDataCooker(DataCookerPath path) : base(path)
        {
            this.Path = path;
        }

        public void BeginDataCooking(ICookedDataRetrieval dependencyRetrieval, CancellationToken cancellationToken)
        {
        }

        public void EndDataCooking(CancellationToken cancellationToken)
        {
        }

        private readonly Dictionary<ushort, ulong> eventCounts = new Dictionary<ushort, ulong>();

        public DataProcessingResult CookDataElement(ETWTraceEvent data, ETWTraceEventSource context, CancellationToken cancellationToken)
        {
            if (!this.eventCounts.ContainsKey((ushort)data.Event.ID))
            {
                this.eventCounts.Add((ushort)data.Event.ID, 1);
            }
            else
            {
                this.eventCounts[(ushort)data.Event.ID]++;
            }

            return DataProcessingResult.Processed;
        }
    }
}
