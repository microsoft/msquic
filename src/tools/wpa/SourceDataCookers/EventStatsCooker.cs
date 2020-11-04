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
    public sealed class EventStatsCooker : CookedDataReflector, ISourceDataCooker<ETWTraceEvent, ETWTraceEventSource, Guid>
    {
        private static Guid MsQuicEtwGuid = new Guid("ff15e657-4f26-570e-88ab-0796b258d11c");

        public const string CookerId = "QuicEventStats";

        public static readonly DataCookerPath CookerPath = new DataCookerPath(QuicEventSourceParser.SourceId, CookerId);

        private readonly Dictionary<ushort, ulong> eventCounts = new Dictionary<ushort, ulong>();

        [DataOutput]
        public IReadOnlyDictionary<ushort, ulong> QuicEventCounts => new ReadOnlyDictionary<ushort, ulong>(this.eventCounts);

        public ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>(new Guid[] { MsQuicEtwGuid }));

        public DataCookerPath Path { get; }

        public IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public DataProductionStrategy DataProductionStrategy { get; }

        public string Description => "Quic Event Stats";

        public SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        public EventStatsCooker() : this(CookerPath)
        {
        }

        private EventStatsCooker(DataCookerPath path) : base(path)
        {
            this.Path = path;
        }

        public void BeginDataCooking(ICookedDataRetrieval dataRetrieval, CancellationToken cancellationToken)
        {
        }

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

        public void EndDataCooking(CancellationToken cancellationToken)
        {
        }
    }
}
