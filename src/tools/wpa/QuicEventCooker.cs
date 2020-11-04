//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Threading;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;
using MsQuicTracing.DataModel;

namespace MsQuicTracing
{
    public sealed class QuicEventCooker : CookedDataReflector, ISourceDataCooker<QuicEventBase, object, Guid>
    {
        public const string CookerId = "QUIC";

        public static readonly DataCookerPath CookerPath = new DataCookerPath(QuicEventParser.SourceId, CookerId);

        public ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>());

        public DataCookerPath Path { get; }

        public IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public DataProductionStrategy DataProductionStrategy { get; }

        public string Description => "MsQuic Event Cooker";

        public SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        [DataOutput]
        public IReadOnlyDictionary<ushort, ulong> EventCounts => new ReadOnlyDictionary<ushort, ulong>(eventCounts);

        public QuicEventCooker() : this(CookerPath)
        {
        }

        private QuicEventCooker(DataCookerPath path) : base(path)
        {
            Path = path;
        }

        public void BeginDataCooking(ICookedDataRetrieval dependencyRetrieval, CancellationToken cancellationToken)
        {
        }

        public void EndDataCooking(CancellationToken cancellationToken)
        {
        }

        private readonly Dictionary<ushort, ulong> eventCounts = new Dictionary<ushort, ulong>();

        public DataProcessingResult CookDataElement(QuicEventBase data, object context, CancellationToken cancellationToken)
        {
            Debug.Assert(!(data is null));

            if (!eventCounts.ContainsKey(data.ID))
            {
                eventCounts.Add(data.ID, 1);
            }
            else
            {
                eventCounts[data.ID]++;
            }

            return DataProcessingResult.Processed;
        }
    }
}
