//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;

namespace QuicEventDataSource.SourceDataCookers
{
    public sealed class EventStatsCooker
        : BaseSourceCooker
    {
        public const string CookerId = "EventStats";
        public static readonly DataCookerPath CookerPath = new DataCookerPath(QuicEventSourceParser.SourceId, CookerId);

        private readonly Dictionary<Guid, ulong> eventCounts;

        [DataOutput]
        public IReadOnlyDictionary<Guid, ulong> EventCounts => new ReadOnlyDictionary<Guid, ulong>(this.eventCounts);

        public override ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>());

        public override string Description => "Event Stats";

        public override SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        public EventStatsCooker()
            : base(CookerId)
        {
            this.eventCounts = new Dictionary<Guid, ulong>();
        }

        public override DataProcessingResult CookDataElement(ETWTraceEvent data, IQuicEventContext context, CancellationToken cancellationToken)
        {
            if (!this.eventCounts.ContainsKey(data.Event.ProviderGuid))
            {
                this.eventCounts.Add(data.Event.ProviderGuid, 1);
            }
            else
            {
                this.eventCounts[data.Event.ProviderGuid]++;
            }

            return DataProcessingResult.Processed;
        }
    }
}
