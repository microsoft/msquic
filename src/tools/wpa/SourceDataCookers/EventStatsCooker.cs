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

namespace MsQuicEtw.SourceDataCookers
{
    public sealed class EventStatsCooker : BaseSourceCooker
    {
        private static Guid MsQuicEtwGuid = new Guid("ff15e657-4f26-570e-88ab-0796b258d11c");

        public const string CookerId = "QuicEventStats";
        public static readonly DataCookerPath CookerPath = new DataCookerPath(QuicEventSourceParser.SourceId, CookerId);

        private readonly Dictionary<ushort, ulong> eventCounts;

        [DataOutput]
        public IReadOnlyDictionary<ushort, ulong> QuicEventCounts => new ReadOnlyDictionary<ushort, ulong>(this.eventCounts);

        public override ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>(new Guid[] { MsQuicEtwGuid }));

        public override string Description => "Quic Event Stats";

        public override SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        public EventStatsCooker() : base(CookerId)
        {
            this.eventCounts = new Dictionary<ushort, ulong>();
        }

        public override DataProcessingResult CookDataElement(ETWTraceEvent data, IQuicEventContext context, CancellationToken cancellationToken)
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
