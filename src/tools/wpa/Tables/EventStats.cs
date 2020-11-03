//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Processing;
using System;
using System.Collections.Generic;
using System.Linq;
using QuicEventDataSource.SourceDataCookers;

namespace QuicEventDataSource.Tables
{
    [Table]
    public sealed class EventStats
    {
        public static TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{EE2FA823-C447-4324-969C-BC8AE215B713}"),
           "Event Stats",
           "Event Stats for ETL",
           category: "Stats",
           requiredDataCookers: new List<DataCookerPath> { EventStatsCooker.CookerPath });

        private static readonly ColumnConfiguration providerIDColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{7C382588-735D-4450-91A5-F4DF6BD4E42A}"), "Provider ID"),
                new UIHints { Width = 80, });

        private static readonly ColumnConfiguration eventCountColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{54B42F78-B2E2-49B0-B5D1-F066399908DB}"), "Event Count"),
                new UIHints { Width = 80, });

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            var eventInfo = tableData.QueryOutput<IReadOnlyDictionary<Guid, ulong>>(
                new DataOutputPath(EventStatsCooker.CookerPath, "EventCounts"));

            if (eventInfo == null)
            {
                // no process data elements were processed by the data cooker
                return;
            }

            if (eventInfo.Count == 0)
            {
                return;
            }

            var table = tableBuilder.SetRowCount(eventInfo.Count);
            var keyValuePair = Projection.Index(eventInfo.ToList());

            var guidProjector = keyValuePair.Compose(x => x.Key);
            var countProjector = keyValuePair.Compose(x => x.Value);

            table.AddColumn(providerIDColumnConfig, guidProjector);
            table.AddColumn(eventCountColumnConfig, countProjector);
        }

    }
}
