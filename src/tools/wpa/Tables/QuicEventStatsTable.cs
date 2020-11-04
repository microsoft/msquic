//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Processing;

namespace MsQuicTracing.Tables
{
    [Table]
    public sealed class QuicEventStatsTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{EE2FA823-C447-4324-969C-BC8AE215B713}"),
           "QUIC Event Stats",
           "QUIC Event Stats for ETL",
           category: "Stats",
           requiredDataCookers: new List<DataCookerPath> { QuicEventCooker.CookerPath });

        private static readonly ColumnConfiguration eventIDColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{7C382588-735D-4450-91A5-F4DF6BD4E42A}"), "Event ID"),
                new UIHints { Width = 80, });

        private static readonly ColumnConfiguration eventCountColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{54B42F78-B2E2-49B0-B5D1-F066399908DB}"), "Event Count"),
                new UIHints { Width = 120, SortOrder = SortOrder.Descending, AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig =
            new TableConfiguration("Events by Count")
            {
                Columns = new[]
                {
                     eventIDColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.GraphColumn,
                     eventCountColumnConfig,
                  }
            };

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var eventInfo = tableData.QueryOutput<IReadOnlyDictionary<ushort, ulong>>(
                new DataOutputPath(QuicEventCooker.CookerPath, "EventCounts"));

            if (eventInfo != null && eventInfo.Count != 0)
            {
                var table = tableBuilder.SetRowCount(eventInfo.Count);
                var keyValuePair = Projection.Index(eventInfo.ToList());

                var idProjector = keyValuePair.Compose(x => x.Key);
                var countProjector = keyValuePair.Compose(x => x.Value);

                table.AddColumn(eventIDColumnConfig, idProjector);
                table.AddColumn(eventCountColumnConfig, countProjector);

                tableBuilder.SetDefaultTableConfiguration(tableConfig);
            }
        }
    }
}
