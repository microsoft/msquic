//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Processing;
using MsQuicTracing.DataModel;

namespace MsQuicTracing.Tables
{
    [Table]
    public sealed class QuicRttTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{547cc354-daad-4335-be62-cb6875c6f168}"),
           "QUIC RTT",
           "QUIC RTT",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEventCooker.CookerPath });

        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{a9ae168b-ad2f-46b4-88bf-f9ceca34a8d7}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{419a4028-3822-480a-a3a0-dc91c87f116f}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{5534a76a-18af-4811-a920-59b77b957dd0}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{691f2346-9544-4a94-bced-7ac476f63532}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration rttColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{1ad097ad-11a0-40c3-9425-d9255512be82}"), "RttMs"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("RTT by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     rttColumnConfig,
                }
            };

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionTput);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            var connections = quicState.Connections;
            if (connections.Count == 0)
            {
                return;
            }

            var data = connections.SelectMany(
                x => x.GetThroughputEvents().Select(
                    y => new ValueTuple<QuicConnection, QuicThroughputData>(x, y))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));
            table.AddColumn(rttColumnConfig, dataProjection.Compose(ProjectRate));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(ValueTuple<QuicConnection, QuicThroughputData> data)
        {
            return data.Item1.Id;
        }

        private static uint ProjectProcessId(ValueTuple<QuicConnection, QuicThroughputData> data)
        {
            return data.Item1.ProcessId;
        }

        private static Timestamp ProjectTime(ValueTuple<QuicConnection, QuicThroughputData> data)
        {
            return data.Item2.TimeStamp;
        }

        private static TimestampDelta ProjectDuration(ValueTuple<QuicConnection, QuicThroughputData> data)
        {
            return data.Item2.Duration;
        }

        private static double ProjectRate(ValueTuple<QuicConnection, QuicThroughputData> data)
        {
            return data.Item2.RttUs / 1000.0;
        }

        #endregion
    }
}
