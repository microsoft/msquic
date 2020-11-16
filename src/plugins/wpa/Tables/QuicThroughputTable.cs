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
    public sealed class QuicThroughputTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{5863d497-7b40-4b2d-992a-177c15bb6d76}"),
           "QUIC Throughput",
           "QUIC Throughput",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEventCooker.CookerPath });

        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{a9ae168b-ad2f-46b4-88bf-f9ceca34a8d7}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c3c4666f-2508-4997-ad8f-4b0dcb78dbae}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{419a4028-3822-480a-a3a0-dc91c87f116f}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{5534a76a-18af-4811-a920-59b77b957dd0}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration bitsColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{1ad097ad-11a0-40c3-9425-d9255512be82}"), "Bits"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("TX/RX Rates by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     bitsColumnConfig,
                },
                AggregationOverTime = AggregationOverTime.Rate
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

            var data = quicState.Connections.SelectMany(
                x => x.GetRawTputEvents()
                    .Where(y => y.Type == QuicTputDataType.Tx || y.Type == QuicTputDataType.Rx)
                    .Select(y => new ValueTuple<QuicConnection, QuicRawTputData>(x, y))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(bitsColumnConfig, dataProjection.Compose(ProjectBits));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Type\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item1.Id;
        }

        private static uint ProjectProcessId(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item1.ProcessId;
        }

        private static string ProjectType(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.Type.ToString();
        }

        private static Timestamp ProjectTime(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.TimeStamp;
        }

        private static ulong ProjectBits(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.Value;
        }

        #endregion
    }
}
