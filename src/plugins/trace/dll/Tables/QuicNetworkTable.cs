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
using QuicTrace.DataModel;

namespace QuicTrace.Tables
{
    [Table]
    public sealed class QuicNetworkTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{5863d497-7b40-4b2d-992a-177c15bb6d76}"),
           "QUIC Network",
           "QUIC Network Usage Tables",
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

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{2F763AAA-C9B7-4C92-82AF-8453817D72E1}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration bitsColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{1ad097ad-11a0-40c3-9425-d9255512be82}"), "Bits"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration bytesColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{FFF87D0E-70C5-443D-B6C7-F115FD95D814}"), "Bytes"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly ColumnConfiguration rttColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{0487D420-EE35-4E6F-A9B4-D535D9AED1AB}"), "Rtt (ms)"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly ColumnConfiguration txDelayColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{8c364574-f245-450c-8b95-651822704af9}"), "TX Delay (us)"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Data Rates by Connection")
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

        private static readonly TableConfiguration tableConfig4 =
            new TableConfiguration("Burst Sizes by Connection")
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
                     bytesColumnConfig,
                }
            };

        private static readonly TableConfiguration tableConfig2 =
            new TableConfiguration("Window Sizes by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     bytesColumnConfig,
                }
            };

        private static readonly TableConfiguration tableConfig3 =
            new TableConfiguration("RTT by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     typeColumnConfig,
                     processIdColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     rttColumnConfig,
                }
            };

        private static readonly TableConfiguration tableConfig5 =
            new TableConfiguration("TX Delay by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     typeColumnConfig,
                     processIdColumnConfig,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     txDelayColumnConfig,
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

            var data = quicState.Connections.SelectMany(
                x => x.GetRawTputEvents().Select(y => new ValueTuple<QuicConnection, QuicRawTputData>(x, y))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));
            table.AddColumn(bitsColumnConfig, dataProjection.Compose(ProjectBits));
            table.AddColumn(bytesColumnConfig, dataProjection.Compose(ProjectBytes));
            table.AddColumn(rttColumnConfig, dataProjection.Compose(ProjectRtt));
            table.AddColumn(txDelayColumnConfig, dataProjection.Compose(ProjectTxDelay));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.InitialSelectionQuery = "[Type]:=\"Tx\" OR [Type]:=\"Rx\"";
            tableConfig1.InitialFilterQuery = "[Type]:<>\"Tx\" AND [Type]:<>\"PktCreate\" AND [Type]:<>\"TxAck\" AND [Type]:<>\"Rx\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig2.InitialSelectionQuery = "[Type]:=\"InFlight\"";
            tableConfig2.InitialFilterQuery =
                "[Type]:=\"Tx\" OR [Type]:=\"TxAck\" OR [Type]:=\"PktCreate\" OR [Type]:=\"Rx\" OR [Type]:=\"Rtt\" OR [Type]:=\"TxDelay\"";
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableConfig3.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig3.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig3.InitialFilterQuery = "[Type]:<>\"Rtt\"";
            tableBuilder.AddTableConfiguration(tableConfig3);

            tableConfig4.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig4.InitialSelectionQuery = "[Type]:=\"Tx\" OR [Type]:=\"Rx\"";
            tableConfig4.InitialFilterQuery =
                "[Type]:<>\"Tx\" AND [Type]:<>\"TxAck\" AND [Type]:<>\"PktCreate\" AND [Type]:<>\"Rx\"";
            tableBuilder.AddTableConfiguration(tableConfig4);

            tableConfig5.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig5.InitialFilterQuery = "[Type]:<>\"TxDelay\"";
            tableBuilder.AddTableConfiguration(tableConfig5);

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

        private static TimestampDelta ProjectDuration(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.Duration;
        }

        private static ulong ProjectBits(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.Value * 8;
        }

        private static ulong ProjectBytes(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.Value;
        }

        private static double ProjectRtt(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return data.Item2.Value / 1000.0;
        }

        private static ulong ProjectTxDelay(ValueTuple<QuicConnection, QuicRawTputData> data)
        {
            return Math.Min(data.Item2.Value, 15000);
        }

        #endregion
    }
}
