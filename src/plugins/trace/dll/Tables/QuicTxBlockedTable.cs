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
using QuicTrace.Cookers;
using QuicTrace.DataModel;

namespace QuicTrace.Tables
{
    [Table]
    public sealed class QuicLTTngTxBlockedTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{FF95AF11-6BE3-4B69-A43D-EDF06820BFFE}"),
           "QUIC TX Blocked State",
           "QUIC TX Blocked State",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionFlowBlocked);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicTxBlockedTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwTxBlockedTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{64efbf30-7f58-4af1-9b8e-2cd81ac0c530}"),
           "QUIC TX Blocked State",
           "QUIC TX Blocked State",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionFlowBlocked);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicTxBlockedTable.BuildTable(tableBuilder, quicState);
        }
    }

    public sealed class QuicTxBlockedTable
    {
        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{d85077b7-abbc-4f1b-b34e-c003f3cc2369}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration streamColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{701943BA-0748-4CD5-A61A-0270E7E45C9A}"), "Stream"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{7fd859c3-e483-415f-adbe-abb5d754906d}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration reasonColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{2dcf872d-e855-4a78-8258-7b466fe44f02}"), "Reason"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{ede5f7bc-4587-499a-a51f-4b2e8d9db77e}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{88230e20-4e79-4d37-aca4-f560a130841f}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration countColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{a647b420-1947-59e6-4468-d3b34c3dcbb0}"), "Count"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration weightColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{196e2985-e16e-40f0-bbbb-3ce8e44d6555}"), "Weight"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration percentWeightColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{56816a13-5b67-47c8-b7ff-c23abfdb4e75}"), "% Weight") { IsPercent = true },
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Timeline by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     streamColumnConfig,
                     reasonColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     countColumnConfig,
                     weightColumnConfig,
                     percentWeightColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     timeColumnConfig,
                     durationColumnConfig,
                }
            };

        private static readonly TableConfiguration tableConfig2 =
            new TableConfiguration("Utilization by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     streamColumnConfig,
                     reasonColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     countColumnConfig,
                     weightColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     percentWeightColumnConfig,
                },
                ChartType = ChartType.StackedLine
            };

        internal struct Data
        {
            internal QuicConnection Connection;
            internal QuicStream? Stream;
            internal QuicFlowBlockedData BlockedData;

            internal Data(QuicConnection connection, QuicFlowBlockedData blockedData, QuicStream? stream = null)
            {
                Connection = connection;
                Stream = stream;
                BlockedData = blockedData;
            }
        }

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var connections = quicState.Connections;
            if (connections.Count == 0)
            {
                return;
            }

            var connData =
                connections.SelectMany(
                    x => x.GetFlowBlockedEvents()
                        .Where(x => x.Flags != QuicFlowBlockedFlags.None)
                        .Select(y => new Data(x, y)));
           var streamData =
                connections.SelectMany(
                    x => x.Streams.SelectMany(
                        y => y.GetFlowBlockedEvents()
                        .Where(z => z.Flags != QuicFlowBlockedFlags.None)
                        .Select(z => new Data(x, z, y))));
            var data = connData.Concat(streamData).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(streamColumnConfig, dataProjection.Compose(ProjectStreamId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(reasonColumnConfig, dataProjection.Compose(ProjectReason));
            table.AddColumn(countColumnConfig, Projection.Constant<uint>(1));
            table.AddColumn(weightColumnConfig, dataProjection.Compose(ProjectWeight));
            table.AddColumn(percentWeightColumnConfig, dataProjection.Compose(ProjectPercentWeight));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig1.InitialFilterShouldKeep = false;
            tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Connection\" OR [Series Name]:=\"Reason\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig2.InitialFilterShouldKeep = false;
            tableConfig2.InitialSelectionQuery = "[Series Name]:=\"Reason\"";
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(Data data)
        {
            return data.Connection.Id;
        }

        private static ulong ProjectStreamId(Data data)
        {
            return data.Stream?.Id ?? 0;
        }

        private static uint ProjectProcessId(Data data)
        {
            return data.Connection.ProcessId;
        }

        private static string ProjectReason(Data data)
        {
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.Scheduling))
            {
                return "Scheduling";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.Pacing))
            {
                return "Pacing";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.AmplificationProtection))
            {
                return "Amplification Protection";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.CongestionControl))
            {
                return "Congestion Control";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.ConnFlowControl))
            {
                return "Connection Flow Control";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.StreamFlowControl))
            {
                return "Stream Flow Control";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.App))
            {
                return "App";
            }
            if (data.BlockedData.Flags.HasFlag(QuicFlowBlockedFlags.StreamIdFlowControl))
            {
                return "Stream ID Flow Control";
            }
            return "None";
        }

        private static TimestampDelta ProjectWeight(Data data)
        {
            return data.BlockedData.Duration;
        }

        private static double ProjectPercentWeight(Data data)
        {
            TimestampDelta TimeNs = data.Connection.FinalTimeStamp - data.Connection.InitialTimeStamp;
            return 100.0 * data.BlockedData.Duration.ToNanoseconds / TimeNs.ToNanoseconds;
        }

        private static Timestamp ProjectTime(Data data)
        {
            return data.BlockedData.TimeStamp;
        }

        private static TimestampDelta ProjectDuration(Data data)
        {
            return data.BlockedData.Duration;
        }

        #endregion
    }
}
