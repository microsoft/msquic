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
    public sealed class QuicLTTngSchedulingTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{2bab73ef-6c49-41b2-9727-484c9d5dfe22}"),
           "QUIC Scheduling",
           "QUIC Scheduling",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionSchedule);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicSchedulingTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwSchedulingTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{2bab73ef-6c49-41b2-9727-484c9d5dfe22}"),
           "QUIC Scheduling",
           "QUIC Scheduling",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionSchedule);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicSchedulingTable.BuildTable(tableBuilder, quicState);
        }
    }

    public sealed class QuicSchedulingTable
    {
        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{4058604f-97c7-4dcb-8f5a-9031c9421224}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{fd130acd-3b11-5fca-94f4-88f604a219ab}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration threadIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{63235373-e080-50fb-02d5-5057e3ba5d38}"), "ThreadId"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration stateColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{18066077-726d-52eb-6e0e-1b7e24a5c3fb}"), "State"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration countColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c40b5bd3-62e4-5660-2ba2-530d1c691d79}"), "Count"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration weightColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{8b2d0d77-c428-4e00-bcd4-08ae2f6e560b}"), "Weight"),
                new UIHints { AggregationMode = AggregationMode.Sum, SortOrder = SortOrder.Descending });

        private static readonly ColumnConfiguration percentWeightColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{65e75fe3-d0d0-4812-b4dd-51a1b5a23819}"), "% Weight") { IsPercent = true },
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{25f6f72c-c393-467e-84a4-9796beee5804}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{6f77a9b0-ccee-4140-bf1c-b5d206d2f9f4}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Timeline by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     stateColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     threadIdColumnConfig,
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
                     stateColumnConfig,
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

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var connections = quicState.Connections;
            if (connections.Count == 0)
            {
                return;
            }

            var data = connections.SelectMany(
                x => x.GetScheduleEvents().Select(
                    y => new ValueTuple<QuicConnection, QuicScheduleData>(x, y))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(threadIdColumnConfig, dataProjection.Compose(ProjectThreadId));
            table.AddColumn(stateColumnConfig, dataProjection.Compose(ProjectState));
            table.AddColumn(countColumnConfig, Projection.Constant<uint>(1));
            table.AddColumn(weightColumnConfig, dataProjection.Compose(ProjectWeight));
            table.AddColumn(percentWeightColumnConfig, dataProjection.Compose(ProjectPercentWeight));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig1.InitialFilterShouldKeep = false;
            tableConfig1.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Connection\" OR [Series Name]:=\"State\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig2.InitialFilterShouldKeep = false;
            tableConfig2.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            tableConfig2.InitialSelectionQuery = "[Series Name]:=\"State\"";
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item1.Id;
        }

        private static uint ProjectProcessId(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item1.ProcessId;
        }

        private static uint ProjectThreadId(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item2.ThreadId;
        }

        private static string ProjectState(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item2.State.ToString();
        }

        private static TimestampDelta ProjectWeight(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item2.Duration;
        }

        private static double ProjectPercentWeight(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            TimestampDelta TimeNs = data.Item1.FinalTimeStamp - data.Item1.InitialTimeStamp;
            return 100.0 * data.Item2.Duration.ToNanoseconds / TimeNs.ToNanoseconds;
        }

        private static Timestamp ProjectTime(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item2.TimeStamp;
        }

        private static TimestampDelta ProjectDuration(ValueTuple<QuicConnection, QuicScheduleData> data)
        {
            return data.Item2.Duration;
        }

        #endregion
    }
}
