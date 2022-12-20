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
    public sealed class QuicLTTngExecutionTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{316D6431-CAA9-4E1D-9FA0-8AE6FA599B7B}"),
           "QUIC Execution",
           "QUIC Execution",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionExec);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicExecutionTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwExecutionTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{A061E331-C988-4681-ACFA-C43537061A71}"),
           "QUIC Execution",
           "QUIC Execution",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.ConnectionExec);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicExecutionTable.BuildTable(tableBuilder, quicState);
        }
    }

    internal sealed class QuicExecutionTable
    {
        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{49c6d674-4a1a-4219-b92c-38fe0d85d6d9}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration cpuColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{666d77d8-35b4-4853-bff4-6a5d2e1eda35}"), "CPU"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{109035a8-a9d7-54bf-92b4-0328d277c69e}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration threadIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{6f8286ea-af76-5793-dbf2-7e7bdc89e1ee}"), "ThreadId"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration nameColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{03adfc15-d217-5857-4d83-b1d84a1d16a6}"), "Name"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{cae6253b-0ce6-466e-bd9f-f7dbf65bdef7}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{355d0868-d1e9-4fa1-a6ba-da2ff12e17eb}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration countColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c5f16d78-b550-5183-d8c0-a1ccc389777e}"), "Count"),
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
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     nameColumnConfig,
                     cpuColumnConfig,
                     processIdColumnConfig,
                     threadIdColumnConfig,
                     weightColumnConfig,
                     percentWeightColumnConfig,
                     countColumnConfig,
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
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     cpuColumnConfig,
                     nameColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     weightColumnConfig,
                     countColumnConfig,
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
                x => x.GetExecutionEvents().Select(
                    y => new ValueTuple<QuicConnection, QuicExecutionData>(x, y))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(threadIdColumnConfig, dataProjection.Compose(ProjectThreadId));
            table.AddColumn(cpuColumnConfig, dataProjection.Compose(ProjectCpu));
            table.AddColumn(nameColumnConfig, dataProjection.Compose(ProjectName));
            table.AddColumn(countColumnConfig, Projection.Constant<uint>(1));
            table.AddColumn(weightColumnConfig, dataProjection.Compose(ProjectWeight));
            table.AddColumn(percentWeightColumnConfig, dataProjection.Compose(ProjectPercentWeight));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            //tableConfig1.InitialFilterShouldKeep = false;
            //tableConfig1.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            //tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Connection\" OR [Series Name]:=\"State\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.ResourceId, cpuColumnConfig);
            //tableConfig2.InitialFilterShouldKeep = false;
            //tableConfig2.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            //tableConfig2.InitialSelectionQuery = "[Series Name]:=\"State\"";
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item1.Id;
        }

        private static uint ProjectProcessId(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item1.ProcessId;
        }

        private static uint ProjectThreadId(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item2.ThreadId;
        }

        private static ushort ProjectCpu(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item2.Processor;
        }

        private static string ProjectName(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item2.Type.ToString();
        }

        private static TimestampDelta ProjectWeight(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item2.Duration;
        }

        private static double ProjectPercentWeight(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            TimestampDelta TimeNs = data.Item1.FinalTimeStamp - data.Item1.InitialTimeStamp;
            return 100.0 * data.Item2.Duration.ToNanoseconds / TimeNs.ToNanoseconds;
        }

        private static Timestamp ProjectTime(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item2.TimeStamp;
        }

        private static TimestampDelta ProjectDuration(ValueTuple<QuicConnection, QuicExecutionData> data)
        {
            return data.Item2.Duration;
        }

        #endregion
    }
}
