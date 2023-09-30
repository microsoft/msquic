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
    public sealed class QuicLTTngWorkerActivityTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{1CB8F133-7941-409E-8F13-6FAF92988E4C}"),
           "QUIC Workers",
           "QUIC Workers",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.WorkerActivity);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicWorkerActivityTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwWorkerActivityTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{605F8393-0260-45B1-85E5-381B7C3BADDE}"),
           "QUIC Workers",
           "QUIC Workers",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.WorkerActivity);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicWorkerActivityTable.BuildTable(tableBuilder, quicState);
        }
    }

    public sealed class QuicWorkerActivityTable
    {
        private static readonly ColumnConfiguration workerColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{9e14c926-73be-4c7c-8b3a-447156fa422e}"), "Worker"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration idealProcessorColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{785b9cda-af33-49c4-894c-d7e922e4c4fd}"), "Ideal Processor"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{da6c804b-2d19-5b9e-4941-ec903c62ba98}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration threadIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{530749a6-4e3f-5ad3-91f8-91ec9332ab09}"), "ThreadId"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration cpuColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3d38dcd2-7ba8-4f35-8f6a-2e69ddcadeb2}"), "CPU"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration countColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3c554919-7249-5268-42d1-bc57bf89dbee}"), "Count"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration weightColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{1f74ed75-a116-42f5-ae5d-ca3b398e4f2e}"), "Weight"),
                new UIHints { AggregationMode = AggregationMode.Sum, SortOrder = SortOrder.Descending });

        private static readonly ColumnConfiguration percentWeightColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{abe589d5-1ca1-401f-9734-527277cb87cb}"), "% Weight") { IsPercent = true },
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{21117af5-ae65-4358-95db-b63544458d03}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{07638cdc-ae16-409c-9619-cf8e6e75fa71}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Timeline by Worker")
            {
                Columns = new[]
                {
                     workerColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     idealProcessorColumnConfig,
                     cpuColumnConfig,
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
            new TableConfiguration("Utilization by Worker")
            {
                Columns = new[]
                {
                     workerColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     idealProcessorColumnConfig,
                     cpuColumnConfig,
                     processIdColumnConfig,
                     threadIdColumnConfig,
                     countColumnConfig,
                     weightColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     percentWeightColumnConfig,
                },
                ChartType = ChartType.Line
            };

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var workers = quicState.Workers;
            if (workers.Count == 0)
            {
                return;
            }

            var data = workers.SelectMany(
                x => x.GetActivityEvents().Select(
                    y => new ValueTuple<QuicWorker, QuicActivityData>(x, y))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(workerColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(idealProcessorColumnConfig, dataProjection.Compose(ProjectIdealProcessor));
            table.AddColumn(cpuColumnConfig, dataProjection.Compose(ProjectCPU));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(threadIdColumnConfig, dataProjection.Compose(ProjectThreadId));
            table.AddColumn(countColumnConfig, Projection.Constant<uint>(1));
            table.AddColumn(weightColumnConfig, dataProjection.Compose(ProjectWeight));
            table.AddColumn(percentWeightColumnConfig, dataProjection.Compose(ProjectPercentWeight));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig1.InitialFilterShouldKeep = false;
            tableConfig1.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Worker\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig2.InitialFilterShouldKeep = false;
            tableConfig2.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            tableConfig2.InitialSelectionQuery = "[Series Name]:=\"Worker\"";
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item1.Id;
        }

        private static ushort ProjectIdealProcessor(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item1.IdealProcessor;
        }

        private static ushort ProjectCPU(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item2.Processor;
        }

        private static uint ProjectProcessId(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item1.ProcessId;
        }

        private static uint ProjectThreadId(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item1.ThreadId;
        }

        private static TimestampDelta ProjectWeight(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item2.Duration;
        }

        private static double ProjectPercentWeight(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            TimestampDelta TimeNs = data.Item1.FinalTimeStamp - data.Item1.InitialTimeStamp;
            return 100.0 * data.Item2.Duration.ToNanoseconds / TimeNs.ToNanoseconds;
        }

        private static Timestamp ProjectTime(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item2.TimeStamp;
        }

        private static TimestampDelta ProjectDuration(ValueTuple<QuicWorker, QuicActivityData> data)
        {
            return data.Item2.Duration;
        }

        #endregion
    }
}
