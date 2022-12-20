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
    public sealed class QuicLTTngDataBatchingTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{81A28430-C04D-466F-B8D4-4174D90B9837}"),
           "QUIC Network (UDP)",
           "QUIC Network (UDP)",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Datapath);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicDataBatchingTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwDataBatchingTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{B2365B31-F7BE-4CE3-82E8-661774789818}"),
           "QUIC Network (UDP)",
           "QUIC Network (UDP)",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Datapath);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicDataBatchingTable.BuildTable(tableBuilder, quicState);
        }
    }

    public sealed class QuicDataBatchingTable
    {
        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3CDB23BF-C6B1-4A21-A809-5683D31C5993}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{72FB3C76-A7EB-4576-97C0-714AABD7B7FE}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration threadIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{530749a6-4e3f-5ad3-91f8-91ec9332ab09}"), "ThreadId"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration cpuColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3d38dcd2-7ba8-4f35-8f6a-2e69ddcadeb2}"), "CPU"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{69545071-7165-4BD3-84BC-9052C310FF33}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration bytesColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{910E9271-9964-49B1-A4BA-668AF89BDF7E}"), "Bytes"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly ColumnConfiguration bitsColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{1ad097ad-11a0-40c3-9425-d9255512be82}"), "Bits"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Data Rates by Datapath")
            {
                Columns = new[]
                {
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     cpuColumnConfig,
                     processIdColumnConfig,
                     threadIdColumnConfig,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     bitsColumnConfig,
                },
                AggregationOverTime = AggregationOverTime.Rate
            };

        private static readonly TableConfiguration tableConfig2 =
            new TableConfiguration("Batch Sizes by Datapath")
            {
                Columns = new[]
                {
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     cpuColumnConfig,
                     processIdColumnConfig,
                     threadIdColumnConfig,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     bytesColumnConfig,
                }
            };

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var events = quicState.Events
                .Where(x => x.EventId == QuicEventId.DatapathSend || x.EventId == QuicEventId.DatapathRecv).ToArray();
            if (events.Length == 0)
            {
                return;
            }

            var table = tableBuilder.SetRowCount(events.Length);
            var dataProjection = Projection.Index(events);

            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(threadIdColumnConfig, dataProjection.Compose(ProjectThreadId));
            table.AddColumn(cpuColumnConfig, dataProjection.Compose(ProjectCPU));
            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(bytesColumnConfig, dataProjection.Compose(ProjectBytes));
            table.AddColumn(bitsColumnConfig, dataProjection.Compose(ProjectBits));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ushort ProjectCPU(QuicEvent evt)
        {
            return evt.Processor;
        }

        private static uint ProjectProcessId(QuicEvent evt)
        {
            return evt.ProcessId;
        }

        private static uint ProjectThreadId(QuicEvent evt)
        {
            return evt.ThreadId;
        }

        private static string ProjectType(QuicEvent evt)
        {
            return (evt.EventId == QuicEventId.DatapathSend) ? "TX" : "RX";
        }

        private static Timestamp ProjectTime(QuicEvent evt)
        {
            return evt.TimeStamp;
        }

        private static uint ProjectBytes(QuicEvent evt)
        {
            if (evt.EventId == QuicEventId.DatapathSend)
            {
                return (evt as QuicDatapathSendEvent)!.TotalSize;
            }
            else
            {
                return (evt as QuicDatapathRecvEvent)!.TotalSize;
            }
        }

        private static uint ProjectBits(QuicEvent evt)
        {
            if (evt.EventId == QuicEventId.DatapathSend)
            {
                return (evt as QuicDatapathSendEvent)!.TotalSize * 8;
            }
            else
            {
                return (evt as QuicDatapathRecvEvent)!.TotalSize * 8;
            }
        }

        #endregion
    }
}
