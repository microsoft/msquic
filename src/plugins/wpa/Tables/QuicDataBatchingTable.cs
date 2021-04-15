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
    public sealed class QuicDataBatchingTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{B2365B31-F7BE-4CE3-82E8-661774789818}"),
           "QUIC Data Batching",
           "QUIC Data Batching",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEventCooker.CookerPath });

        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3CDB23BF-C6B1-4A21-A809-5683D31C5993}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{72FB3C76-A7EB-4576-97C0-714AABD7B7FE}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration cpuColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3d38dcd2-7ba8-4f35-8f6a-2e69ddcadeb2}"), "CPU"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{69545071-7165-4BD3-84BC-9052C310FF33}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration bytesColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{910E9271-9964-49B1-A4BA-668AF89BDF7E}"), "Bytes"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("TX/RX Batching Rates by Datapath")
            {
                Columns = new[]
                {
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     cpuColumnConfig,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     bytesColumnConfig,
                }
            };

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Datapath);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            var events = quicState.Events
                .Where(x => x.EventId == QuicEventId.DatapathSend || x.EventId == QuicEventId.DatapathRecv).ToArray();
            if (events.Length == 0)
            {
                return;
            }

            var table = tableBuilder.SetRowCount(events.Length);
            var dataProjection = Projection.Index(events);

            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(cpuColumnConfig, dataProjection.Compose(ProjectCPU));
            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(bytesColumnConfig, dataProjection.Compose(ProjectBytes));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static uint ProjectProcessId(QuicEvent evt)
        {
            return evt.ProcessId;
        }

        private static uint ProjectCPU(QuicEvent evt)
        {
            return evt.Processor;
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

        #endregion
    }
}
