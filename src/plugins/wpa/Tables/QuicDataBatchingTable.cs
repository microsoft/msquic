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

        private static readonly ColumnConfiguration datapathColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{EA4E4C1E-E36F-4E02-83E0-70C07EBD9395}"), "Datapath"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{3CDB23BF-C6B1-4A21-A809-5683D31C5993}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{72FB3C76-A7EB-4576-97C0-714AABD7B7FE}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{69545071-7165-4BD3-84BC-9052C310FF33}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{C1E78678-10B5-43BD-A600-1D5BCC59D48E}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration rateColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{910E9271-9964-49B1-A4BA-668AF89BDF7E}"), "Rate"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("TX/RX Batching Rates by Datapath")
            {
                Columns = new[]
                {
                     datapathColumnConfig,
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     timeColumnConfig,
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     rateColumnConfig,
                }
            };

        readonly struct Data
        {
            internal QuicDatapath Datapath { get; }
            internal bool Tx { get; }
            internal Timestamp Time { get; }
            internal TimestampDelta Duration { get; }
            internal ulong Rate { get; }
            internal Data(QuicDatapath datapath, bool tx, Timestamp time, TimestampDelta duration, ulong rate)
            {
                Datapath = datapath;
                Tx = tx;
                Time = time;
                Duration = duration;
                Rate = rate;
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

            var datapaths = quicState.Datapaths;
            if (datapaths.Count == 0)
            {
                return;
            }

            var data = new List<Data>();
            foreach (var datapath in datapaths)
            {
                foreach (var evt in datapath.GetDatapathEvents())
                {
                    data.Add(new Data(datapath, true, evt.TimeStamp, evt.Duration, evt.TxBatchRate));
                    data.Add(new Data(datapath, false, evt.TimeStamp, evt.Duration, evt.RxBatchRate));
                }
            }

            var table = tableBuilder.SetRowCount(data.Count);
            var dataProjection = Projection.Index(data);

            table.AddColumn(datapathColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));
            table.AddColumn(rateColumnConfig, dataProjection.Compose(ProjectRate));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Type\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(Data data)
        {
            return data.Datapath.Id;
        }

        private static uint ProjectProcessId(Data data)
        {
            return data.Datapath.ProcessId;
        }

        private static string ProjectType(Data data)
        {
            return data.Tx ? "TX" : "RX";
        }

        private static Timestamp ProjectTime(Data data)
        {
            return data.Time;
        }

        private static TimestampDelta ProjectDuration(Data data)
        {
            return data.Duration;
        }

        private static ulong ProjectRate(Data data)
        {
            return data.Rate;
        }

        #endregion
    }
}
