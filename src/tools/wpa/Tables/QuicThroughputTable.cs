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

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{691f2346-9544-4a94-bced-7ac476f63532}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration rateColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{1ad097ad-11a0-40c3-9425-d9255512be82}"), "Rate"),
                new UIHints { AggregationMode = AggregationMode.Average });

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
                     durationColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     rateColumnConfig,
                }
            };

        readonly struct Data
        {
            internal QuicConnection Connection { get; }
            internal bool Tx { get; }
            internal Timestamp Time { get; }
            internal TimestampDelta Duration { get; }
            internal ulong Rate { get; }
            internal Data(QuicConnection connection, bool tx, Timestamp time, TimestampDelta duration, ulong rate)
            {
                Connection = connection;
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

            var data = new List<Data>();
            foreach (var conn in connections)
            {
                foreach (var evt in conn.GetThroughputEvents())
                {
                    data.Add(new Data(conn, true, evt.TimeStamp, evt.Duration, evt.TxRate));
                    data.Add(new Data(conn, false, evt.TimeStamp, evt.Duration, evt.RxRate));
                }
            }

            var table = tableBuilder.SetRowCount(data.Count);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
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
            return data.Connection.Id;
        }

        private static uint ProjectProcessId(Data data)
        {
            return data.Connection.ProcessId;
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
