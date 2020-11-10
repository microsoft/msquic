//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Processing;
using MsQuicTracing.DataModel;

namespace MsQuicTracing.Tables
{
    [Table]
    public sealed class QuicTxWindowsTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{C0F061CE-9BC6-4752-9F73-ADBCC639CB2A}"),
           "QUIC TX Windows",
           "QUIC TX Windows",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEventCooker.CookerPath });

        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{d4b7d1f4-ac9d-457f-adef-0ffc4cf2646f}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{9acd186c-ec5e-4b9f-974d-e469a14c5e0a}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{adbb413a-b620-4ac3-90f9-ec5cc27c0db2}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{87ae3df5-7c20-45b3-8f1e-2e95b86d11d2}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{5746534f-80d3-47db-b335-1f4970d1fd56}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration bytesColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c599073e-6d27-4445-b83d-dcfee018e25b}"), "Bytes"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("TX Windows by Connection")
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

        readonly struct Data
        {
            internal QuicConnection Connection { get; }
            internal string Type { get; }
            internal Timestamp Time { get; }
            internal TimestampDelta Duration { get; }
            internal ulong Bytes { get; }
            internal Data(QuicConnection connection, string type, Timestamp time, TimestampDelta duration, ulong bytes)
            {
                Connection = connection;
                Type = type;
                Time = time;
                Duration = duration;
                Bytes = bytes;
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
                    data.Add(new Data(conn, "InFlight", evt.TimeStamp, evt.Duration, evt.BytesInFlight));
                    data.Add(new Data(conn, "Buffered", evt.TimeStamp, evt.Duration, evt.BytesBufferedForSend));
                    data.Add(new Data(conn, "CongestionWindow", evt.TimeStamp, evt.Duration, evt.CongestionWindow));
                    data.Add(new Data(conn, "ConnectionFlowControl", evt.TimeStamp, evt.Duration, evt.FlowControlAvailable));
                    data.Add(new Data(conn, "StreamFlowControl", evt.TimeStamp, evt.Duration, evt.StreamFlowControlAvailable));
                }
            }

            var table = tableBuilder.SetRowCount(data.Count);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));
            table.AddColumn(bytesColumnConfig, dataProjection.Compose(ProjectBytes));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig1.InitialSelectionQuery = "[Type]:=\"InFlight\"";
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
            return data.Type;
        }

        private static Timestamp ProjectTime(Data data)
        {
            return data.Time;
        }

        private static TimestampDelta ProjectDuration(Data data)
        {
            return data.Duration;
        }

        private static ulong ProjectBytes(Data data)
        {
            return data.Bytes;
        }

        #endregion
    }
}
