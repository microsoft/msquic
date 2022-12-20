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
using QuicTrace.Cookers;
using QuicTrace.DataModel;

namespace QuicTrace.Tables
{
    [Table]
    public sealed class QuicLTTngConnectionTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{A5676710-AC1B-425B-A8D9-D787668B9CD0}"),
           "QUIC Connections",
           "QUIC Connections",
           category: "System Activity",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Connection);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicConnectionTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwConnectionTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{91B61BF7-E1F2-4F9F-8826-05DDBDD23252}"),
           "QUIC Connections",
           "QUIC Connections",
           category: "System Activity",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Connection);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicConnectionTable.BuildTable(tableBuilder, quicState);
        }
    }

    public sealed class QuicConnectionTable
    {
        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{0cfc8d02-5220-45ee-a1f8-96f2fd5924d6}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{9044a78d-fee7-4978-bfdb-eddfb24e404c}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{f63d96ae-c39e-4402-9293-705b70a22ecf}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{7a9932e0-5dd5-4d9e-ac60-c684f19fb2c4}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration pointerColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{853c395d-c547-5bb0-8e0f-d218dfd195fc}"), "Pointer"),
                new UIHints { CellFormat = ColumnFormats.HexFormat });

        private static readonly ColumnConfiguration correlationIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{67a2692f-fda3-5968-0ba0-d48635a57bfe}"), "Correlation ID"),
                new UIHints { CellFormat = ColumnFormats.HexFormat });

        private static readonly ColumnConfiguration isServerColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{195e91dd-c051-56d8-76ff-d6f9a182489e}"), "IsServer"),
                new UIHints { });

        private static readonly ColumnConfiguration stateColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c8622027-3db5-5095-c5c6-e0bcb4bbc2d3}"), "Final State"),
                new UIHints { });

        private static readonly ColumnConfiguration bytesSentColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c9a4bebc-4d6a-5963-5eb4-a7ae0ad8c73f}"), "Bytes Sent"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration bytesReceivedColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{4fab621a-7d25-50de-ce25-b8840baae60c}"), "Bytes Received"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Timeline by Connection")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     pointerColumnConfig,
                     correlationIdColumnConfig,
                     isServerColumnConfig,
                     stateColumnConfig,
                     bytesSentColumnConfig,
                     bytesReceivedColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     timeColumnConfig,
                     durationColumnConfig,
                }
            };

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var connections = quicState.Connections;
            if (connections.Count == 0)
            {
                return;
            }

            var table = tableBuilder.SetRowCount(connections.Count);
            var dataProjection = Projection.Index(connections);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(pointerColumnConfig, dataProjection.Compose(ProjectPointer));
            table.AddColumn(correlationIdColumnConfig, dataProjection.Compose(ProjectCorrelationId));
            table.AddColumn(isServerColumnConfig, dataProjection.Compose(ProjectIsServer));
            table.AddColumn(stateColumnConfig, dataProjection.Compose(ProjectState));
            table.AddColumn(bytesSentColumnConfig, dataProjection.Compose(ProjectBytesSent));
            table.AddColumn(bytesReceivedColumnConfig, dataProjection.Compose(ProjectBytesReceived));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableConfig1.InitialFilterShouldKeep = false;
            tableConfig1.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Connection\"";
            tableBuilder.AddTableConfiguration(tableConfig1);
            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectId(QuicConnection connection)
        {
            return connection.Id;
        }

        private static uint ProjectProcessId(QuicConnection connection)
        {
            return connection.ProcessId;
        }

        private static ulong ProjectPointer(QuicConnection connection)
        {
            return connection.Pointer;
        }

        private static ulong ProjectCorrelationId(QuicConnection connection)
        {
            return connection.CorrelationId;
        }

        private static string ProjectIsServer(QuicConnection connection)
        {
            return connection.IsServer is null ? "Unknown" : connection.IsServer.ToString();
        }

        private static string ProjectState(QuicConnection connection)
        {
            return connection.State.ToString();
        }

        private static ulong ProjectBytesSent(QuicConnection connection)
        {
            return connection.BytesSent;
        }

        private static ulong ProjectBytesReceived(QuicConnection connection)
        {
            return connection.BytesReceived;
        }

        private static Timestamp ProjectTime(QuicConnection connection)
        {
            return connection.InitialTimeStamp;
        }

        private static TimestampDelta ProjectDuration(QuicConnection connection)
        {
            return connection.FinalTimeStamp - connection.InitialTimeStamp;
        }

        #endregion
    }
}
