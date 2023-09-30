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
    public sealed class QuicLTTngStreamStateTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{E704BC40-B36D-447B-BD41-8E05E97D1E72}"),
           "QUIC Stream States",
           "QUIC Stream States",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Packet);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicStreamStateTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwStreamStateTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{e8718744-e6b6-4db9-a1fb-ba2e9a1aaa8d}"),
           "QUIC Stream States",
           "QUIC Stream States",
           category: "Computation",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Packet);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicStreamStateTable.BuildTable(tableBuilder, quicState);
        }
    }

    public sealed class QuicStreamStateTable
    {
        private static readonly ColumnConfiguration connectionColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{49c6d674-4a1a-4219-b92c-38fe0d85d6d9}"), "Connection"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        /*private static readonly ColumnConfiguration streamColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{bc726b53-becd-4ad8-903b-25186ea9e558}"), "Stream"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });*/

        private static readonly ColumnConfiguration streamIDColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{ea50a0d5-5a99-451e-b715-1c794f47edfa}"), "Stream ID"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{109035a8-a9d7-54bf-92b4-0328d277c69e}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration nameColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{03adfc15-d217-5857-4d83-b1d84a1d16a6}"), "Name"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{cae6253b-0ce6-466e-bd9f-f7dbf65bdef7}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max, SortOrder = SortOrder.Ascending });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{355d0868-d1e9-4fa1-a6ba-da2ff12e17eb}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Timeline by Connection,Stream")
            {
                Columns = new[]
                {
                     connectionColumnConfig,
                     streamIDColumnConfig,
                     nameColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     //streamColumnConfig,
                     processIdColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     timeColumnConfig,
                     durationColumnConfig,
                }
            };

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var streams = quicState.Streams;
            if (streams.Count == 0)
            {
                return;
            }

            var data = streams.Take(1000)
                .Where(s => s.StreamId != ulong.MaxValue)
                .SelectMany(
                    s => s.Timings.StateChangeDeltas
                    .Select(y => (s, y.Item1, y.Item2, y.Item3))).ToArray();

            var table = tableBuilder.SetRowCount(data.Length);
            var dataProjection = Projection.Index(data);

            table.AddColumn(connectionColumnConfig, dataProjection.Compose(ProjectConnection));
            //table.AddColumn(streamColumnConfig, dataProjection.Compose(ProjectStream));
            table.AddColumn(streamIDColumnConfig, dataProjection.Compose(ProjectStreamId));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(nameColumnConfig, dataProjection.Compose(ProjectName));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            //tableConfig1.InitialFilterShouldKeep = false;
            //tableConfig1.InitialExpansionQuery = "[Series Name]:=\"Process (ID)\"";
            //tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Connection\" OR [Series Name]:=\"State\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static ulong ProjectConnection((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item1.Connection!.Id;
        }

        private static ulong ProjectStream((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item1.Id;
        }

        private static ulong ProjectStreamId((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item1.StreamId;
        }

        private static uint ProjectProcessId((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item1.ProcessId;
        }

        private static string ProjectName((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item2.ToString();
        }

        private static Timestamp ProjectTime((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item3;
        }

        private static TimestampDelta ProjectDuration((QuicStream, QuicStreamState, Timestamp, TimestampDelta) data)
        {
            return data.Item4;
        }

        #endregion
    }
}
