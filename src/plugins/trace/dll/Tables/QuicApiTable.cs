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
    public sealed class QuicLTTngApiTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{762003DB-BEA7-40B5-897E-DC9EBEA3B3EA}"),
           "QUIC API Calls",
           "QUIC API Calls",
           category: "System Activity",
           requiredDataCookers: new List<DataCookerPath> { QuicLTTngEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Api);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicLTTngEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicApiTable.BuildTable(tableBuilder, quicState);
        }
    }

    [Table]
    public sealed class QuicEtwApiTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{99e857d1-db91-4ed1-87ff-0e1491e9edbf}"),
           "QUIC API Calls",
           "QUIC API Calls",
           category: "System Activity",
           requiredDataCookers: new List<DataCookerPath> { QuicEtwEventCooker.CookerPath });

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Api);
        }

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableBuilder is null) && !(tableData is null));

            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEtwEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            QuicApiTable.BuildTable(tableBuilder, quicState);
        }
    }


    public sealed class QuicApiTable
    {
        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{405e3af7-64e3-459a-9c82-87fad3380512}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration processIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{6da292f0-6d1f-48e8-8973-185dc721ba49}"), "Process (ID)"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration threadIdColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{552467f4-d548-4fa3-888c-0f99f251fffe}"), "ThreadId"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration cpuColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c6ffd7ff-9654-4ba7-b8cd-1ac6fdaae332}"), "CPU"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c1a13739-c6e1-4d6d-82ef-81e369502fc4}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{8a2a289b-930e-49f8-a9d5-e9ad3566005c}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration pointerColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{335877cd-f4e7-4cef-9898-9a951d696d41}"), "Pointer"),
                new UIHints { CellFormat = ColumnFormats.HexFormat });

        private static readonly ColumnConfiguration resultColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{c4b800ba-7627-45ac-ac24-3786fbd54f1d}"), "Result"),
                new UIHints { });

        private static readonly ColumnConfiguration countColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{f60412fc-402f-4a56-8af3-054bf7b7614c}"), "Count"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Duration by Type")
            {
                Columns = new[]
                {
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     processIdColumnConfig,
                     threadIdColumnConfig,
                     cpuColumnConfig,
                     pointerColumnConfig,
                     resultColumnConfig,
                     countColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     timeColumnConfig,
                     durationColumnConfig,
                }
            };

        private static readonly TableConfiguration tableConfig2 =
            new TableConfiguration("Duration by Process, Thread, Type")
            {
                Columns = new[]
                {
                     processIdColumnConfig,
                     threadIdColumnConfig,
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     cpuColumnConfig,
                     pointerColumnConfig,
                     resultColumnConfig,
                     countColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     timeColumnConfig,
                     durationColumnConfig,
                }
            };

        public static void BuildTable(ITableBuilder tableBuilder, QuicState quicState)
        {
            var data = quicState.GetApiCalls();
            if (data.Count == 0)
            {
                return;
            }

            var table = tableBuilder.SetRowCount(data.Count);
            var dataProjection = Projection.Index(data);

            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(processIdColumnConfig, dataProjection.Compose(ProjectProcessId));
            table.AddColumn(threadIdColumnConfig, dataProjection.Compose(ProjectThreadId));
            table.AddColumn(cpuColumnConfig, dataProjection.Compose(ProjectCpu));
            table.AddColumn(pointerColumnConfig, dataProjection.Compose(ProjectPointer));
            table.AddColumn(resultColumnConfig, dataProjection.Compose(ProjectResult));
            table.AddColumn(countColumnConfig, Projection.Constant<uint>(1));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableConfig2.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig2.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig2);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static string ProjectType(QuicApiData data)
        {
            return data.Type.ToString();
        }

        private static uint ProjectProcessId(QuicApiData data)
        {
            return data.ProcessId;
        }

        private static uint ProjectThreadId(QuicApiData data)
        {
            return data.ThreadId;
        }

        private static ushort ProjectCpu(QuicApiData data)
        {
            return data.Processor;
        }

        private static ulong ProjectPointer(QuicApiData data)
        {
            return data.Pointer;
        }

        private static uint ProjectResult(QuicApiData data)
        {
            return data.Result;
        }

        private static Timestamp ProjectTime(QuicApiData data)
        {
            return data.TimeStamp;
        }

        private static TimestampDelta ProjectDuration(QuicApiData data)
        {
            return data.Duration;
        }

        #endregion
    }
}
