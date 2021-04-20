﻿//
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
using QuicTrace.DataModel;

namespace QuicTrace.Tables
{
    [Table]
    public sealed class QuicStreamLifetimeTable
    {
        public static readonly TableDescriptor TableDescriptor = new TableDescriptor(
           Guid.Parse("{602DA05C-E8B9-43A6-AC50-885B7AC602B5}"),
           "QUIC Stream Lifetime",
           "QUIC Stream Lifetime",
           category: "Communications",
           requiredDataCookers: new List<DataCookerPath> { QuicEventCooker.CookerPath });

        private static readonly ColumnConfiguration typeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{D0612FB2-4243-4C13-9164-5D55837F7E04}"), "Type"),
                new UIHints { AggregationMode = AggregationMode.UniqueCount });

        private static readonly ColumnConfiguration countColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{9583D245-BD70-4BA3-A249-088F0D6C0D8C}"), "Count"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{5DBA083B-F886-4D40-B112-77F91134A909}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Creation/Destruction Rates")
            {
                Columns = new[]
                {
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     countColumnConfig,
                },
                AggregationOverTime = AggregationOverTime.Rate
            };

        public static bool IsDataAvailable(IDataExtensionRetrieval tableData)
        {
            Debug.Assert(!(tableData is null));
            var quicState = tableData.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
            return quicState != null && quicState.DataAvailableFlags.HasFlag(QuicDataAvailableFlags.Stream);
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
                .Where(x => x.EventId == QuicEventId.StreamCreated || x.EventId == QuicEventId.StreamDestroyed).ToArray();
            if (events.Length == 0)
            {
                return;
            }

            var table = tableBuilder.SetRowCount(events.Length);
            var dataProjection = Projection.Index(events);

            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(countColumnConfig, Projection.Constant<uint>(1));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static string ProjectType(QuicEvent evt)
        {
            return evt.EventId == QuicEventId.StreamCreated ? "Stream Create" : "Stream Destroy";
        }

        private static Timestamp ProjectTime(QuicEvent evt)
        {
            return evt.TimeStamp;
        }

        #endregion
    }
}
