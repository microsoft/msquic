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

        private static readonly ColumnConfiguration timeColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{5DBA083B-F886-4D40-B112-77F91134A909}"), "Time"),
                new UIHints { AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration durationColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{CAB180F7-B400-4B12-96F7-8E7E07FCB3FE}"), "Duration"),
                new UIHints { AggregationMode = AggregationMode.Sum });

        private static readonly ColumnConfiguration rateColumnConfig =
            new ColumnConfiguration(
                new ColumnMetadata(new Guid("{11AD5640-1E90-4E76-82AB-B47F2A908E13}"), "Rate"),
                new UIHints { AggregationMode = AggregationMode.Average });

        private static readonly TableConfiguration tableConfig1 =
            new TableConfiguration("Creation/Destruction Rates")
            {
                Columns = new[]
                {
                     typeColumnConfig,
                     TableConfiguration.PivotColumn,
                     TableConfiguration.LeftFreezeColumn,
                     durationColumnConfig,
                     timeColumnConfig,
                     TableConfiguration.RightFreezeColumn,
                     TableConfiguration.GraphColumn,
                     rateColumnConfig,
                }
            };

        struct Data
        {
            internal bool Created { get; set; }
            internal Timestamp TimeStamp { get; set; }
            internal TimestampDelta Duration{ get; set; }
            internal ulong Rate { get; set; }
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

            var rawEvents = quicState.Events;
            if (rawEvents.Count == 0)
            {
                return;
            }

            int eventCount = rawEvents.Count;
            int eventIndex = 0;
            var resolution = new TimestampDelta(25 * 1000 * 1000);

            Data sample = new Data();
            ulong createCount = 0;
            ulong destroyCount = 0;

            var data = new List<Data>();
            foreach (var evt in rawEvents)
            {
                if (eventIndex == 0)
                {
                    sample.TimeStamp = evt.TimeStamp;
                }
                eventIndex++;

                if (evt.ID == QuicEventId.StreamCreated)
                {
                    createCount++;
                }
                else if (evt.ID == QuicEventId.StreamDestroyed)
                {
                    destroyCount++;
                }

                if (sample.TimeStamp + resolution <= evt.TimeStamp || eventIndex == eventCount)
                {
                    sample.Duration = evt.TimeStamp - sample.TimeStamp;

                    sample.Created = true;
                    sample.Rate = (createCount * 1000 * 1000 * 1000) / (ulong)sample.Duration.ToNanoseconds;
                    data.Add(sample);

                    sample.Created = false;
                    sample.Rate = (destroyCount * 1000 * 1000 * 1000) / (ulong)sample.Duration.ToNanoseconds;
                    data.Add(sample);

                    sample.TimeStamp = evt.TimeStamp;
                    createCount = 0;
                    destroyCount = 0;
                }
            }

            var table = tableBuilder.SetRowCount(data.Count);
            var dataProjection = Projection.Index(data);

            table.AddColumn(typeColumnConfig, dataProjection.Compose(ProjectType));
            table.AddColumn(timeColumnConfig, dataProjection.Compose(ProjectTime));
            table.AddColumn(durationColumnConfig, dataProjection.Compose(ProjectDuration));
            table.AddColumn(rateColumnConfig, dataProjection.Compose(ProjectRate));

            tableConfig1.AddColumnRole(ColumnRole.StartTime, timeColumnConfig);
            tableConfig1.AddColumnRole(ColumnRole.Duration, durationColumnConfig);
            //tableConfig1.InitialSelectionQuery = "[Series Name]:=\"Type\"";
            tableBuilder.AddTableConfiguration(tableConfig1);

            tableBuilder.SetDefaultTableConfiguration(tableConfig1);
        }

        #region Projections

        private static string ProjectType(Data data)
        {
            return data.Created ? "Create" : "Destroy";
        }

        private static Timestamp ProjectTime(Data data)
        {
            return data.TimeStamp;
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
