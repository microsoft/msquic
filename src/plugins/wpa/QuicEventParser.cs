//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;
using MsQuicTracing.DataModel;
using MsQuicTracing.DataModel.ETW;

#pragma warning disable CA1031 // Do not catch general exception types

namespace MsQuicTracing
{
    public enum QuicEventSourceType
    {
        ETW,
        LTTng // TODO - Add support
    }

    public sealed class QuicEventParser : SourceParserBase<QuicEvent, object, Guid>
    {
        public const string SourceId = "QUIC";

        public override string Id => SourceId;

        private DataSourceInfo? info;

        private readonly IEnumerable<string> filePaths;

        private readonly QuicEventSourceType sourceType;

        public override DataSourceInfo DataSourceInfo => info ?? throw new InvalidOperationException("Data Source has not been processed");

        public QuicEventParser(IEnumerable<string> filePaths, QuicEventSourceType sourceType)
        {
            if (sourceType != QuicEventSourceType.ETW)
            {
                throw new NotSupportedException("Source type not supported");
            }

            this.filePaths = filePaths;
            this.sourceType = sourceType;
        }

        public override void ProcessSource(ISourceDataProcessor<QuicEvent, object, Guid> dataProcessor, ILogger logger, IProgress<int> progress, CancellationToken cancellationToken)
        {
            switch (sourceType)
            {
                case QuicEventSourceType.ETW:
                    ProcessEtwSource(dataProcessor, progress, cancellationToken);
                    break;
                default:
                    throw new NotSupportedException("Source type not supported");
            }
        }

        #region ETW

        private static readonly Guid EventTraceGuid = new Guid("68fdd900-4a3e-11d1-84f4-0000f80464e3");
        private static readonly Guid SystemConfigExGuid = new Guid("9B79EE91-B5FD-41c0-A243-4248E266E9D0");

        private static bool IsKnownSynthEvent(TraceEvent evt)
        {
            return evt.ProviderGuid == EventTraceGuid || evt.ProviderGuid == SystemConfigExGuid;
        }

        private void ProcessEtwSource(ISourceDataProcessor<QuicEvent, object, Guid> dataProcessor, IProgress<int> progress, CancellationToken cancellationToken)
        {
            using var source = new ETWTraceEventSource(filePaths);
            long StartTime = 0;

            source.AllEvents += (evt) =>
            {
                bool isOriginalHeader = source.SessionStartTime == evt.TimeStamp;

                if (info == null &&
                    !isOriginalHeader &&
                    !IsKnownSynthEvent(evt) &&
                    evt.TimeStamp.Ticks != 0)
                {
                    var deltaBetweenStartAndFirstTicks = evt.TimeStamp.Ticks - source.SessionStartTime.Ticks;
                    var relativeNanoSeconds = deltaBetweenStartAndFirstTicks * 100;

                    StartTime = evt.TimeStamp.Ticks;
                    var lastnano = relativeNanoSeconds + ((source.SessionEndTime.Ticks - evt.TimeStamp.Ticks) * 100);
                    info = new DataSourceInfo(relativeNanoSeconds, lastnano, evt.TimeStamp.ToUniversalTime());
                }

                progress.Report((int)(evt.TimeStampRelativeMSec / source.SessionEndTimeRelativeMSec * 100));
            };

            source.AllEvents += (evt) =>
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    source.StopProcessing();
                    return;
                }

                if (evt.ProviderGuid == QuicEvent.ProviderGuid)
                {
                    try
                    {
                        var quicEvent = QuicEtwEvent.TryCreate(evt, new Timestamp((evt.TimeStamp.Ticks - StartTime) * 100));
                        if (quicEvent != null)
                        {
                            dataProcessor.ProcessDataElement(quicEvent, this, cancellationToken);
                        }
                    }
                    catch
                    {

                    }
                }
            };

            source.Process();

            if (info == null)
            {
                info = new DataSourceInfo(0, (source.SessionEndTime.Ticks - source.SessionStartTime.Ticks) * 100, source.SessionStartTime.ToUniversalTime());
            }
        }

        #endregion

        #region LTTng

        // TODO - Add support

        #endregion
    }
}
