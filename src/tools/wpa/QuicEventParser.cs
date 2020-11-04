//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;
using MsQuicTracing.DataModel;

namespace MsQuicTracing
{
    public enum QuicEventSourceType
    {
        ETW,
        LTTng // TODO - Add support
    }

    public sealed class QuicEventParser : SourceParserBase<QuicEventBase, object, Guid>
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

        public override void ProcessSource(ISourceDataProcessor<QuicEventBase, object, Guid> dataProcessor, ILogger logger, IProgress<int> progress, CancellationToken cancellationToken)
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
        private static readonly Guid MsQuicEtwGuid = new Guid("ff15e657-4f26-570e-88ab-0796b258d11c");

        private static bool IsKnownSynthEvent(TraceEvent evt)
        {
            return evt.ProviderGuid == EventTraceGuid || evt.ProviderGuid == SystemConfigExGuid;
        }

        private void ProcessEtwSource(ISourceDataProcessor<QuicEventBase, object, Guid> dataProcessor, IProgress<int> progress, CancellationToken cancellationToken)
        {
            using var source = new ETWTraceEventSource(filePaths);

            QuicEtwEvent? currentEvent = null;
            source.AllEvents += (evt) =>
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    source.StopProcessing();
                    return;
                }

                if (evt.ProviderGuid == MsQuicEtwGuid)
                {
                    if (currentEvent is null)
                    {
                        currentEvent = new QuicEtwEvent(evt);
                    }
                    else
                    {
                        currentEvent.Event = evt;
                    }
                    dataProcessor.ProcessDataElement(currentEvent, source, cancellationToken);
                }
            };

            DateTime? firstTime = null;
            source.AllEvents += (evt) =>
            {
                bool isOriginalHeader = source.SessionStartTime == evt.TimeStamp;

                if (!firstTime.HasValue &&
                    !isOriginalHeader &&
                    !IsKnownSynthEvent(evt) &&
                    evt.TimeStamp.Ticks != 0)
                {
                    firstTime = evt.TimeStamp;
                }

                progress.Report((int)(evt.TimeStampRelativeMSec / source.SessionEndTimeRelativeMSec * 100));
            };

            source.Process();

            if (firstTime.HasValue)
            {
                var deltaBetweenStartAndFirstTicks = firstTime.Value.Ticks - source.SessionStartTime.Ticks;
                var firstRelativeNano = deltaBetweenStartAndFirstTicks * 100;

                var lastnano = firstRelativeNano + ((source.SessionEndTime.Ticks - firstTime.Value.Ticks) * 100);
                info = new DataSourceInfo(firstRelativeNano, lastnano, firstTime.Value.ToUniversalTime());
            }
            else
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
