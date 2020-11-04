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

namespace MsQuicTracing
{
    public sealed class QuicEventSourceParser : SourceParserBase<ETWTraceEvent, ETWTraceEventSource, Guid>
    {
        public const string SourceId = "QuicEvent";

        private static Guid EventTraceGuid = new Guid("68fdd900-4a3e-11d1-84f4-0000f80464e3");
        private static Guid SystemConfigExGuid = new Guid("9B79EE91-B5FD-41c0-A243-4248E266E9D0");

        public override string Id => SourceId;

        private DataSourceInfo? info;

        private readonly IEnumerable<string> filePaths;

        public override DataSourceInfo DataSourceInfo => this.info ?? throw new InvalidOperationException("Data Source has not been processed");

        public QuicEventSourceParser(IEnumerable<string> filePaths)
        {
            this.filePaths = filePaths;
        }

        private static bool IsKnownSynthEvent(TraceEvent evt)
        {
            return evt.ProviderGuid == EventTraceGuid || evt.ProviderGuid == SystemConfigExGuid;
        }

        public override void ProcessSource(ISourceDataProcessor<ETWTraceEvent, ETWTraceEventSource, Guid> dataProcessor, ILogger logger, IProgress<int> progress, CancellationToken cancellationToken)
        {
            using var source = new ETWTraceEventSource(filePaths);
            source.AllEvents += (evt) => ParseEvent(evt, dataProcessor, source, cancellationToken);

            DateTime? firstEvent = null;

            source.AllEvents += (evt) =>
            {
                bool isOriginalHeader = source.SessionStartTime == evt.TimeStamp;

                if (!firstEvent.HasValue &&
                    !isOriginalHeader &&
                    !IsKnownSynthEvent(evt) &&
                    evt.TimeStamp.Ticks != 0)
                {
                    firstEvent = evt.TimeStamp;
                }

                progress.Report((int)(evt.TimeStampRelativeMSec / source.SessionEndTimeRelativeMSec * 100));
            };

            source.Process();

            if (firstEvent.HasValue)
            {
                var deltaBetweenStartAndFirstTicks = firstEvent.Value.Ticks - source.SessionStartTime.Ticks;
                var firstRelativeNano = deltaBetweenStartAndFirstTicks * 100;

                var lastnano = firstRelativeNano + ((source.SessionEndTime.Ticks - firstEvent.Value.Ticks) * 100);
                this.info = new DataSourceInfo(firstRelativeNano, lastnano, firstEvent.Value.ToUniversalTime());
            }
            else
            {
                this.info = new DataSourceInfo(0, (source.SessionEndTime.Ticks - source.SessionStartTime.Ticks) * 100, source.SessionStartTime.ToUniversalTime());
            }
        }

        private static void ParseEvent(TraceEvent evt, ISourceDataProcessor<ETWTraceEvent, ETWTraceEventSource, Guid> dataProcessor, ETWTraceEventSource source, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                source.StopProcessing();
                return;
            }

            dataProcessor.ProcessDataElement(new ETWTraceEvent(evt), source, cancellationToken);
        }
    }
}
