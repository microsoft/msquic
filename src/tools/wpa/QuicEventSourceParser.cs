//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;
using System;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using System.Collections.Generic;

namespace QuicEventDataSource
{
    public sealed class QuicEventContext : IQuicEventContext
    {
        private readonly ETWTraceEventSource source;

        public string LogFileName => source.LogFileName;

        public Version OSVersion => source.OSVersion;

        public int CpuSpeedMHz => source.CpuSpeedMHz;

        public int NumberOfProcessors => source.NumberOfProcessors;

        public int PointerSize => source.PointerSize;

        public QuicEventContext(ETWTraceEventSource source)
        {
            this.source = source;
        }
    }

    public sealed class QuicEventSourceParser : SourceParserBase<ETWTraceEvent, IQuicEventContext, Guid>
    {
        public const string SourceId = "QuicEvent";

        public override string Id => SourceId;

        private DataSourceInfo info;
        private IEnumerable<string> filePaths;

        public override DataSourceInfo DataSourceInfo => this.info;


        public QuicEventSourceParser(IEnumerable<string> filePaths)
        {
            this.filePaths = filePaths;
        }

        private static void ParseEvent(TraceEvent evt, ISourceDataProcessor<ETWTraceEvent, IQuicEventContext, Guid> dataProcessor, QuicEventContext context, ETWTraceEventSource source, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                source.StopProcessing();
                return;
            }

            // TODO: Instead of creating a ETWTraceEvent each time, reuse existing one...
            var result = dataProcessor.ProcessDataElement(new ETWTraceEvent(evt), context, cancellationToken);
            // TODO: do something with the result
        }

        private static Guid MsQuicEtwGuid = new Guid("ff15e657-4f26-570e-88ab-0796b258d11c");

        private static bool IsKnownSynthEvent(TraceEvent evt)
        {
            return evt.ProviderGuid == MsQuicEtwGuid;
        }

        public override void ProcessSource(ISourceDataProcessor<ETWTraceEvent, IQuicEventContext, Guid> dataProcessor, ILogger logger, IProgress<int> progress, CancellationToken cancellationToken)
        {
            using (var source = new ETWTraceEventSource(filePaths))
            {
                var context = new QuicEventContext(source);

                source.AllEvents += (evt) => ParseEvent(evt, dataProcessor, context, source, cancellationToken);

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
        }
    }
}
