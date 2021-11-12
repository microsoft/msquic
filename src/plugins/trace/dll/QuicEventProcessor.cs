//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;
using QuicTrace.DataModel;

namespace QuicTrace
{
    public class QuicEventProcessor : CustomDataProcessorWithSourceParser<QuicEvent, object, Guid>
    {
        internal QuicEventProcessor(
            ISourceParser<QuicEvent, object, Guid> sourceParser,
            ProcessorOptions options,
            IApplicationEnvironment applicationEnvironment,
            IProcessorEnvironment processorEnvironment)
            : base(sourceParser, options, applicationEnvironment, processorEnvironment)
        {
        }
    }
}
