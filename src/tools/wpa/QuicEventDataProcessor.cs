//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;

namespace MsQuicEtw
{
    public class QuicEventDataProcessor
        : CustomDataProcessorBaseWithSourceParser<ETWTraceEvent, IQuicEventContext, Guid>
    {
        internal QuicEventDataProcessor(
            ISourceParser<ETWTraceEvent, IQuicEventContext, Guid> sourceParser,
            ProcessorOptions options,
            IApplicationEnvironment applicationEnvironment,
            IProcessorEnvironment processorEnvironment,
            IReadOnlyDictionary<TableDescriptor, Action<ITableBuilder, IDataExtensionRetrieval>> allTablesMapping,
            IEnumerable<TableDescriptor> metadataTables)
            : base(sourceParser, options, applicationEnvironment, processorEnvironment, allTablesMapping, metadataTables)
        {
        }
    }
}
