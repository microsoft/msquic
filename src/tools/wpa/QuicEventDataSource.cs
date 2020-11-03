﻿//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using Microsoft.Performance.SDK.Processing;
using System.Collections.Generic;
using System.Linq;

namespace QuicEventDataSource
{
    /// <summary>
    /// This custom data source defines processes MsQuic ETW events.
    /// </summary>
    [CustomDataSource(
        "{FA99CEB6-7043-42FA-97BA-932337EE19F5}",
        "QUIC Event",
        "Events generated by MsQuic")]
    [FileDataSource("etl", "Event Trace Log")]
    public class QuicEventDataSource : CustomDataSourceBase
    {
        IApplicationEnvironment applicationEnvironment;

        protected override ICustomDataProcessor CreateProcessorCore(
            IEnumerable<IDataSource> dataSources,
            IProcessorEnvironment processorEnvironment,
            ProcessorOptions options)
        {
            return new QuicEventDataProcessor(
                new QuicEventSourceParser(dataSources.Select(x => x.GetUri().LocalPath).ToArray()),
                options,
                this.applicationEnvironment,
                processorEnvironment,
                this.AllTables,
                this.MetadataTables);
        }

        /// <summary>
        /// This method is called to perform additional checks on the data source, to confirm that the data is contains
        /// can be processed. This is helpful for common file extensions, such as ".xml" or ".log". This method could
        /// peek inside at the contents confirm whether it is associated with this custom data source.
        ///
        /// For this sample, we just assume that if the file name is a match, it is handled by this add-in.
        /// </summary>
        /// <param name="path">Path to the source file</param>
        /// <returns>true when <param name="path"> is handled by this add-in</param></returns>
        protected override bool IsFileSupportedCore(string path)
        {
            return true;
        }

        /// <summary>
        /// This method just saves the application environment so that it can be used later.
        /// </summary>
        /// <param name="applicationEnvironment">Contains information helpful to future processing</param>
        protected override void SetApplicationEnvironmentCore(IApplicationEnvironment applicationEnvironment)
        {
            this.applicationEnvironment = applicationEnvironment;
        }
    }
}
