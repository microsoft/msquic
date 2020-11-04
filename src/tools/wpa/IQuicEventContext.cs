//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Text;

namespace MsQuicTracing
{
    public interface IQuicEventContext
    {
        string LogFileName { get; }

        Version OSVersion { get; }
        int CpuSpeedMHz { get; }
        int NumberOfProcessors { get; }
        int PointerSize { get; }

        // Consider adding TraceEventParsers

    }
}
