//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK.Extensibility;

namespace MsQuicTracing.DataModel
{
    public abstract class QuicEventBase : IKeyedDataType<Guid>
    {
        public abstract Guid Provider { get; }

        public abstract ushort ID { get; }

        public int CompareTo(Guid other)
        {
            return Provider.CompareTo(other);
        }

        public Guid GetKey() => Provider;
    }
}
