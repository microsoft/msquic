//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK.Extensibility;

namespace MsQuicTracing.DataModel
{
    public enum QuicObjectType
    {
        Global,
        Registration,
        Configuration,
        Worker,
        Listener,
        Binding,
        Connection,
        Stream,
        Datapath
    }

    public enum QuicEventId : ushort
    {
        LibraryInitialized = 1,
        LibraryUninitialized = 2,
        LibraryAddRef = 3,
        LibraryRelease = 4,
        LibraryWorkerPoolInit = 5,
        AllocFailure = 6,
        LibraryRundown = 7,
        LibraryError = 8,
        LibraryErrorStatus = 9,
        LibraryAssert = 10,
        ApiEnter = 11,
        ApiExit = 12,
        ApiExitStatus = 13,
        ApiWaitOperation = 14,

        WorkerCreated = 2048,
        WorkerStart = 2049,
        WorkerStop = 2050,
        WorkerActivityStateUpdated = 2051,
        WorkerQueueDelayUpdated = 2052,
        WorkerDestroyed = 2053,
        WorkerCleanup = 2054,
        WorkerError = 2055,
        WorkerErrorStatus = 2056
    }

    public abstract class QuicEvent : IKeyedDataType<Guid>
    {
        public abstract Guid Provider { get; }

        public abstract int PointerSize { get; }

        public abstract uint ProcessId { get; }

        public abstract uint ThreadId { get; }

        public abstract QuicEventId ID { get; }

        public abstract ulong TimeStamp { get; }

        public abstract QuicObjectType ObjectType { get; }

        public abstract ulong ObjectPointer { get; }

        public abstract object? Payload { get; }

        #region IKeyedDataType

        public int CompareTo(Guid other)
        {
            return Provider.CompareTo(other);
        }

        public Guid GetKey() => Provider;

        #endregion
    }
}
