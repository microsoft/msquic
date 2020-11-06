//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK;
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
        LibraryUninitialized,
        LibraryAddRef,
        LibraryRelease,
        LibraryWorkerPoolInit,
        AllocFailure,
        LibraryRundown,
        LibraryError,
        LibraryErrorStatus,
        LibraryAssert,
        ApiEnter,
        ApiExit,
        ApiExitStatus,
        ApiWaitOperation,

        WorkerCreated = 2048,
        WorkerStart,
        WorkerStop,
        WorkerActivityStateUpdated,
        WorkerQueueDelayUpdated,
        WorkerDestroyed,
        WorkerCleanup,
        WorkerError,
        WorkerErrorStatus,

        ConnCreated = 5120,
        ConnDestroyed,
        ConnHandshakeComplete,
        ConnScheduleState,
        ConnExecOper,
        ConnExecApiOper,
        ConnExecTimerOper,
        ConnLocalAddrAdded,
        ConnRemoteAddrAdded,
        ConnLocalAddrRemoved,
        ConnRemoteAddrRemoved,
        ConnAssignWorker,
        ConnHandshakeStart,
        ConnRegisterSession,
        ConnUnregisterSession,
        ConnTransportShutdown,
        ConnAppShutdown,
        ConnInitializeComplete,
        ConnHandleClosed,
        ConnVersionSet,
        ConnOutFlowStats,
        ConnOutFlowBlocked,
        ConnInFlowStats,
        ConnCubic,
        ConnCongestion,
        ConnPersistentCongestion,
        ConnRecoveryExit,
        ConnRundown,
        ConnSourceCidAdded,
        ConnDestCidAdded,
        ConnSourceCidRemoved,
        ConnDestCidRemoved,
        ConnLossDetectionTimerSet,
        ConnLossDetectionTimerCancel,
        ConnDropPacket,
        ConnDropPacketEx,
        ConnError,
        ConnErrorStatus,
        ConnNewPacketKeys,
        ConnKeyPhaseChange,
        ConnStats,
        ConnShutdownComplete,
        ConnReadKeyUpdated,
        ConnWriteKeyUpdated,
        ConnPacketSent,
        ConnPacketRecv,
        ConnPacketLost,
        ConnPacketACKed,
        ConnLogError,
        ConnLogWarning,
        ConnLogInfo,
        ConnLogVerbose,
        ConnQueueSendFlush,
        ConnOutFlowStreamStats,
        ConnPacketStats,
        ConnServerResumeTicket,

        StreamCreated = 6144,
        StreamDestroyed,
        StreamOutFlowBlocked,
        StreamRundown,
        StreamSendState,
        StreamRecvState,
        StreamError,
        StreamErrorStatus,
    }

    public abstract class QuicEvent : IKeyedDataType<Guid>
    {
        public abstract Guid Provider { get; }

        public abstract int PointerSize { get; }

        public abstract uint ProcessId { get; }

        public abstract uint ThreadId { get; }

        public abstract ushort Processor { get; }

        public abstract QuicEventId ID { get; }

        public abstract Timestamp TimeStamp { get; }

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
