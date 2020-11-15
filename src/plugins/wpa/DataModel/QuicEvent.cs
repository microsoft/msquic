//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;

#pragma warning disable CA1305 // Specify IFormatProvider
#pragma warning disable CA2211 // Non-constant fields should not be visible

namespace MsQuicTracing.DataModel
{
    public enum QuicEventParseMode
    {
        Full,
        WpaFilter
    }

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
        PerfCountersRundown,
        LibrarySendRetryStateUpdated,

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

        DatapathSend = 9217,
        DatapathRecv,
        DatapathError,
        DatapathErrorStatus,
        DatapathCreated,
        DatapathDestroyed,
    }

    //
    // The base class for all QUIC events.
    //
    public class QuicEvent : IKeyedDataType<Guid>
    {
        //
        // Global configuration to control how parsing works. Defaults to WPA filter mode.
        //
        public static QuicEventParseMode ParseMode = QuicEventParseMode.WpaFilter;

        //
        // The provider GUID used for MsQuic ETW on Windows.
        //
        public static readonly Guid ProviderGuid = new Guid("ff15e657-4f26-570e-88ab-0796b258d11c");

        public QuicEventId ID { get; }

        public QuicObjectType ObjectType { get; }

        public Timestamp TimeStamp { get; }

        public ushort Processor { get; }

        public uint ProcessId { get; }

        public uint ThreadId { get; }

        public int PointerSize { get; }

        public ulong ObjectPointer { get; }

        public virtual string PrefixString => PrefixStrings[(int)ObjectType];

        public virtual string HeaderString =>
            string.Format("|{0,2}|{1,5:X}|{2,5:X}|{3}|{4}|{5:X}|",
                Processor, ProcessId, ThreadId, TimeStamp.ToTimeSpan, PrefixString, ObjectPointer);

        public virtual string PayloadString => string.Format("[{0}]", ID);

        public override string ToString()
        {
            return string.Format("{0} {1}", HeaderString, PayloadString);
        }

        #region Internal

        static readonly string[] PrefixStrings = new string[]
        {
            " lib",
            " reg",
            "cnfg",
            "wrkr",
            "list",
            "bind",
            "conn",
            "strm",
            " udp"
        };

        internal QuicEvent(QuicEventId id, QuicObjectType objectType, Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer = 0)
        {
            ID = id;
            ObjectType = objectType;
            TimeStamp = timestamp;
            Processor = processor;
            ProcessId = processId;
            ThreadId = threadId;
            PointerSize = pointerSize;
            ObjectPointer = objectPointer;
        }

        public int CompareTo(Guid other)
        {
            return ProviderGuid.CompareTo(other);
        }

        public Guid GetKey() => ProviderGuid;

        #endregion
    }
}
