//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;

#pragma warning disable CA1305 // Specify IFormatProvider

namespace QuicTrace.DataModel
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
        LibraryServerInit,
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
        LibraryVersion,
        LibraryInitializedV2,
        DataPathInitialized,
        LibraryRundownV2,
        DataPathRundown,

        RegistrationCreated = 1024,
        RegistrationDestroyed,
        RegistrationCleanup,
        RegistrationRundown,
        RegistrationError,
        RegistrationErrorStatus,
        RegistrationShutdown,

        WorkerCreated = 2048,
        WorkerStart,
        WorkerStop,
        WorkerActivityStateUpdated,
        WorkerQueueDelayUpdated,
        WorkerDestroyed,
        WorkerCleanup,
        WorkerError,
        WorkerErrorStatus,

        ConfigurationCreated = 3072,
        ConfigurationDestroyed,
        ConfigurationCleanup,
        QuicConfigurationRundown = 3076,
        ConfigurationError,
        QuicConfigurationErrorStatus,

        ListenerCreated = 4096,
        ListenerDestroyed,
        ListenerStarted,
        ListenerStopped,
        ListenerRundown,
        ListenerError,
        ListenerErrorStatus,

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
        ConnVNEOtherVersionList,
        ConnClientReceivedVersionList,
        ConnServerSupportedVersionList,
        ConnSpuriousCongestion,
        ConnNoListenerIp,
        ConnNoListenerAlpn,
        ConnFlushSend,
        ConnTimerSet,
        ConnTimerCancel,
        ConnTimerExpire,

        StreamCreated = 6144,
        StreamDestroyed,
        StreamOutFlowBlocked,
        StreamRundown,
        StreamSendState,
        StreamRecvState,
        StreamError,
        StreamErrorStatus,
        StreamLogError,
        StreamLogWarning,
        StreamLogInfo,
        StreamLogVerbose,
        StreamAlloc,
        StreamWriteFrames,
        StreamReceiveFrame,
        StreamAppReceive,
        StreamAppReceiveComplete,
        StreamAppSend,

        BindingCreated = 7168,
        BindingRundown,
        BindingDestroyed,
        BindingCleanup,
        BindingDropPacket,
        BindingDropPacketEx,
        BindingError,
        BindingErrorStatus,
        BindingExecOper,

        TlsError = 8192,
        TlsErrorStatus,
        TlsMessage,

        DatapathSend = 9217,
        DatapathRecv,
        DatapathError,
        DatapathErrorStatus,
        DatapathCreated,
        DatapathDestroyed,

        LogError = 10240,
        LogWarning,
        LogInfo,
        LogVerbose,

        PacketCreated = 11264,
        PacketEncrypt,
        PacketFinalize,
        PacketBatchSent,
        PacketReceive,
        PacketDecrypt
    }

    //
    // The base class for all QUIC events.
    //
    public class QuicEvent : IKeyedDataType<Guid>, IComparable<Guid>
    {
        //
        // Global configuration to control how parsing works. Defaults to WPA filter mode.
        //
        public static QuicEventParseMode ParseMode { get; set; } = QuicEventParseMode.WpaFilter;

        //
        // The provider GUID used for MsQuic ETW on Windows.
        //
        public static readonly Guid ProviderGuid = new Guid("ff15e657-4f26-570e-88ab-0796b258d11c");

        public QuicEventId EventId { get; }

        public QuicObjectType ObjectType { get; }

        public Timestamp TimeStamp { get; }

        public ushort Processor { get; }

        public uint ProcessId { get; }

        public uint ThreadId { get; }

        public int PointerSize { get; }

        public ulong ObjectPointer { get; }

        public virtual string PrefixString => PrefixStrings[(int)ObjectType];

        public virtual string HeaderString =>
            ObjectType == QuicObjectType.Global ?
                string.Format("[{0,2}][{1,5:X}][{2,5:X}][{3}][{4}]",
                    Processor, ProcessId, ThreadId, TimeStamp.ToTimeSpan, PrefixString) :
                string.Format("[{0,2}][{1,5:X}][{2,5:X}][{3}][{4}][{5:X}]",
                    Processor, ProcessId, ThreadId, TimeStamp.ToTimeSpan, PrefixString, ObjectPointer);

        public virtual string PayloadString => string.Format("[{0}]", EventId);

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
            EventId = id;
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
