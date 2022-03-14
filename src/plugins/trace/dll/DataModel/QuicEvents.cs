//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Net;
using Microsoft.Performance.SDK;

#pragma warning disable CA1305 // Specify IFormatProvider
#pragma warning disable CA1707 // Identifiers should not contain underscores

namespace QuicTrace.DataModel
{
    public enum QuicApiType
    {
        SetParam,
        GetParam,
        RegistrationOpen,
        RegistrationClose,
        RegistrationShutdown,
        ConfigurationOpen,
        ConfigurationClose,
        ConfigurationLoadCredential,
        ListenerOpen,
        ListenerClose,
        ListenerStart,
        ListenerStop,
        ConnectionOpen,
        ConnectionClose,
        ConnectionShutdown,
        ConnectionStart,
        ConnectionSetConfiguration,
        ConnectionSendResumptionTicket,
        StreamOpen,
        StreamClose,
        StreamStart,
        StreamShutdown,
        StreamSend,
        StreamReceiveComplete,
        StreamReceiveSetEnabled,
        StreamDatagramSend
    }

    public enum QuicConnectionState
    {
        Unknown,
        Allocated,
        Started,
        HandshakeComplete,
        Shutdown,
        Closed
    }

    [Flags]
    public enum QuicDatapathFeatures
    {
        RecvSideScaling = 1,
        RecvCoalescing = 2,
        SendSegmentation = 4
    }

    public enum QuicErrorCode
    {
        NO_ERROR = 0x0,
        INTERNAL_ERROR = 0x1,
        CONNECTION_REFUSED = 0x2,
        FLOW_CONTROL_ERROR = 0x3,
        STREAM_LIMIT_ERROR = 0x4,
        STREAM_STATE_ERROR = 0x5,
        FINAL_SIZE_ERROR = 0x6,
        FRAME_ENCODING_ERROR = 0x7,
        TRANSPORT_PARAMETER_ERROR = 0x8,
        CONNECTION_ID_LIMIT_ERROR = 0x9,
        PROTOCOL_VIOLATION = 0xA,
        INVALID_TOKEN = 0xB,
        APPLICATION_ERROR = 0xC,
        CRYPTO_BUFFER_EXCEEDED = 0xD,
        KEY_UPDATE_ERROR = 0xE,
        AEAD_LIMIT_REACHED = 0xF,

        TLS_CLOSE_NOTIFY = 0x100,
        TLS_USER_CANCELED = 0x116,
        TLS_HANDSHAKE_FAILURE = 0x128,
        TLS_BAD_CERTIFICATE = 0x12A,
        TLS_CERTIFICATE_UNSUPPORTED = 0x12B,
        TLS_CERTIFICATE_REVOKED = 0x12C,
        TLS_CERTIFICATE_EXPIRED = 0x12D,
        TLS_CERTIFICATE_UNKNOWN = 0x12E,
        TLS_UNKNOWN_CA = 0x130,
        TLS_ACCESS_DENIED = 0x131,
        TLS_INTERNAL_ERROR = 0x150,
        TLS_UNRECOGNIZED_NAME = 0x170,
        TLS_CERTIFICATE_REQUIRED = 0x174,
        TLS_NO_APPLICATION_PROTOCOL = 0x178,

        QUIC_VERSION_NEGOTIATION_ERROR = 0x53F8
    }

    public enum QuicExecutionType
    {
        Unknown,

        OperApi,
        OperFlushRecv,
        OperUnreachable,
        OperFlushStreamRecv,
        OperFlushSend,
        OperTlsComplete,
        OperTimerExpired,
        OperTraceRundown,
        OperVersionNegotiation,
        OperStatelessReset,
        OperRetry,

        ApiConnClose,
        ApiConnShutdown,
        ApiConnStart,
        ApiConnSetConfiguration,
        ApiConnSendResumptionTicket,
        ApiStreamClose,
        ApiStreamShutdown,
        ApiStreamStart,
        ApiStreamSend,
        ApiStreamReceiveComplete,
        ApiStreamReceiveSetEnabled,
        ApiSetParam,
        ApiGetParam,
        ApiDatagramSend,

        TimerPacing,
        TimerAckDelay,
        TimerLossDetection,
        TimerKeepAlive,
        TimerIdle,
        TimerShutdown
    }

    [Flags]
    public enum QuicFlowBlockedFlags
    {
        None = 0x00,
        Scheduling = 0x01,
        Pacing = 0x02,
        AmplificationProtection = 0x04,
        CongestionControl = 0x08,
        ConnFlowControl = 0x10,
        StreamIdFlowControl = 0x20,
        StreamFlowControl = 0x40,
        App = 0x80
    }

    public enum QuicScheduleState
    {
        Idle,
        Queued,
        Processing,
        Max
    }

    #region Global Events

    public class QuicDataPathInitializedEvent : QuicEvent
    {
        public uint DatapathFeatures { get; }

        public QuicDatapathFeatures Features => (QuicDatapathFeatures)DatapathFeatures;

        public override string PayloadString =>
            string.Format("Initialized, DatapathFeatures=[{1}]", Features);

        internal QuicDataPathInitializedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint datapathFeatures) :
            base(QuicEventId.LibraryInitialized, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            DatapathFeatures = datapathFeatures;
        }
    }

    public class QuicLibraryInitializedEvent : QuicEvent
    {
        public uint PartitionCount { get; }

        public uint DatapathFeatures { get; }

        public QuicDatapathFeatures Features => (QuicDatapathFeatures)DatapathFeatures;

        public override string PayloadString =>
            string.Format("Initialized, PartitionCount={0} DatapathFeatures=[{1}]", PartitionCount, Features);

        internal QuicLibraryInitializedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint partitionCount, uint datapathFeatures) :
            base(QuicEventId.LibraryInitialized, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            PartitionCount = partitionCount;
            DatapathFeatures = datapathFeatures;
        }
    }

    public class QuicLibraryInitializedV2Event : QuicEvent
    {
        public uint PartitionCount { get; }

        public override string PayloadString =>
            string.Format("Initialized, PartitionCount={0}", PartitionCount);

        internal QuicLibraryInitializedV2Event(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint partitionCount) :
            base(QuicEventId.LibraryInitialized, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            PartitionCount = partitionCount;
        }
    }

    public class QuicLibraryUninitializedEvent : QuicEvent
    {
        public override string PayloadString => "Uninitialized";

        internal QuicLibraryUninitializedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.LibraryUninitialized, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicLibraryAddRefEvent : QuicEvent
    {
        public override string PayloadString => "AddRef";

        internal QuicLibraryAddRefEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.LibraryAddRef, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicLibraryReleaseEvent : QuicEvent
    {
        public override string PayloadString => "Release";

        internal QuicLibraryReleaseEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.LibraryRelease, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicLibraryServerInitEvent : QuicEvent
    {
        public override string PayloadString => "Shared server state initializing";

        internal QuicLibraryServerInitEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.LibraryServerInit, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicAllocFailureEvent : QuicEvent
    {
        public string Description { get; }

        public ulong ByteCount { get; }

        public override string PayloadString =>
            string.Format("Allocation of '{0}' failed. ({1} bytes)", Description, ByteCount);

        internal QuicAllocFailureEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, string description, ulong byteCount) :
            base(QuicEventId.AllocFailure, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Description = description;
            ByteCount = byteCount;
        }
    }

    public class QuicDataPathRundownEvent : QuicEvent
    {
        public uint DatapathFeatures { get; }

        public QuicDatapathFeatures Features => (QuicDatapathFeatures)DatapathFeatures;

        public override string PayloadString =>
            string.Format("Rundown,  DatapathFeatures=[{1}]", Features);

        internal QuicDataPathRundownEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint datapathFeatures) :
            base(QuicEventId.LibraryInitialized, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            DatapathFeatures = datapathFeatures;
        }
    }

    public class QuicLibraryRundownEvent : QuicEvent
    {
        public uint PartitionCount { get; }

        public uint DatapathFeatures { get; }

        public QuicDatapathFeatures Features => (QuicDatapathFeatures)DatapathFeatures;

        public override string PayloadString =>
            string.Format("Rundown, PartitionCount={0} DatapathFeatures=[{1}]", PartitionCount, Features);

        internal QuicLibraryRundownEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint partitionCount, uint datapathFeatures) :
            base(QuicEventId.LibraryRundown, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            PartitionCount = partitionCount;
            DatapathFeatures = datapathFeatures;
        }
    }

    public class QuicLibraryRundownV2Event : QuicEvent
    {
        public uint PartitionCount { get; }

        public override string PayloadString =>
            string.Format("Rundown, PartitionCount={0}", PartitionCount);

        internal QuicLibraryRundownV2Event(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint partitionCount) :
            base(QuicEventId.LibraryRundown, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            PartitionCount = partitionCount;
        }
    }

    public class QuicLibraryErrorEvent : QuicEvent
    {
        public string ErrorString { get; }

        public override string PayloadString => string.Format("ERROR, {0}", ErrorString);

        internal QuicLibraryErrorEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, string errorString) :
            base(QuicEventId.LibraryError, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            ErrorString = errorString;
        }
    }

    public class QuicLibraryErrorStatusEvent : QuicEvent
    {
        public uint Status { get; }

        public string ErrorString { get; }

        public override string PayloadString => string.Format("ERROR, {0}, {1}", Status, ErrorString);

        internal QuicLibraryErrorStatusEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint status, string errorString) :
            base(QuicEventId.LibraryErrorStatus, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Status = status;
            ErrorString = errorString;
        }
    }

    public class QuicLibraryAssertEvent : QuicEvent
    {
        public uint Line { get; }

        public string File { get; }

        public string Expression { get; }

        public override string PayloadString => string.Format("ASSERT, {0}:{1} - {2}", File, Line, Expression);

        internal QuicLibraryAssertEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint line, string file, string expression) :
            base(QuicEventId.LibraryAssert, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Line = line;
            File = file;
            Expression = expression;
        }
    }

    public class QuicApiEnterEvent : QuicEvent
    {
        public uint Type { get; }

        public QuicApiType ApiType => (QuicApiType)Type;

        public ulong Handle { get; }

        public override string PrefixString => " api";

        public override string PayloadString => string.Format("Enter {0} ({1:X})", ApiType, Handle);

        internal QuicApiEnterEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint type, ulong handle) :
            base(QuicEventId.ApiEnter, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Type = type;
            Handle = handle;
        }
    }

    public class QuicApiExitEvent : QuicEvent
    {
        public override string PrefixString => " api";

        public override string PayloadString => "Exit";

        internal QuicApiExitEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.ApiExit, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicApiExitStatusEvent : QuicEvent
    {
        public uint Status { get; }

        public override string PrefixString => " api";

        public override string PayloadString => string.Format("Exit {0}", Status);

        internal QuicApiExitStatusEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint status) :
            base(QuicEventId.ApiExitStatus, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Status = status;
        }
    }

    public class QuicApiWaitOperationEvent : QuicEvent
    {
        public override string PrefixString => " api";

        public override string PayloadString => "Waiting on operation";

        internal QuicApiWaitOperationEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.ApiWaitOperation, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicPerfCountersRundownEvent : QuicEvent
    {
        //public ulong[] Counters { get; } = null!; // TODO

        public override string PayloadString => "Perf counters Rundown";

        internal QuicPerfCountersRundownEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize) :
            base(QuicEventId.PerfCountersRundown, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
        }
    }

    public class QuicLibrarySendRetryStateUpdatedEvent : QuicEvent
    {
        public byte Value { get; }

        public override string PayloadString => string.Format("New SendRetryEnabled state, {0}", Value != 0);

        internal QuicLibrarySendRetryStateUpdatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, byte value) :
            base(QuicEventId.LibrarySendRetryStateUpdated, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Value = value;
        }
    }

    public class QuicLibraryVersionEvent : QuicEvent
    {
        public uint Major { get; }
        public uint Minor { get; }
        public uint Patch { get; }
        public uint Build { get; }

        public override string PayloadString => string.Format("Version {0}.{1}.{2}.{3}", Major, Minor, Patch, Build);

        internal QuicLibraryVersionEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, uint major, uint minor, uint patch, uint build) :
            base(QuicEventId.LibraryVersion, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Major = major;
            Minor = minor;
            Patch = patch;
            Build = build;
        }
    }

    public class QuicLibraryMessageEvent : QuicEvent
    {
        public string Message { get; }

        public override string PayloadString => Message;

        public override string HeaderString =>
            string.Format("[{0,2}][{1,5:X}][{2,5:X}][{3}]",
                Processor, ProcessId, ThreadId, TimeStamp.ToTimeSpan);

        public override string ToString()
        {
            return string.Format("{0}{1}", HeaderString, PayloadString);
        }

        internal QuicLibraryMessageEvent(QuicEventId id, Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, string message) :
            base(id, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize)
        {
            Message = message;
        }
    }

    #endregion

    #region Worker Events

    public class QuicWorkerCreatedEvent : QuicEvent
    {
        public ushort IdealProcessor { get; }

        public ulong OwnerPointer { get; }

        internal QuicWorkerCreatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ushort idealProcessor, ulong ownerPointer) :
            base(QuicEventId.WorkerCreated, QuicObjectType.Worker, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            IdealProcessor = idealProcessor;
            OwnerPointer = ownerPointer;
        }
    }

    public class QuicWorkerActivityStateUpdatedEvent : QuicEvent
    {
        public byte IsActive { get; }

        public uint Arg { get; }

        internal QuicWorkerActivityStateUpdatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, byte isActive, uint arg) :
            base(QuicEventId.WorkerActivityStateUpdated, QuicObjectType.Worker, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            IsActive = isActive;
            Arg = arg;
        }
    }

    public class QuicWorkerQueueDelayUpdatedEvent : QuicEvent
    {
        public uint QueueDelay { get; }

        internal QuicWorkerQueueDelayUpdatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint queueDelay) :
            base(QuicEventId.WorkerQueueDelayUpdated, QuicObjectType.Worker, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            QueueDelay = queueDelay;
        }
    }

    #endregion

    #region Connection Events

    public class QuicConnectionCreatedEvent : QuicEvent
    {
        public uint IsServer { get; }

        public ulong CorrelationId { get; }

        public override string PayloadString =>
            string.Format("Created, IsServer={0}, CorrelationId={1}", (IsServer != 0), CorrelationId);

        internal QuicConnectionCreatedEvent(QuicEventId id, Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint isServer, ulong correlationId) :
            base(id, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            IsServer = isServer;
            CorrelationId = correlationId;
        }
    }

    public class QuicConnectionDestroyedEvent : QuicEvent
    {
        public override string PayloadString => "Destroyed";

        internal QuicConnectionDestroyedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.ConnDestroyed, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicConnectionHandshakeCompleteEvent : QuicEvent
    {
        public override string PayloadString => "Handshake complete";

        internal QuicConnectionHandshakeCompleteEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.ConnHandshakeComplete, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicConnectionScheduleStateEvent : QuicEvent
    {
        public uint State { get; }

        public QuicScheduleState ScheduleState { get { return (QuicScheduleState)State; } }

        public override string PayloadString =>
            string.Format("Scheduling: {0}", ScheduleState);

        internal QuicConnectionScheduleStateEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint state) :
            base(QuicEventId.ConnScheduleState, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            State = state;
        }
    }

    public class QuicConnectionExecOperEvent : QuicEvent
    {
        public uint Type { get; }

        public QuicExecutionType ExecutionType => (QuicExecutionType)((uint)QuicExecutionType.OperApi + Type);

        public override string PayloadString => string.Format("Execute: {0}", ExecutionType);

        internal QuicConnectionExecOperEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint type) :
            base(QuicEventId.ConnExecOper, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Type = type;
        }
    }

    public class QuicConnectionExecApiOperEvent : QuicEvent
    {
        public uint Type { get; }

        public QuicExecutionType ExecutionType => (QuicExecutionType)((uint)QuicExecutionType.ApiConnClose + Type);

        public override string PayloadString => string.Format("Execute: {0}", ExecutionType);

        internal QuicConnectionExecApiOperEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint type) :
            base(QuicEventId.ConnExecApiOper, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Type = type;
        }
    }

    public class QuicConnectionExecTimerOperEvent : QuicEvent
    {
        public uint Type { get; }

        public QuicExecutionType ExecutionType => (QuicExecutionType)((uint)QuicExecutionType.TimerPacing + Type);

        public override string PayloadString => string.Format("Execute: {0}", ExecutionType);

        internal QuicConnectionExecTimerOperEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint type) :
            base(QuicEventId.ConnExecTimerOper, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Type = type;
        }
    }

    public class QuicConnectionAssignWorkerEvent : QuicEvent
    {
        public ulong WorkerPointer { get; }

        public override string PayloadString => string.Format("Assigned worker: {0:X}", WorkerPointer);

        internal QuicConnectionAssignWorkerEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong workerPointer) :
            base(QuicEventId.ConnAssignWorker, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            WorkerPointer = workerPointer;
        }
    }

    public class QuicConnectionTransportShutdownEvent : QuicEvent
    {
        public ulong ErrorCode { get; }

        public byte IsRemoteShutdown { get; }

        public byte IsQuicStatus { get; }

        public string ErrorString =>
            (IsQuicStatus == 0) ?
                string.Format("{0} ({1})", (QuicErrorCode)ErrorCode, ErrorCode) :
                string.Format("QUIC_STATUS={0}", ErrorCode);

        public override string PayloadString =>
            string.Format("Transport Shutdown: {0} (Remote={1})", ErrorString, (IsRemoteShutdown != 0));

        internal QuicConnectionTransportShutdownEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong errorCode, byte isRemoteShutdown, byte isQuicStatus) :
            base(QuicEventId.ConnTransportShutdown, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ErrorCode = errorCode;
            IsRemoteShutdown = isRemoteShutdown;
            IsQuicStatus = isQuicStatus;
        }
    }

    public class QuicConnectionAppShutdownEvent : QuicEvent
    {
        public ulong ErrorCode { get; }

        public byte IsRemoteShutdown { get; }

        public override string PayloadString =>
            string.Format("App Shutdown: {0} (Remote={1})", ErrorCode, (IsRemoteShutdown != 0));

        internal QuicConnectionAppShutdownEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong errorCode, byte isRemoteShutdown) :
            base(QuicEventId.ConnAppShutdown, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ErrorCode = errorCode;
            IsRemoteShutdown = isRemoteShutdown;
        }
    }

    public class QuicConnectionHandleClosedEvent : QuicEvent
    {
        public override string PayloadString => "Handle closed";

        internal QuicConnectionHandleClosedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.ConnHandleClosed, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicConnectionOutFlowStatsEvent : QuicEvent
    {
        public ulong BytesSent { get; }

        public uint BytesInFlight { get; }

        public uint BytesInFlightMax { get; }

        public uint CongestionWindow { get; }

        public uint SlowStartThreshold { get; }

        public ulong ConnectionFlowControl { get; }

        public ulong IdealBytes { get; }

        public ulong PostedBytes { get; }

        public uint SmoothedRtt { get; }

        public override string PayloadString =>
            string.Format("OUT: BytesSent={0} InFlight={1} InFlightMax={2} CWnd={3} SSThresh={4} ConnFC={5} ISB={6} PostedBytes={7} SRtt={8}",
                BytesSent, BytesInFlight, BytesInFlightMax, CongestionWindow, SlowStartThreshold, ConnectionFlowControl, IdealBytes, PostedBytes, SmoothedRtt);

        internal QuicConnectionOutFlowStatsEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                                 ulong bytesSent, uint bytesInFlight, uint bytesInFlightMax, uint congestionWindow, uint slowStartThreshold,
                                                 ulong connectionFlowControl, ulong idealBytes, ulong postedBytes, uint smoothedRtt) :
            base(QuicEventId.ConnOutFlowStats, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            BytesSent = bytesSent;
            BytesInFlight = bytesInFlight;
            BytesInFlightMax = bytesInFlightMax;
            CongestionWindow = congestionWindow;
            SlowStartThreshold = slowStartThreshold;
            ConnectionFlowControl = connectionFlowControl;
            IdealBytes = idealBytes;
            PostedBytes = postedBytes;
            SmoothedRtt = smoothedRtt;
        }
    }

    public class QuicConnectionOutFlowBlockedEvent : QuicEvent
    {
        public byte ReasonFlags { get; }

        public QuicFlowBlockedFlags FlowBlockedFlags => (QuicFlowBlockedFlags)ReasonFlags;

        public override string PayloadString =>
            ReasonFlags == 0 ?
                "Send Unblocked" :
                string.Format("Send Blocked: {0}", FlowBlockedFlags);

        internal QuicConnectionOutFlowBlockedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, byte reasonFlags) :
            base(QuicEventId.ConnOutFlowBlocked, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ReasonFlags = reasonFlags;
        }
    }

    public class QuicConnectionInFlowStatsEvent : QuicEvent
    {
        public ulong BytesRecv { get; }

        public override string PayloadString => string.Format("IN: BytesRecv={0}", BytesRecv);

        internal QuicConnectionInFlowStatsEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong bytesRecv) :
            base(QuicEventId.ConnInFlowStats, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            BytesRecv = bytesRecv;
        }
    }

    public class QuicConnectionCongestionEvent : QuicEvent
    {
        public override string PayloadString => "Congestion event";

        internal QuicConnectionCongestionEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.ConnCongestion, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicConnectionSourceCidAddedEvent : QuicEvent
    {
        public ulong SequenceNumber { get; }


#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] CID { get; }
#pragma warning restore CA1819 // Properties should not return arrays

        internal QuicConnectionSourceCidAddedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                                       ulong sequenceNumber, ReadOnlySpan<byte> cid) :
            base(QuicEventId.ConnSourceCidAdded, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            SequenceNumber = sequenceNumber;
            CID = cid.ToArray();
        }
    }

    public class QuicConnectionDestinationCidAddedEvent : QuicEvent
    {
        public ulong SequenceNumber { get; }


#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] CID { get; }
#pragma warning restore CA1819 // Properties should not return arrays

        internal QuicConnectionDestinationCidAddedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                                       ulong sequenceNumber, ReadOnlySpan<byte> cid) :
            base(QuicEventId.ConnDestCidAdded, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            SequenceNumber = sequenceNumber;
            CID = cid.ToArray();
        }
    }

    public class QuicConnectionStatsEvent : QuicEvent
    {
        public uint SmoothedRtt { get; }

        public uint CongestionCount { get; }

        public uint PersistentCongestionCount { get; }

        public ulong SendTotalBytes { get; }

        public ulong RecvTotalBytes { get; }

        public override string PayloadString =>
            string.Format("STATS: SmoothedRtt={0} CongestionCount={1} PersistentCongestionCount={2} SendTotalBytes={3} RecvTotalBytes={4}",
                SmoothedRtt, CongestionCount, PersistentCongestionCount, SendTotalBytes, RecvTotalBytes);

        internal QuicConnectionStatsEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                          uint smoothedRtt, uint congestionCount, uint persistentCongestionCount, ulong sendTotalBytes, ulong recvTotalBytes) :
            base(QuicEventId.ConnStats, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            SmoothedRtt = smoothedRtt;
            CongestionCount = congestionCount;
            PersistentCongestionCount = persistentCongestionCount;
            SendTotalBytes = sendTotalBytes;
            RecvTotalBytes = recvTotalBytes;
        }
    }

    public class QuicConnectionOutFlowStreamStatsEvent : QuicEvent
    {
        public ulong StreamFlowControl { get; }

        public ulong StreamSendWindow { get; }

        public override string PayloadString => string.Format("OUT: StreamFC={0} StreamSndWnd={1}", StreamFlowControl, StreamSendWindow);

        internal QuicConnectionOutFlowStreamStatsEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                                       ulong streamFlowControl, ulong streamSendWindow) :
            base(QuicEventId.ConnOutFlowStreamStats, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            StreamFlowControl = streamFlowControl;
            StreamSendWindow = streamSendWindow;
        }
    }

    public class QuicConnectionMessageEvent : QuicEvent
    {
        public string Message { get; }

        public override string PayloadString => Message;

        internal QuicConnectionMessageEvent(QuicEventId id, Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, string message) :
            base(id, QuicObjectType.Connection, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Message = message;
        }
    }

    #endregion

    #region Stream Events

    public class QuicStreamCreatedEvent : QuicEvent
    {
        public ulong Connection { get; }

        public ulong StreamID { get; }

        public byte IsLocalOwned { get; }

        internal QuicStreamCreatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                        ulong connection, ulong streamId, byte isLocalOwned) :
            base(QuicEventId.StreamCreated, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Connection = connection;
            StreamID = streamId;
            IsLocalOwned = isLocalOwned;
        }
    }

    public class QuicStreamDestroyedEvent : QuicEvent
    {
        public override string PayloadString => "Destroyed";

        internal QuicStreamDestroyedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.StreamDestroyed, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicStreamOutFlowBlockedEvent : QuicEvent
    {
        public byte ReasonFlags { get; }

        internal QuicStreamOutFlowBlockedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, byte reasonFlags) :
            base(QuicEventId.StreamOutFlowBlocked, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ReasonFlags = reasonFlags;
        }
    }

    public class QuicStreamErrorEvent : QuicEvent
    {
        public string ErrorString { get; }

        public override string PayloadString => string.Format("ERROR, {0}", ErrorString);

        internal QuicStreamErrorEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, string errorString) :
            base(QuicEventId.StreamError, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ErrorString = errorString;
        }
    }

    public class QuicStreamErrorStatusEvent : QuicEvent
    {
        public uint Status { get; }

        public string ErrorString { get; }

        public override string PayloadString => string.Format("ERROR, {0}, {1}", Status, ErrorString);

        internal QuicStreamErrorStatusEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint status, string errorString) :
            base(QuicEventId.StreamErrorStatus, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Status = status;
            ErrorString = errorString;
        }
    }

    public class QuicStreamAllocEvent : QuicEvent
    {
        public ulong Connection { get; }

        internal QuicStreamAllocEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong connection) :
            base(QuicEventId.StreamAlloc, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Connection = connection;
        }
    }

    public class QuicStreamWriteFramesEvent : QuicEvent
    {
        public ulong ID { get; }

        internal QuicStreamWriteFramesEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong id) :
            base(QuicEventId.StreamWriteFrames, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ID = id;
        }
    }

    public class QuicStreamReceiveFrameEvent : QuicEvent
    {
        public ulong ID { get; }

        internal QuicStreamReceiveFrameEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, ulong id) :
            base(QuicEventId.StreamReceiveFrame, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ID = id;
        }
    }

    public class QuicStreamAppReceiveEvent : QuicEvent
    {
        internal QuicStreamAppReceiveEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.StreamAppReceive, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicStreamAppReceiveCompleteEvent : QuicEvent
    {
        internal QuicStreamAppReceiveCompleteEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.StreamAppReceiveComplete, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicStreamAppSendEvent : QuicEvent
    {
        internal QuicStreamAppSendEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.StreamAppSend, QuicObjectType.Stream, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    #endregion

    #region Datapath Events

    public class QuicDatapathCreatedEvent : QuicEvent
    {
        public IPEndPoint LocalAddress { get; }

        public IPEndPoint RemoteAddress { get; }

        public override string PayloadString =>
            string.Format("Created, local={0} remote={1}", LocalAddress, RemoteAddress);

        internal QuicDatapathCreatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, IPEndPoint localAddress, IPEndPoint remoteAddress) :
            base(QuicEventId.DatapathCreated, QuicObjectType.Datapath, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            LocalAddress = localAddress;
            RemoteAddress = remoteAddress;
        }
    }

    public class QuicDatapathDestroyedEvent : QuicEvent
    {
        public override string PayloadString => "Destroyed";

        internal QuicDatapathDestroyedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer) :
            base(QuicEventId.DatapathDestroyed, QuicObjectType.Datapath, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
        }
    }

    public class QuicDatapathSendEvent : QuicEvent
    {
        public uint TotalSize { get; }

        public byte BufferCount { get; }

        public ushort SegmentSize { get; }

        public IPEndPoint RemoteAddress { get; }

        public IPEndPoint LocalAddress { get; }

        public override string PayloadString =>
            string.Format("Send {0} bytes in {1} buffers (segment={2}) Src={3} Dst={4}",
                TotalSize, BufferCount, SegmentSize, LocalAddress, RemoteAddress);

        internal QuicDatapathSendEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                       uint totalSize, byte bufferCount, ushort segmentSize, IPEndPoint remoteAddress, IPEndPoint localAddress) :
            base(QuicEventId.DatapathSend, QuicObjectType.Datapath, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            TotalSize = totalSize;
            BufferCount = bufferCount;
            SegmentSize = segmentSize;
            RemoteAddress = remoteAddress;
            LocalAddress = localAddress;
        }
    }

    public class QuicDatapathRecvEvent : QuicEvent
    {
        public uint TotalSize { get; }

        public ushort SegmentSize { get; }

        public IPEndPoint LocalAddress { get; }

        public IPEndPoint RemoteAddress { get; }

        public override string PayloadString =>
            string.Format("Recv {0} bytes (segment={1}) Src={2} Dst={3}",
                TotalSize, SegmentSize, RemoteAddress, LocalAddress);

        internal QuicDatapathRecvEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer,
                                       uint totalSize, ushort segmentSize, IPEndPoint remoteAddress, IPEndPoint localAddress) :
            base(QuicEventId.DatapathRecv, QuicObjectType.Datapath, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            TotalSize = totalSize;
            SegmentSize = segmentSize;
            RemoteAddress = remoteAddress;
            LocalAddress = localAddress;
        }
    }

    public class QuicDatapathErrorEvent : QuicEvent
    {
        public string ErrorString { get; }

        public override string PayloadString => string.Format("ERROR, {0}", ErrorString);

        internal QuicDatapathErrorEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, string errorString) :
            base(QuicEventId.DatapathError, QuicObjectType.Datapath, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            ErrorString = errorString;
        }
    }

    public class QuicDatapathErrorStatusEvent : QuicEvent
    {
        public uint Status { get; }

        public string ErrorString { get; }

        public override string PayloadString => string.Format("ERROR, {0}, {1}", Status, ErrorString);

        internal QuicDatapathErrorStatusEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong objectPointer, uint status, string errorString) :
            base(QuicEventId.DatapathErrorStatus, QuicObjectType.Datapath, timestamp, processor, processId, threadId, pointerSize, objectPointer)
        {
            Status = status;
            ErrorString = errorString;
        }
    }

    #endregion

    #region Packet Events

    public class QuicPacketCreatedEvent : QuicEvent
    {
        public ulong ID => ObjectPointer;

        public ulong BatchID { get; }

        internal QuicPacketCreatedEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong id, ulong id2) :
            base(QuicEventId.PacketCreated, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize, id)
        {
            BatchID = id2;
        }
    }

    public class QuicPacketEncryptEvent : QuicEvent
    {
        public ulong ID => ObjectPointer;

        internal QuicPacketEncryptEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong id) :
            base(QuicEventId.PacketEncrypt, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize, id)
        {
        }
    }

    public class QuicPacketFinalizeEvent : QuicEvent
    {
        public ulong ID => ObjectPointer;

        internal QuicPacketFinalizeEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong id) :
            base(QuicEventId.PacketFinalize, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize, id)
        {
        }
    }

    public class QuicPacketBatchSentEvent : QuicEvent
    {
        public ulong ID => ObjectPointer;

        internal QuicPacketBatchSentEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong id) :
            base(QuicEventId.PacketBatchSent, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize, id)
        {
        }
    }

    public class QuicPacketReceiveEvent : QuicEvent
    {
        public ulong ID => ObjectPointer;

        internal QuicPacketReceiveEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong id) :
            base(QuicEventId.PacketReceive, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize, id)
        {
        }
    }

    public class QuicPacketDecryptEvent : QuicEvent
    {
        public ulong ID => ObjectPointer;

        internal QuicPacketDecryptEvent(Timestamp timestamp, ushort processor, uint processId, uint threadId, int pointerSize, ulong id) :
            base(QuicEventId.PacketDecrypt, QuicObjectType.Global, timestamp, processor, processId, threadId, pointerSize, id)
        {
        }
    }

    #endregion
}
