//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Net;
using System.Runtime.InteropServices;

namespace MsQuicTracing.DataModel
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
        Processing
    }

    internal static class SpanHelpers
    {
        internal static unsafe T ReadValue<T>(this ref ReadOnlySpan<byte> data) where T : unmanaged
        {
            T val = MemoryMarshal.Cast<byte, T>(data)[0];
            data = data.Slice(sizeof(T));
            return val;
        }

        internal static ulong ReadPointer(this ref ReadOnlySpan<byte> data, int pointerSize)
        {
            return pointerSize == 8 ? data.ReadValue<ulong>() : data.ReadValue<uint>();
        }

        internal static IPEndPoint ReadAddress(this ref ReadOnlySpan<byte> data)
        {
            byte length = data.ReadValue<byte>();
            var buf = data.Slice(0, length);
            data = data.Slice(length);

            int family = buf[0] | ((ushort)buf[1] << 8);
            int port = (ushort)buf[3] | ((ushort)buf[2] << 8);

            if (family == 0) // unspecified
            {
                return new IPEndPoint(IPAddress.Any, port);
            }
            else if (family == 2) // v4
            {
                return new IPEndPoint(new IPAddress(buf.Slice(4, 4)), port);
            }
            else // v6
            {
                return new IPEndPoint(new IPAddress(buf.Slice(4, 16)), port);
            }
        }
    }

    #region Global Event Payloads

    public class QuicApiEnterPayload
    {
        public uint Type { get; protected set; }

        public ulong Handle { get; protected set; }
    }

    public class QuicApiExitStatusPayload
    {
        public uint Status { get; protected set; }
    }

    #endregion

    #region Worker Event Payloads

    public class QuicWorkerCreatedPayload
    {
        public ushort IdealProcessor { get; protected set; }

        public ulong OwnerPointer { get; protected set; }
    }

    public class QuicWorkerActivityStateUpdatedPayload
    {
        public byte IsActive { get; protected set; }

        public uint Arg { get; protected set; }
    }

    public class QuicWorkerQueueDelayUpdatedPayload
    {
        public uint QueueDelay { get; protected set; }
    }

    #endregion

    #region Connection Event Payloads

    public class QuicConnectionCreatedPayload
    {
        public uint IsServer { get; protected set; }

        public ulong CorrelationId { get; protected set; }
    }

    public class QuicConnectionScheduleStatePayload
    {
        public uint State { get; protected set; }
    }

    public class QuicConnectionExecOperPayload
    {
        public uint Type { get; protected set; }
    }

    public class QuicConnectionExecApiOperPayload
    {
        public uint Type { get; protected set; }
    }

    public class QuicConnectionExecTimerOperPayload
    {
        public uint Type { get; protected set; }
    }

    public class QuicConnectionAssignWorkerPayload
    {
        public ulong WorkerPointer { get; protected set; }
    }

    public class QuicConnectionTransportShutdownPayload
    {
        public ulong ErrorCode { get; protected set; }

        public byte IsRemoteShutdown { get; protected set; }

        public byte IsQuicStatus { get; protected set; }
    }

    public class QuicConnectionAppShutdownPayload
    {
        public ulong ErrorCode { get; protected set; }

        public byte IsRemoteShutdown { get; protected set; }
    }

    public class QuicConnectionOutFlowStatsPayload
    {
        public ulong BytesSent { get; protected set; }

        public uint BytesInFlight { get; protected set; }

        public uint BytesInFlightMax { get; protected set; }

        public uint CongestionWindow { get; protected set; }

        public uint SlowStartThreshold { get; protected set; }

        public ulong ConnectionFlowControl { get; protected set; }

        public ulong IdealBytes { get; protected set; }

        public ulong PostedBytes { get; protected set; }

        public uint SmoothedRtt { get; protected set; }
    }

    public class QuicConnectionOutFlowBlockedPayload
    {
        public byte ReasonFlags { get; protected set; }
    }

    public class QuicConnectionInFlowStatsPayload
    {
        public ulong BytesRecv { get; protected set; }
    }

    public class QuicConnectionStatsPayload
    {
        public uint SmoothedRtt { get; protected set; }

        public uint CongestionCount { get; protected set; }

        public uint PersistentCongestionCount { get; protected set; }

        public ulong SendTotalBytes { get; protected set; }

        public ulong RecvTotalBytes { get; protected set; }
    }

    public class QuicConnectionOutFlowStreamStatsPayload
    {
        public ulong StreamFlowControl { get; protected set; }

        public ulong StreamSendWindow { get; protected set; }
    }

    #endregion

    #region Stream Event Payloads

    public class QuicStreamCreatedPayload
    {
        public ulong Connection { get; protected set; }

        public ulong ID { get; protected set; }

        public byte IsLocalOwned { get; protected set; }
    }

    public class QuicStreamOutFlowBlockedPayload
    {
        public byte ReasonFlags { get; protected set; }
    }

    #endregion

    #region Datapath Event Payloads

    public class QuicDatapathSendPayload
    {
        public uint TotalSize { get; protected set; }

        public byte BufferCount { get; protected set; }

        public ushort SegmentSize { get; protected set; }

#pragma warning disable CS8618 // Non-nullable field is uninitialized.
        public IPEndPoint RemoteAddress { get; protected set; }

        public IPEndPoint LocalAddress { get; protected set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized.
    }

    public class QuicDatapathRecvPayload
    {
        public uint TotalSize { get; protected set; }

        public ushort SegmentSize { get; protected set; }

#pragma warning disable CS8618 // Non-nullable field is uninitialized.
        public IPEndPoint LocalAddress { get; protected set; }

        public IPEndPoint RemoteAddress { get; protected set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized.
    }

    #endregion
}
