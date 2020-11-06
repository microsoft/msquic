//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MsQuicTracing.DataModel
{
    public enum QuicScheduleState
    {
        Idle,
        Queued,
        Processing
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

    internal static class SpanHelpers
    {
        internal static T ReadValue<T>(this ref ReadOnlySpan<byte> data) where T : unmanaged
        {
            T val = MemoryMarshal.Cast<byte, T>(data)[0];
            data = data.Slice(Unsafe.SizeOf<T>());
            return val;
        }
        internal static ulong ReadPointer(this ref ReadOnlySpan<byte> data, int pointerSize)
        {
            return pointerSize == 8 ? data.ReadValue<ulong>() : data.ReadValue<uint>();
        }
    }

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

    public class QuicConnectionCreatedPayload
    {
        public uint IsServer { get; protected set; }

        public ulong CorrelationId { get; protected set; }
    }

    public class QuicConnectionScheduleStatePayload
    {
        public uint State { get; protected set; }
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
}
