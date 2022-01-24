//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    [Flags]
    public enum QuicDataAvailableFlags
    {
        None = 0x0000,
        Api = 0x0001,
        Worker = 0x0002,
        WorkerActivity = 0x0004,
        Connection = 0x0008,
        ConnectionSchedule = 0x0010,
        ConnectionFlowBlocked = 0x0020,
        ConnectionExec = 0x0040,
        ConnectionTput = 0x0080,
        Stream = 0x0100,
        StreamFlowBlocked = 0x0200,
        Datapath = 0x0400
    };

    public readonly struct QuicActivityData
    {
        public Timestamp TimeStamp { get; }

        public TimestampDelta Duration { get; }

        public ushort Processor { get; }

        internal QuicActivityData(Timestamp timeStamp, TimestampDelta duration, ushort processor)
        {
            TimeStamp = timeStamp;
            Duration = duration;
            Processor = processor;
        }
    }

    public readonly struct QuicApiData
    {
        public QuicApiType Type { get; }

        public ushort Processor { get; }

        public uint ProcessId { get; }

        public uint ThreadId { get; }

        public Timestamp TimeStamp { get; }

        public TimestampDelta Duration { get; }

        public ulong Pointer { get; }

        public uint Result { get; }

        internal QuicApiData(QuicApiType type, ushort procesor, uint processId, uint threadId,
            Timestamp timeStamp, TimestampDelta duration, ulong pointer, uint result)
        {
            Type = type;
            Processor = procesor;
            ProcessId = processId;
            ThreadId = threadId;
            TimeStamp = timeStamp;
            Duration = duration;
            Pointer = pointer;
            Result = result;
        }
    }

    public struct QuicDatapathData
    {
        public Timestamp TimeStamp { get; internal set; }

        public TimestampDelta Duration { get; internal set; }

        public ulong TxRate { get; internal set; } // bps

        public ulong RxRate { get; internal set; } // bps

        public ulong BytesSent { get; internal set; }

        public ulong BytesReceived { get; internal set; }

        public ulong SendEventCount { get; internal set; }

        public ulong ReceiveEventCount { get; internal set; }

        public ulong TxBatchRate => SendEventCount == 0 ? 0 : BytesSent / SendEventCount;

        public ulong RxBatchRate => ReceiveEventCount == 0 ? 0 : BytesReceived / ReceiveEventCount;
    }

    public readonly struct QuicExecutionData
    {
        public Timestamp TimeStamp { get; }

        public uint ThreadId { get; }

        public ushort Processor { get; }

        public TimestampDelta Duration { get; }

        public QuicExecutionType Type { get; }

        internal QuicExecutionData(Timestamp timeStamp, uint threadId, ushort procesor, TimestampDelta duration, QuicExecutionType type)
        {
            TimeStamp = timeStamp;
            ThreadId = threadId;
            Processor = procesor;
            Duration = duration;
            Type = type;
        }
    }

    public readonly struct QuicFlowBlockedData
    {
        public Timestamp TimeStamp { get; }

        public TimestampDelta Duration { get; }

        public QuicFlowBlockedFlags Flags { get; }

        internal QuicFlowBlockedData(Timestamp timeStamp, TimestampDelta duration, QuicFlowBlockedFlags flags)
        {
            TimeStamp = timeStamp;
            Duration = duration;
            Flags = flags;
        }
    }

    public readonly struct QuicScheduleData
    {
        public Timestamp TimeStamp { get; }

        public TimestampDelta Duration { get; }

        public uint ThreadId { get; }

        public QuicScheduleState State { get; }

        internal QuicScheduleData(Timestamp timeStamp, TimestampDelta duration, uint threadId, QuicScheduleState state)
        {
            TimeStamp = timeStamp;
            Duration = duration;
            ThreadId = threadId;
            State = state;
        }
    }

    public enum QuicTputDataType
    {
        Tx,         // Sent to UDP
        PktCreate,  // Packet created to be sent
        TxAck,      // Packet(s) bytes acknowledged
        Rx,         // Packet received
        Rtt,
        InFlight,
        CWnd,
        Bufferred,
        ConnFC,
        StreamFC,
        TxDelay
    }

    public struct QuicRawTputData
    {
        public QuicTputDataType Type { get; internal set; }

        public Timestamp TimeStamp { get; internal set; }

        public TimestampDelta Duration { get; internal set; }

        public ulong Value { get; internal set; }
    }
}
