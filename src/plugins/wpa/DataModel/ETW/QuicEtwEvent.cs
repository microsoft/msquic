//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK;

namespace MsQuicTracing.DataModel.ETW
{
    [Flags]
    internal enum QuicEtwEventKeywords : ulong
    {
        Registration  = 0x0000000000000001ul,
        Configuration = 0x0000000000000002ul,
        Listener      = 0x0000000000000004ul,
        Worker        = 0x0000000000000008ul,
        Binding       = 0x0000000000000010ul,
        Connection    = 0x0000000000000020ul,
        Stream        = 0x0000000000000040ul,
        UDP           = 0x0000000000000080ul,
        Packet        = 0x0000000000000100ul,
        TLS           = 0x0000000000000200ul,
        Platform      = 0x0000000000000400ul,
        Api           = 0x0000000000000800ul,
        Log           = 0x0000000000001000ul,
        LowVolume     = 0x0000000080000000ul,
        DataFlow      = 0x0000000040000000ul,
        Scheduling    = 0x0000000020000000ul,
    }

    internal enum QuicEtwEventOpcode : byte
    {
        Global = 11,
        Registration,
        Configuration,
        Worker,
        Listener,
        Binding,
        Connection,
        Stream,
        Datapath
    }

    internal unsafe ref struct EtwDataReader
    {
        private ReadOnlySpan<byte> Data;

        private readonly int PointerSize;

        internal EtwDataReader(void* pointer, int length, int pointerSize)
        {
            Data = new ReadOnlySpan<byte>(pointer, length);
            PointerSize = pointerSize;
        }

        internal unsafe T ReadValue<T>() where T : unmanaged
        {
            T val = MemoryMarshal.Cast<byte, T>(Data)[0];
            Data = Data.Slice(sizeof(T));
            return val;
        }

        internal byte ReadByte() => ReadValue<byte>();

        internal ushort ReadUShort() => ReadValue<ushort>();

        internal uint ReadUInt() => ReadValue<uint>();

        internal ulong ReadULong() => ReadValue<ulong>();

        internal ulong ReadPointer()
        {
            return PointerSize == 8 ? ReadValue<ulong>() : ReadValue<uint>();
        }

        internal string ReadString()
        {
            var chars = new List<char>();
            while (true)
            {
                byte c = ReadValue<byte>();
                if (c == 0)
                {
                    break;
                }
                chars.Add((char)c);
            }
            return new string(chars.ToArray());
        }

        internal IPEndPoint ReadAddress()
        {
            byte length = ReadValue<byte>();
            var buf = Data.Slice(0, length);
            Data = Data.Slice(length);

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

    internal static class QuicEtwEvent
    {
        private static QuicObjectType ComputeObjectType(TraceEvent evt)
        {
            if ((byte)evt.Opcode >= (byte)QuicEtwEventOpcode.Global)
            {
                //
                // If using the new opcodes, calculate object type from opcode. (fast method)
                //
                return (QuicObjectType)((byte)evt.Opcode - (byte)QuicEtwEventOpcode.Global);
            }
            else
            {
                var keywords = (QuicEtwEventKeywords)evt.Keywords;

                //
                // If using the old opcodes, calculate object type from keyword flags. (slow method)
                //
                if (keywords.HasFlag(QuicEtwEventKeywords.Registration))
                {
                    return QuicObjectType.Registration;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.Configuration))
                {
                    return QuicObjectType.Configuration;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.Listener))
                {
                    return QuicObjectType.Listener;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.Worker))
                {
                    return QuicObjectType.Worker;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.Binding))
                {
                    return QuicObjectType.Binding;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.Connection) || keywords.HasFlag(QuicEtwEventKeywords.TLS))
                {
                    return QuicObjectType.Connection;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.Stream))
                {
                    return QuicObjectType.Stream;
                }
                else if (keywords.HasFlag(QuicEtwEventKeywords.UDP))
                {
                    return QuicObjectType.Datapath;
                }
                else
                {
                    return QuicObjectType.Global;
                }
            }
        }

        internal static unsafe QuicEvent? TryCreate(TraceEvent evt, Timestamp timestamp)
        {
            var id = (QuicEventId)evt.ID;
            var processor = (ushort)evt.ProcessorNumber;
            var processId = (uint)evt.ProcessID;
            var threadId = (uint)evt.ThreadID;
            var pointerSize = evt.PointerSize;
            var data = new EtwDataReader(evt.DataStart.ToPointer(), evt.EventDataLength, pointerSize);

            switch (id)
            {
                case QuicEventId.ApiEnter:
                    return new QuicApiEnterEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadPointer());
                case QuicEventId.ApiExit:
                    return new QuicApiExitEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.ApiExitStatus:
                    return new QuicApiExitStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());

                case QuicEventId.WorkerCreated:
                    return new QuicWorkerCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUShort(), data.ReadPointer());
                case QuicEventId.WorkerActivityStateUpdated:
                    return new QuicWorkerActivityStateUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte(), data.ReadUInt());
                case QuicEventId.WorkerQueueDelayUpdated:
                    return new QuicWorkerQueueDelayUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());

                case QuicEventId.ConnCreated:
                case QuicEventId.ConnRundown:
                    return new QuicConnectionCreatedEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadULong());
                case QuicEventId.ConnDestroyed:
                    return new QuicConnectionDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case QuicEventId.ConnScheduleState:
                    return new QuicConnectionScheduleStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case QuicEventId.ConnExecOper:
                    return new QuicConnectionExecOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case QuicEventId.ConnExecApiOper:
                    return new QuicConnectionExecApiOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case QuicEventId.ConnExecTimerOper:
                    return new QuicConnectionExecTimerOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case QuicEventId.ConnAssignWorker:
                    return new QuicConnectionAssignWorkerEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadPointer());
                case QuicEventId.ConnTransportShutdown:
                    return new QuicConnectionTransportShutdownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadByte(), data.ReadByte());
                case QuicEventId.ConnAppShutdown:
                    return new QuicConnectionAppShutdownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadByte());
                case QuicEventId.ConnOutFlowStats:
                    return new QuicConnectionOutFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong(), data.ReadULong(), data.ReadUInt());
                case QuicEventId.ConnOutFlowBlocked:
                    return new QuicConnectionOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case QuicEventId.ConnInFlowStats:
                    return new QuicConnectionInFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case QuicEventId.ConnStats:
                    return new QuicConnectionStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong());
                case QuicEventId.ConnOutFlowStreamStats:
                    return new QuicConnectionOutFlowStreamStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadULong());
                case QuicEventId.ConnLogError:
                case QuicEventId.ConnLogWarning:
                case QuicEventId.ConnLogInfo:
                case QuicEventId.ConnLogVerbose:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicConnectionMessageEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());

                case QuicEventId.StreamCreated:
                case QuicEventId.StreamRundown:
                    return new QuicStreamCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadPointer(), data.ReadULong(), data.ReadByte());
                case QuicEventId.StreamOutFlowBlocked:
                    return new QuicStreamOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());

                case QuicEventId.DatapathSend:
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case QuicEventId.DatapathRecv:
                    return new QuicDatapathRecvEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());

                default:
                    return null;
            }
        }
    }
}
