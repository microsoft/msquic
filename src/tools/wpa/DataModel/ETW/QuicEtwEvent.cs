//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
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

    internal class QuicEtwEvent : QuicEvent
    {
        public override Guid Provider { get; }

        public override QuicEventId ID { get; }

        public override int PointerSize { get; }

        public override uint ProcessId { get; }

        public override uint ThreadId { get; }

        public override ushort Processor { get; }

        public override Timestamp TimeStamp { get; }

        public override QuicObjectType ObjectType { get; }

        public override ulong ObjectPointer { get; }

        public override object? Payload { get; }

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

        private static object? DecodePayload(QuicEventId id, ReadOnlySpan<byte> data, int pointerSize)
        {
            switch (id)
            {
                case QuicEventId.WorkerCreated:
                    return new QuicWorkerCreatedEtwPayload(data, pointerSize);
                case QuicEventId.WorkerActivityStateUpdated:
                    return new QuicWorkerActivityStateUpdatedEtwPayload(data);
                case QuicEventId.WorkerQueueDelayUpdated:
                    return new QuicWorkerQueueDelayUpdatedEtwPayload(data);
                case QuicEventId.ConnCreated:
                case QuicEventId.ConnRundown:
                    return new QuicConnectionCreatedEtwPayload(data);
                case QuicEventId.ConnScheduleState:
                    return new QuicConnectionScheduleStateEtwPayload(data);
                case QuicEventId.ConnExecOper:
                    return new QuicConnectionExecOperEtwPayload(data);
                case QuicEventId.ConnExecApiOper:
                    return new QuicConnectionExecApiOperEtwPayload(data);
                case QuicEventId.ConnExecTimerOper:
                    return new QuicConnectionExecTimerOperEtwPayload(data);
                case QuicEventId.ConnAssignWorker:
                    return new QuicConnectionAssignWorkerEtwPayload(data, pointerSize);
                case QuicEventId.ConnTransportShutdown:
                    return new QuicConnectionTransportShutdownEtwPayload(data);
                case QuicEventId.ConnAppShutdown:
                    return new QuicConnectionAppShutdownEtwPayload(data);
                case QuicEventId.ConnOutFlowStats:
                    return new QuicConnectionOutFlowStatsEtwPayload(data);
                case QuicEventId.ConnOutFlowBlocked:
                    return new QuicConnectionOutFlowBlockedEtwPayload(data);
                case QuicEventId.ConnInFlowStats:
                    return new QuicConnectionInFlowStatsEtwPayload(data);
                case QuicEventId.ConnStats:
                    return new QuicConnectionStatsEtwPayload(data);
                default:
                    return null;
            }
        }

        internal unsafe QuicEtwEvent(TraceEvent evt, Timestamp timestamp)
        {
            Provider = evt.ProviderGuid;
            ID = (QuicEventId)evt.ID;
            PointerSize = evt.PointerSize;
            ProcessId = (uint)evt.ProcessID;
            ThreadId = (uint)evt.ThreadID;
            Processor = (ushort)evt.ProcessorNumber;
            TimeStamp = timestamp;
            ObjectType = ComputeObjectType(evt);
            ReadOnlySpan<byte> data = new ReadOnlySpan<byte>(evt.DataStart.ToPointer(), evt.EventDataLength);
            if (ObjectType != QuicObjectType.Global)
            {
                ObjectPointer = data.ReadPointer(PointerSize);
                Payload = DecodePayload(ID, data, PointerSize);
            }
            else
            {
                Payload = DecodePayload(ID, data, PointerSize);
            }
        }
    }
}
