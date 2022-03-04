//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel.ETW
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
        RPS           = 0x0000000000002000ul,
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
            var data = new QuicEtwDataReader(evt.DataStart.ToPointer(), evt.EventDataLength, pointerSize);

            switch (id)
            {
                case QuicEventId.LibraryInitialized:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryInitializedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt());
                case QuicEventId.LibraryInitializedV2:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryInitializedV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case QuicEventId.DataPathInitialized:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDataPathInitializedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case QuicEventId.LibraryUninitialized:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryUninitializedEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.LibraryAddRef:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryAddRefEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.LibraryRelease:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryReleaseEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.LibraryServerInit:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryServerInitEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.AllocFailure:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicAllocFailureEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadString(), data.ReadULong());
                case QuicEventId.DataPathRundown:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDataPathRundownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case QuicEventId.LibraryRundown:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryRundownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt());
                case QuicEventId.LibraryRundownV2:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryRundownV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case QuicEventId.LibraryError:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadString());
                case QuicEventId.LibraryErrorStatus:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadString());
                case QuicEventId.LibraryAssert:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryAssertEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadString(), data.ReadString());
                case QuicEventId.ApiEnter:
                    return new QuicApiEnterEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadPointer());
                case QuicEventId.ApiExit:
                    return new QuicApiExitEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.ApiExitStatus:
                    return new QuicApiExitStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case QuicEventId.ApiWaitOperation:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicApiWaitOperationEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.PerfCountersRundown:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicPerfCountersRundownEvent(timestamp, processor, processId, threadId, pointerSize);
                case QuicEventId.LibrarySendRetryStateUpdated:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibrarySendRetryStateUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadByte());
                case QuicEventId.LibraryVersion:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryVersionEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt());

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
                case QuicEventId.ConnHandshakeComplete:
                    return new QuicConnectionHandshakeCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
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
                case QuicEventId.ConnHandleClosed:
                    return new QuicConnectionHandleClosedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case QuicEventId.ConnOutFlowStats:
                    return new QuicConnectionOutFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong(), data.ReadULong(), data.ReadUInt());
                case QuicEventId.ConnOutFlowBlocked:
                    return new QuicConnectionOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case QuicEventId.ConnInFlowStats:
                    return new QuicConnectionInFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case QuicEventId.ConnCongestion:
                    return new QuicConnectionCongestionEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case QuicEventId.ConnSourceCidAdded:
                    return new QuicConnectionSourceCidAddedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadBytes());
                case QuicEventId.ConnDestCidAdded:
                    return new QuicConnectionDestinationCidAddedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadBytes());
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
                case QuicEventId.StreamDestroyed:
                    return new QuicStreamDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case QuicEventId.StreamError:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicStreamErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());
                case QuicEventId.StreamErrorStatus:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicStreamErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadString());
                case QuicEventId.StreamAlloc:
                    return new QuicStreamAllocEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case QuicEventId.StreamWriteFrames:
                    return new QuicStreamWriteFramesEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case QuicEventId.StreamReceiveFrame:
                    return new QuicStreamReceiveFrameEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case QuicEventId.StreamAppReceive:
                    return new QuicStreamAppReceiveEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case QuicEventId.StreamAppReceiveComplete:
                    return new QuicStreamAppReceiveCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case QuicEventId.StreamAppSend:
                    return new QuicStreamAppSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());

                case (QuicEventId)9216: // Temporary, while there are still builds out there generating this old event
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), new System.Net.IPEndPoint(0,0));
                case QuicEventId.DatapathSend:
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case QuicEventId.DatapathRecv:
                    return new QuicDatapathRecvEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case QuicEventId.DatapathError:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDatapathErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());
                case QuicEventId.DatapathErrorStatus:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDatapathErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadString());
                case QuicEventId.DatapathCreated:
                    return new QuicDatapathCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadAddress(), data.ReadAddress());
                case QuicEventId.DatapathDestroyed:
                    return new QuicDatapathDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());

                case QuicEventId.LogError:
                case QuicEventId.LogWarning:
                case QuicEventId.LogInfo:
                case QuicEventId.LogVerbose:
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryMessageEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadString());

                case QuicEventId.PacketCreated:
                    return new QuicPacketCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong(), data.ReadULong());
                case QuicEventId.PacketEncrypt:
                    return new QuicPacketEncryptEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case QuicEventId.PacketFinalize:
                    return new QuicPacketFinalizeEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case QuicEventId.PacketBatchSent:
                    return new QuicPacketBatchSentEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case QuicEventId.PacketReceive:
                    return new QuicPacketReceiveEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case QuicEventId.PacketDecrypt:
                    return new QuicPacketDecryptEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());

                default:
                    return null;
            }
        }
    }
}
