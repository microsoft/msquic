//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using LTTngCds.CookerData;
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

        // TODO: QuicEtwDataReader to IDataReader
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE2001:Embedded statements must be on their own line", Justification = "<Pending>")]
        internal static unsafe QuicEvent? TryCreate(Timestamp timestamp, QuicEventId id, ushort processor, uint processId, uint threadId, int pointerSize, QuicEtwDataReader data)
        {
            switch (id.ToString())
            {
                case nameof(QuicEventId.LibraryInitialized):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryInitializedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt());
                case nameof(QuicEventId.LibraryInitializedV2):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryInitializedV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.DataPathInitialized):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDataPathInitializedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.LibraryUninitialized):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryUninitializedEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibraryAddRef):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryAddRefEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibraryRelease):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryReleaseEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibraryServerInit):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryServerInitEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.AllocFailure):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicAllocFailureEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadString(), data.ReadULong());
                case nameof(QuicEventId.DataPathRundown):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDataPathRundownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.LibraryRundown):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryRundownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt());
                case nameof(QuicEventId.LibraryRundownV2):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryRundownV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.LibraryError):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadString());
                case nameof(QuicEventId.LibraryErrorStatus):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadString());
                case nameof(QuicEventId.LibraryAssert):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryAssertEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadString(), data.ReadString());
                case nameof(QuicEventId.ApiEnter):
                    return new QuicApiEnterEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadPointer());
                case nameof(QuicEventId.ApiExit):
                    return new QuicApiExitEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.ApiExitStatus):
                    return new QuicApiExitStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.ApiWaitOperation):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicApiWaitOperationEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.PerfCountersRundown):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicPerfCountersRundownEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibrarySendRetryStateUpdated):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibrarySendRetryStateUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadByte());
                case nameof(QuicEventId.LibraryVersion):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryVersionEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt());

                case nameof(QuicEventId.WorkerCreated):
                    return new QuicWorkerCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUShort(), data.ReadPointer());
                case nameof(QuicEventId.WorkerActivityStateUpdated):
                    return new QuicWorkerActivityStateUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte(), data.ReadUInt());
                case nameof(QuicEventId.WorkerQueueDelayUpdated):
                    return new QuicWorkerQueueDelayUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());

                case nameof(QuicEventId.ConnCreated):
                case nameof(QuicEventId.ConnRundown):
                    return new QuicConnectionCreatedEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadULong());
                case nameof(QuicEventId.ConnDestroyed):
                    return new QuicConnectionDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnHandshakeComplete):
                    return new QuicConnectionHandshakeCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnScheduleState):
                    return new QuicConnectionScheduleStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnExecOper):
                    return new QuicConnectionExecOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnExecApiOper):
                    return new QuicConnectionExecApiOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnExecTimerOper):
                    return new QuicConnectionExecTimerOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnAssignWorker):
                    return new QuicConnectionAssignWorkerEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadPointer());
                case nameof(QuicEventId.ConnTransportShutdown):
                    return new QuicConnectionTransportShutdownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadByte(), data.ReadByte());
                case nameof(QuicEventId.ConnAppShutdown):
                    return new QuicConnectionAppShutdownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadByte());
                case nameof(QuicEventId.ConnHandleClosed):
                    return new QuicConnectionHandleClosedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnOutFlowStats):
                    return new QuicConnectionOutFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong(), data.ReadULong(), data.ReadUInt());
                case nameof(QuicEventId.ConnOutFlowBlocked):
                    return new QuicConnectionOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.ConnInFlowStats):
                    return new QuicConnectionInFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.ConnCongestion):
                    return new QuicConnectionCongestionEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnCongestionV2):
                    return new QuicConnectionCongestionV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.ConnSourceCidAdded):
                    return new QuicConnectionSourceCidAddedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadBytes());
                case nameof(QuicEventId.ConnDestCidAdded):
                    return new QuicConnectionDestinationCidAddedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadBytes());
                case nameof(QuicEventId.ConnStats):
                    return new QuicConnectionStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong());
                case nameof(QuicEventId.ConnStatsV2):
                    return new QuicConnectionStatsV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong(), data.ReadUInt());
                case nameof(QuicEventId.ConnOutFlowStreamStats):
                    return new QuicConnectionOutFlowStreamStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadULong());
                case nameof(QuicEventId.ConnLogError):
                case nameof(QuicEventId.ConnLogWarning):
                case nameof(QuicEventId.ConnLogInfo):
                case nameof(QuicEventId.ConnLogVerbose):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicConnectionMessageEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());

                case nameof(QuicEventId.StreamCreated):
                case nameof(QuicEventId.StreamRundown):
                    return new QuicStreamCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadPointer(), data.ReadULong(), data.ReadByte());
                case nameof(QuicEventId.StreamDestroyed):
                    return new QuicStreamDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamOutFlowBlocked):
                    return new QuicStreamOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.StreamSendState):
                    return new QuicStreamSendStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.StreamRecvState):
                    return new QuicStreamRecvStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.StreamError):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicStreamErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());
                case nameof(QuicEventId.StreamErrorStatus):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicStreamErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadString());
                case nameof(QuicEventId.StreamAlloc):
                    return new QuicStreamAllocEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.StreamWriteFrames):
                    return new QuicStreamWriteFramesEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.StreamReceiveFrame):
                    return new QuicStreamReceiveFrameEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.StreamAppReceive):
                    return new QuicStreamAppReceiveEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamAppReceiveComplete):
                    return new QuicStreamAppReceiveCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamAppSend):
                    return new QuicStreamAppSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamReceiveFrameComplete):
                    return new QuicStreamReceiveFrameCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamAppReceiveCompleteCall):
                    return new QuicStreamAppReceiveCompleteCallEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());

                case nameof(QuicEventId.Temporal):
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), new System.Net.IPEndPoint(0, 0));
                case nameof(QuicEventId.DatapathSend):
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case nameof(QuicEventId.DatapathRecv):
                    return new QuicDatapathRecvEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case nameof(QuicEventId.DatapathError):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDatapathErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());
                case nameof(QuicEventId.DatapathErrorStatus):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDatapathErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadString());
                case nameof(QuicEventId.DatapathCreated):
                    return new QuicDatapathCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadAddress(), data.ReadAddress());
                case nameof(QuicEventId.DatapathDestroyed):
                    return new QuicDatapathDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());

                case nameof(QuicEventId.LogError):
                case nameof(QuicEventId.LogWarning):
                case nameof(QuicEventId.LogInfo):
                case nameof(QuicEventId.LogVerbose):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryMessageEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadString());

                case nameof(QuicEventId.PacketCreated):
                    return new QuicPacketCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong(), data.ReadULong());
                case nameof(QuicEventId.PacketEncrypt):
                    return new QuicPacketEncryptEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketFinalize):
                    return new QuicPacketFinalizeEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketBatchSent):
                    return new QuicPacketBatchSentEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketReceive):
                    return new QuicPacketReceiveEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketDecrypt):
                    return new QuicPacketDecryptEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());

                default:
                    return null;
            }
        }

        internal static unsafe QuicEvent? TryCreate(Timestamp timestamp, QuicEventId id, ushort processor, uint processId, uint threadId, int pointerSize, QuicLTTngDataReader data)
        {
            switch (id.ToString())
            {
                case nameof(QuicEventId.LibraryInitialized):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryInitializedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt());
                case nameof(QuicEventId.LibraryInitializedV2):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryInitializedV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.DataPathInitialized):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDataPathInitializedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.LibraryUninitialized):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryUninitializedEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibraryAddRef):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryAddRefEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibraryRelease):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryReleaseEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibraryServerInit):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryServerInitEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.AllocFailure):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicAllocFailureEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadString(), data.ReadULong());
                case nameof(QuicEventId.DataPathRundown):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDataPathRundownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.LibraryRundown):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryRundownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt());
                case nameof(QuicEventId.LibraryRundownV2):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryRundownV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.LibraryError):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadString());
                case nameof(QuicEventId.LibraryErrorStatus):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadString());
                case nameof(QuicEventId.LibraryAssert):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryAssertEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadString(), data.ReadString());
                case nameof(QuicEventId.ApiEnter):
                    return new QuicApiEnterEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadPointer());
                case nameof(QuicEventId.ApiExit):
                    return new QuicApiExitEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.ApiExitStatus):
                    return new QuicApiExitStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt());
                case nameof(QuicEventId.ApiWaitOperation):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicApiWaitOperationEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.PerfCountersRundown):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicPerfCountersRundownEvent(timestamp, processor, processId, threadId, pointerSize);
                case nameof(QuicEventId.LibrarySendRetryStateUpdated):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibrarySendRetryStateUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadByte());
                case nameof(QuicEventId.LibraryVersion):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryVersionEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt());

                case nameof(QuicEventId.WorkerCreated):
                    return new QuicWorkerCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUShort(), data.ReadPointer());
                case nameof(QuicEventId.WorkerActivityStateUpdated):
                    return new QuicWorkerActivityStateUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte(), data.ReadUInt());
                case nameof(QuicEventId.WorkerQueueDelayUpdated):
                    return new QuicWorkerQueueDelayUpdatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());

                case nameof(QuicEventId.ConnCreated):
                case nameof(QuicEventId.ConnRundown):
                    return new QuicConnectionCreatedEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadULong());
                case nameof(QuicEventId.ConnDestroyed):
                    return new QuicConnectionDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnHandshakeComplete):
                    return new QuicConnectionHandshakeCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnScheduleState):
                    return new QuicConnectionScheduleStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnExecOper):
                    return new QuicConnectionExecOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnExecApiOper):
                    return new QuicConnectionExecApiOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnExecTimerOper):
                    return new QuicConnectionExecTimerOperEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt());
                case nameof(QuicEventId.ConnAssignWorker):
                    return new QuicConnectionAssignWorkerEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadPointer());
                case nameof(QuicEventId.ConnTransportShutdown):
                    return new QuicConnectionTransportShutdownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadByte(), data.ReadByte());
                case nameof(QuicEventId.ConnAppShutdown):
                    return new QuicConnectionAppShutdownEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadByte());
                case nameof(QuicEventId.ConnHandleClosed):
                    return new QuicConnectionHandleClosedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnOutFlowStats):
                    return new QuicConnectionOutFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong(), data.ReadULong(), data.ReadUInt());
                case nameof(QuicEventId.ConnOutFlowBlocked):
                    return new QuicConnectionOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.ConnInFlowStats):
                    return new QuicConnectionInFlowStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.ConnCongestion):
                    return new QuicConnectionCongestionEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.ConnCongestionV2):
                    return new QuicConnectionCongestionV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.ConnSourceCidAdded):
                    return new QuicConnectionSourceCidAddedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadBytes());
                case nameof(QuicEventId.ConnDestCidAdded):
                    return new QuicConnectionDestinationCidAddedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadBytes());
                case nameof(QuicEventId.ConnStats):
                    return new QuicConnectionStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong());
                case nameof(QuicEventId.ConnStatsV2):
                    return new QuicConnectionStatsV2Event(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUInt(), data.ReadUInt(), data.ReadULong(), data.ReadULong(), data.ReadUInt());
                case nameof(QuicEventId.ConnOutFlowStreamStats):
                    return new QuicConnectionOutFlowStreamStatsEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong(), data.ReadULong());
                case nameof(QuicEventId.ConnLogError):
                case nameof(QuicEventId.ConnLogWarning):
                case nameof(QuicEventId.ConnLogInfo):
                case nameof(QuicEventId.ConnLogVerbose):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicConnectionMessageEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());

                case nameof(QuicEventId.StreamCreated):
                case nameof(QuicEventId.StreamRundown):
                    return new QuicStreamCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadPointer(), data.ReadULong(), data.ReadByte());
                case nameof(QuicEventId.StreamDestroyed):
                    return new QuicStreamDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamOutFlowBlocked):
                    return new QuicStreamOutFlowBlockedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.StreamSendState):
                    return new QuicStreamSendStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.StreamRecvState):
                    return new QuicStreamRecvStateEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadByte());
                case nameof(QuicEventId.StreamError):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicStreamErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());
                case nameof(QuicEventId.StreamErrorStatus):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicStreamErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadString());
                case nameof(QuicEventId.StreamAlloc):
                    return new QuicStreamAllocEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.StreamWriteFrames):
                    return new QuicStreamWriteFramesEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.StreamReceiveFrame):
                    return new QuicStreamReceiveFrameEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadULong());
                case nameof(QuicEventId.StreamAppReceive):
                    return new QuicStreamAppReceiveEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamAppReceiveComplete):
                    return new QuicStreamAppReceiveCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamAppSend):
                    return new QuicStreamAppSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamReceiveFrameComplete):
                    return new QuicStreamReceiveFrameCompleteEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());
                case nameof(QuicEventId.StreamAppReceiveCompleteCall):
                    return new QuicStreamAppReceiveCompleteCallEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());

                case nameof(QuicEventId.Temporal):
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), new System.Net.IPEndPoint(0, 0));
                case nameof(QuicEventId.DatapathSend):
                    return new QuicDatapathSendEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadByte(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case nameof(QuicEventId.DatapathRecv):
                    return new QuicDatapathRecvEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadUShort(), data.ReadAddress(), data.ReadAddress());
                case nameof(QuicEventId.DatapathError):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDatapathErrorEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadString());
                case nameof(QuicEventId.DatapathErrorStatus):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicDatapathErrorStatusEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadUInt(), data.ReadString());
                case nameof(QuicEventId.DatapathCreated):
                    return new QuicDatapathCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer(), data.ReadAddress(), data.ReadAddress());
                case nameof(QuicEventId.DatapathDestroyed):
                    return new QuicDatapathDestroyedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadPointer());

                case nameof(QuicEventId.LogError):
                case nameof(QuicEventId.LogWarning):
                case nameof(QuicEventId.LogInfo):
                case nameof(QuicEventId.LogVerbose):
                    if (QuicEvent.ParseMode != QuicEventParseMode.Full) return null;
                    return new QuicLibraryMessageEvent(id, timestamp, processor, processId, threadId, pointerSize, data.ReadString());

                case nameof(QuicEventId.PacketCreated):
                    return new QuicPacketCreatedEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong(), data.ReadULong());
                case nameof(QuicEventId.PacketEncrypt):
                    return new QuicPacketEncryptEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketFinalize):
                    return new QuicPacketFinalizeEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketBatchSent):
                    return new QuicPacketBatchSentEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketReceive):
                    return new QuicPacketReceiveEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());
                case nameof(QuicEventId.PacketDecrypt):
                    return new QuicPacketDecryptEvent(timestamp, processor, processId, threadId, pointerSize, data.ReadULong());

                default:
                    return null;
            }
        }

        internal static unsafe QuicEvent? TryCreate(LTTngEvent evt)
        {
            var idstring = evt.Name.Substring(evt.Name.IndexOf(':') + 1);
            QuicEventId id;
            if (!Enum.TryParse(idstring, out id))
                return null;
            var timestamp = evt.Timestamp;
            var processId = UInt32.Parse(evt.StreamDefinedEventContext.FieldsByName["_vpid"].GetValueAsString());
            var threadId = UInt32.Parse(evt.StreamDefinedEventContext.FieldsByName["_vtid"].GetValueAsString());
            int pointerSize = 8;
            var data = new QuicLTTngDataReader(evt.Payload, pointerSize);
            return TryCreate(timestamp, id, 0, processId, threadId, pointerSize, data);
        }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE2001:Embedded statements must be on their own line", Justification = "<Pending>")]
        internal static unsafe QuicEvent? TryCreate(TraceEvent evt, Timestamp timestamp)
        {
            var processor = (ushort)evt.ProcessorNumber;
            var processId = (uint)evt.ProcessID;
            var threadId = (uint)evt.ThreadID;
            var pointerSize = evt.PointerSize;
            var data = new QuicEtwDataReader(evt.DataStart.ToPointer(), evt.EventDataLength, pointerSize);
            return TryCreate(timestamp, (QuicEventId)evt.ID, processor, processId, threadId, pointerSize, data);
        }
    }
}
