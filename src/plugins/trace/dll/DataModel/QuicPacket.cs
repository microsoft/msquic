//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public sealed class QuicSendPacket : IQuicObject
    {
        public static QuicSendPacket New(ulong pointer, uint processId) => new QuicSendPacket(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.PacketCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.PacketFinalize;

        public ulong Id { get; }

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        internal QuicPacketBatch? Batch;

        internal List<QuicStream> Streams = new List<QuicStream> { };

        public Timestamp PacketCreate { get; internal set; }
        public Timestamp PacketFirstWrite { get; internal set; }

        internal QuicSendPacket(ulong packetID, uint processId)
        {
            Id = packetID;
            Pointer = packetID;
            ProcessId = processId;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            switch (evt.EventId)
            {
                case QuicEventId.PacketCreated:
                    {
                        var _evt = evt as QuicPacketCreatedEvent;
                        PacketCreate = evt.TimeStamp;
                        Batch = state.PacketBatchSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, _evt!.BatchID, evt.ProcessId));
                        Batch.Packets.Add(this);
                        break;
                    }
                case QuicEventId.PacketEncrypt:
                    foreach (var Stream in Streams)
                    {
                        Stream.Timings.UpdateToState(QuicStreamState.Encrypt, evt.TimeStamp);
                    }
                    break;
                case QuicEventId.PacketFinalize:
                    foreach (var Stream in Streams)
                    {
                        if (Stream.Timings.FirstPacketSend == Timestamp.Zero)
                        {
                            Stream.Timings.FirstPacketSend = evt.TimeStamp;
                        }

                        Stream.Timings.SendPacket = null;
                        Stream.Timings.UpdateToState(QuicStreamState.Send, evt.TimeStamp);
                    }
                    break;
                default:
                    break;
            }
        }
    }

    public sealed class QuicReceivePacket : IQuicObject
    {
        public static QuicReceivePacket New(ulong pointer, uint processId) => new QuicReceivePacket(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.PacketReceive;

        public static ushort DestroyedEventId => (ushort)QuicEventId.PacketFinalize; // Not actually

        public ulong Id { get; }

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        public Timestamp PacketReceive { get; internal set; }
        public Timestamp PacketDecrypt { get; internal set; }
        public Timestamp PacketDecryptComplete { get; internal set; }

        internal QuicReceivePacket(ulong packetID, uint processId)
        {
            Id = packetID;
            Pointer = packetID;
            ProcessId = processId;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            switch (evt.EventId)
            {
                case QuicEventId.PacketReceive:
                    PacketReceive = evt.TimeStamp;
                    break;
                case QuicEventId.PacketDecrypt:
                    PacketDecrypt = evt.TimeStamp;
                    break;
                default:
                    break;
            }
        }
    }

    public sealed class QuicPacketBatch : IQuicObject
    {
        public static QuicPacketBatch New(ulong pointer, uint processId) => new QuicPacketBatch(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.PacketCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.PacketBatchSent;

        public ulong Id { get; }

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        internal List<QuicSendPacket> Packets = new List<QuicSendPacket> { };

        internal QuicPacketBatch(ulong batchID, uint processId)
        {
            Id = batchID;
            Pointer = batchID;
            ProcessId = processId;
        }

        internal void AddEvent(QuicEvent evt, QuicState state)
        {
            switch (evt.EventId)
            {
                case QuicEventId.PacketBatchSent:
                    foreach (var Packet in Packets)
                    {
                        foreach (var Stream in Packet.Streams)
                        {
                            Stream.Timings.UpdateToIdle(evt.TimeStamp);
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
