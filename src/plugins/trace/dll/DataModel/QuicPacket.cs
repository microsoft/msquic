//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System.Collections.Generic;
using Microsoft.Performance.SDK;

namespace QuicTrace.DataModel
{
    public sealed class QuicPacket : IQuicObject
    {
        public static QuicPacket New(ulong pointer, uint processId) => new QuicPacket(pointer, processId);

        public static ushort CreateEventId => (ushort)QuicEventId.PacketCreated;

        public static ushort DestroyedEventId => (ushort)QuicEventId.PacketFinalize;

        public ulong Id { get; }

        public ulong Pointer { get; }

        public uint ProcessId { get; }

        internal QuicPacketBatch? Batch;

        internal List<QuicStream> Streams = new List<QuicStream> { };

        public Timestamp PacketCreate { get; internal set; }
        public Timestamp PacketReceive { get; internal set; }
        public Timestamp PacketDecrypt { get; internal set; }
        public Timestamp PacketDecryptComplete { get; internal set; }

        internal QuicPacket(ulong packetID, uint processId)
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
                    PacketCreate = evt.TimeStamp;
                    Batch = state.PacketBatchSet.FindOrCreateActive(evt);
                    Batch.Packets.Add(this);
                    break;
                case QuicEventId.PacketEncrypt:
                    foreach (var Stream in Streams)
                    {
                        if (Stream.Timings.State != QuicStreamState.Write)
                        {
                            Stream.Timings.EncounteredError = true;
                            continue;
                        }

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

        internal List<QuicPacket> Packets = new List<QuicPacket> { };

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
                            if (Stream.Timings.State == QuicStreamState.Send)
                            {
                                Stream.Timings.UpdateToIdle(evt.TimeStamp);
                            }
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
