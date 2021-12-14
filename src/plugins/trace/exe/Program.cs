//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.Toolkit.Engine;
using QuicTrace.DataModel;

namespace QuicTrace
{
    class Program
    {
        static void PrintCommands()
        {
            Console.WriteLine(
                "\n" +
                "Commands:\n" +
                "  -p, --print           Prints events as text\n" +
                "  -r, --report          Prints out an analysis of possible problems in the trace\n" +
                "  -s, --rps             Prints out an analysis RPS-related events in the trace\n"
                );
        }

        static void PrintArgs()
        {
            Console.WriteLine(
                "\n" +
                "Quic Trace Analyzer\n" +
                "\n" +
                "quictrace <options> [command]\n" +
                "\n" +
                "Options:\n" +
                "  -c, --capture         Captures local events to analyze\n" +
                "  -f, --file <file>     Opens a local file of events to analyze\n" +
                "  -h, --help            Prints out help text\n" +
                "  -t, --text            Enables additional trace processing to allow for full text output"
                );
            PrintCommands();
        }

        static string? CaptureLocalTrace()
        {
            const string fileName = "C:\\Windows\\System32\\LogFiles\\WMI\\quicetw.etl";
            const string name = "quicetw";
            Guid providerGuid = Guid.Parse("{ff15e657-4f26-570e-88ab-0796b258d11c}");


            using var session = new TraceEventSession(name, fileName);
            Console.WriteLine(session.EnableProvider(providerGuid, Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose, matchAnyKeywords: 0));

            Thread.Sleep(250); // Just let the rundowns fire.

            return fileName;
        }

        static QuicState[] ProcessTraceFiles(IEnumerable<string> filePaths)
        {
            var quicStates = new List<QuicState>();
            foreach (var filePath in filePaths)
            {
                //
                // Create our runtime environment, add file, enable cookers, and process.
                //
                PluginSet pluginSet;

                if (string.IsNullOrWhiteSpace(typeof(QuicEtwSource).Assembly.Location))
                {
                    // Single File EXE
                    pluginSet = PluginSet.Load(new[] { Environment.CurrentDirectory }, new SingleFileAssemblyLoader());
                }
                else
                {
                    pluginSet = PluginSet.Load();
                }

                using var dataSources = DataSourceSet.Create(pluginSet);
                dataSources.AddFile(filePath);
                var info = new EngineCreateInfo(dataSources.AsReadOnly());
                using var runtime = Engine.Create(info);
                runtime.EnableCooker(QuicEventCooker.CookerPath);
                Console.WriteLine("Processing...");
                var results = runtime.Process();
                Console.WriteLine("Done.\n");

                //
                // Return our 'cooked' data.
                //
                quicStates.Add(results.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State")));
            }

            return quicStates.ToArray();
        }

        static void RunReport(QuicState quicState)
        {
            //
            // Worker info
            //

            var workers = quicState.Workers;
            Console.WriteLine("\nWORKERS ({0})\n", workers.Count);

            uint unhealthyWorkers = 0;
            uint mostlyIdleWorkers = 0;
            uint reallyActiveWorkers = 0;

            const uint UnhealthyQueueDelayUs = 25 * 1000; // More than 25 ms queue delay is "unhealthy"

            foreach (var worker in workers)
            {
                if (worker.AverageQueueDelayUs >= UnhealthyQueueDelayUs)
                {
                    unhealthyWorkers++;
                }

                if (worker.ActivePercent <= 5)
                {
                    mostlyIdleWorkers++;
                }
                else if (worker.ActivePercent >= 80)
                {
                    reallyActiveWorkers++;
                }
            }

            if (unhealthyWorkers == 0)
            {
                Console.WriteLine("  All workers healthy.");
            }
            else
            {
                Console.Write("  {0} workers unhealthy: [", unhealthyWorkers);
                unhealthyWorkers = 0;
                foreach (var worker in workers)
                {
                    if (worker.AverageQueueDelayUs >= UnhealthyQueueDelayUs)
                    {
                        if (unhealthyWorkers != 0)
                        {
                            Console.Write(", ");
                        }
                        Console.Write("#{0}", worker.Id);
                        unhealthyWorkers++;
                    }
                }
                Console.WriteLine("]");
            }

            Console.WriteLine("  {0} workers mostly idle.", mostlyIdleWorkers);
            Console.WriteLine("  {0} workers really active.", reallyActiveWorkers);

            //
            // Connection info
            //

            var conns = quicState.Connections;
            Console.WriteLine("\nCONNECTIONS ({0})\n", conns.Count);

            //
            // TODO - Dump Connection info
            //
        }

        internal class RequestTiming
        {
            public ulong StreamAlloc = 0;
            public ulong PacketWrite = 0;
            public ulong PacketEncrypt = 0;
            public ulong PacketFinalize = 0;
            public ulong PacketSend = 0;
            public ulong PacketReceive = 0;
            public ulong PacketDecrypt = 0;
            public ulong PacketRead = 0;
            public ulong StreamFlush = 0;
            public ulong StreamDelete = 0;

            public ulong ConnectionQueueTime = 0;

            public ulong StreamID = ulong.MaxValue;

            public ulong[] ToArray() { return new ulong[] { StreamAlloc, PacketWrite, PacketEncrypt, PacketFinalize, PacketSend, PacketReceive, PacketDecrypt, PacketRead, StreamFlush, StreamDelete }; }

            public bool IsIncomplete { get { return ToArray().Min() == 0 || StreamID == ulong.MaxValue; } }

            public bool IsServer {  get { return PacketReceive < StreamAlloc; } }

            public ulong Latency { get { return StreamDelete - StreamAlloc; } }

            public ulong Min { get { return ToArray().Min(); } }

            public ulong QueueTime { get { return PacketWrite - StreamAlloc; } }
            public ulong WriteTime { get { return PacketEncrypt - PacketWrite; } }
            public ulong EncryptTime { get { return PacketFinalize - PacketEncrypt; } }
            public ulong FinalizeTime { get { return PacketSend - PacketFinalize; } }
            public ulong PeerTime { get { return Peer == null ? 0 : Peer.PacketSend - Peer.PacketReceive; } }
            public ulong RecvTime { get { return PacketDecrypt - PacketReceive; } }
            public ulong DecryptTime { get { return PacketRead > PacketDecrypt ? PacketRead - PacketDecrypt : 0; } }
            public ulong ReadTime { get { return StreamFlush > PacketRead ? StreamFlush - PacketRead : 0; } }
            public ulong FlushTime { get { return StreamDelete - StreamFlush; } }

            public ulong UdpTime { get { return (PacketReceive - PacketSend) - PeerTime; } }

            public QuicRequestConn? Connection = null;

            public RequestTiming? Peer = null;

            public void WriteLine()
            {
                ulong min = Min;
                Console.WriteLine(
                    "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}",
                    StreamAlloc - min,
                    PacketWrite - min,
                    PacketEncrypt - min,
                    PacketFinalize - min,
                    PacketSend - min,
                    PacketReceive - min,
                    PacketDecrypt - min,
                    PacketRead - min,
                    StreamFlush - min,
                    StreamDelete - min);
            }

            public void WriteLine2()
            {
                Console.WriteLine(
                    "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}",
                    Latency,
                    QueueTime,
                    WriteTime,
                    EncryptTime,
                    FinalizeTime,
                    PeerTime,
                    UdpTime,
                    RecvTime,
                    DecryptTime,
                    ReadTime,
                    FlushTime);
            }
        }

        internal class QuicRequestConn : IQuicObject
        {
            public static QuicRequestConn New(ulong pointer, uint processId) => new QuicRequestConn(pointer, processId);

            public static ushort CreateEventId => (ushort)QuicEventId.ConnSourceCidAdded;

            public static ushort DestroyedEventId => 0;

            public ulong Id { get; }

            private static ulong NextId = 1;

            public ulong Pointer { get; }

            public uint ProcessId { get; }

            public QuicRequestConn? Peer = null;

            public QuicScheduleState LastProcessingState = QuicScheduleState.Idle;
            public ulong LastProcessingTime = 0;

            internal QuicRequestConn(ulong pointer, uint processId)
            {
                Id = NextId++;
                Pointer = pointer;
                ProcessId = processId;
            }
        }

        internal class QuicPacketBatch : IQuicObject
        {
            public static QuicPacketBatch New(ulong pointer, uint processId) => new QuicPacketBatch(pointer, processId);

            public static ushort CreateEventId => (ushort)QuicEventId.PacketBatchCreate;

            public static ushort DestroyedEventId => 0;

            public ulong Id { get; }

            public ulong Pointer { get; }

            public uint ProcessId { get; }

            public ulong PacketSend = 0;

            internal QuicPacketBatch(ulong pointer, uint processId)
            {
                Id = pointer;
                Pointer = pointer;
                ProcessId = processId;
            }
        }

        internal class QuicPacket : IQuicObject
        {
            public static QuicPacket New(ulong pointer, uint processId) => new QuicPacket(pointer, processId);

            public static ushort CreateEventId => (ushort)QuicEventId.PacketCreated;

            public static ushort DestroyedEventId => 0;

            public ulong Id { get; }

            public ulong Pointer { get; }

            public uint ProcessId { get; }

            public QuicPacketBatch? Batch = null;

            public ulong PacketEncrypt = 0;
            public ulong PacketFinalize = 0;
            public ulong PacketReceive = 0;
            public ulong PacketDecrypt = 0;
            public ulong PacketRead = 0;

            internal QuicPacket(ulong pointer, uint processId)
            {
                Id = pointer;
                Pointer = pointer;
                ProcessId = processId;
            }
        }

        internal class QuicStreamRequest : IQuicObject
        {
            public static QuicStreamRequest New(ulong pointer, uint processId) => new QuicStreamRequest(pointer, processId);

            public static ushort CreateEventId => (ushort)QuicEventId.StreamAlloc;

            public static ushort DestroyedEventId => (ushort)QuicEventId.StreamDestroyed;

            public ulong Id { get; }

            private static ulong NextId = 1;

            public ulong Pointer { get; }

            public uint ProcessId { get; }

            public RequestTiming Timings { get; }

            public QuicPacket? SendPacket = null;

            public QuicPacket? RecvPacket = null;

            internal QuicStreamRequest(ulong pointer, uint processId)
            {
                Id = NextId++;
                Pointer = pointer;
                ProcessId = processId;
                Timings = new RequestTiming();
            }
        }

        class SequentialByteComparer : IEqualityComparer<byte[]>
        {
#pragma warning disable CS8767 // Nullability of reference types in type of parameter doesn't match implicitly implemented member (possibly because of nullability attributes).
            public bool Equals(byte[] x, byte[] y) => StructuralComparisons.StructuralEqualityComparer.Equals(x, y);
#pragma warning restore CS8767 // Nullability of reference types in type of parameter doesn't match implicitly implemented member (possibly because of nullability attributes).
            public int GetHashCode([System.Diagnostics.CodeAnalysis.DisallowNull] byte[] obj)
            {
                return StructuralComparisons.StructuralEqualityComparer.GetHashCode(obj);
            }
        }

        static void RunRpsAnalysis(QuicState[] quicStates)
        {
            var ConnSet = new QuicObjectSet<QuicRequestConn>(QuicRequestConn.CreateEventId, QuicRequestConn.DestroyedEventId, QuicRequestConn.New);
            var StreamSet = new QuicObjectSet<QuicStreamRequest>(QuicStreamRequest.CreateEventId, QuicStreamRequest.DestroyedEventId, QuicStreamRequest.New);
            var PacketBatchSet = new QuicObjectSet<QuicPacketBatch>(QuicPacketBatch.CreateEventId, QuicPacketBatch.DestroyedEventId, QuicPacketBatch.New);
            var PacketSet = new QuicObjectSet<QuicPacket>(QuicPacket.CreateEventId, QuicPacket.DestroyedEventId, QuicPacket.New);

            var ConnSourceCIDs = new Dictionary<byte[], QuicRequestConn>(new SequentialByteComparer());
            var ConnDestinationCIDs = new Dictionary<byte[], QuicRequestConn>(new SequentialByteComparer());

            var ClientRequests = new List<RequestTiming>();
            var ServerRequests = new List<RequestTiming>();

            //Console.WriteLine("StreamAlloc, PacketWrite, PacketEncrypt, PacketFinalize, PacketSend, PacketReceive, PacketDecrypt, PacketRead, StreamFlush, StreamDelete");

            foreach (var quicState in quicStates)
            {
                foreach (var evt in quicState.Events)
                {
                    switch (evt.EventId)
                    {
                        case QuicEventId.ConnScheduleState:
                        {
                            var Conn = ConnSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Conn.LastProcessingState = (evt as QuicConnectionScheduleStateEvent)!.ScheduleState;
                            Conn.LastProcessingTime = (ulong)evt.TimeStamp.ToNanoseconds;
                            //Console.WriteLine("ConnScheduleState {0} {1}", evt.ObjectPointer, Conn.LastProcessingState);
                            break;
                        }
                        case QuicEventId.ConnSourceCidAdded:
                        {
                            //Console.WriteLine("ConnSourceCidAdded {0}", evt.ObjectPointer);
                            var Conn = ConnSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            ConnSourceCIDs.Add((evt as QuicConnectionSourceCidAddedEvent)!.CID, Conn);
                            if (Conn.Peer == null && ConnDestinationCIDs.TryGetValue((evt as QuicConnectionSourceCidAddedEvent)!.CID, out var peer))
                            {
                                Conn.Peer = peer;
                                peer.Peer = Conn;
                                //Console.WriteLine("Peer Set {0}", evt.ObjectPointer);
                            }
                            break;
                        }
                        case QuicEventId.ConnDestCidAdded:
                        {
                            //Console.WriteLine("ConnDestCidAdded {0}", evt.ObjectPointer);
                            var Conn = ConnSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            ConnDestinationCIDs.Add((evt as QuicConnectionDestinationCidAddedEvent)!.CID, Conn);
                            if (Conn.Peer == null && ConnSourceCIDs.TryGetValue((evt as QuicConnectionDestinationCidAddedEvent)!.CID, out var peer))
                            {
                                Conn.Peer = peer;
                                peer.Peer = Conn;
                                //Console.WriteLine("Peer Set (dest) {0}", evt.ObjectPointer);
                            }
                            break;
                        }
                        case QuicEventId.StreamAlloc:
                        {
                            //Console.WriteLine("StreamAlloc {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Stream.Timings.StreamAlloc = (ulong)evt.TimeStamp.ToNanoseconds;
                            if (Stream.Timings.Connection == null)
                            {
                                Stream.Timings.Connection = ConnSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamAllocEvent)!.Connection, evt.ProcessId));
                                //Console.WriteLine("Conn Set {0}", evt.ObjectPointer);
                            }
                            break;
                        }
                        case QuicEventId.StreamCreated:
                        {
                            //Console.WriteLine("StreamCreated {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Stream.Timings.StreamID = (evt as QuicStreamCreatedEvent)!.StreamID;
                            //Stream.Timings.StreamAlloc = (ulong)evt.TimeStamp.ToNanoseconds;
                            if (Stream.Timings.Connection == null)
                            {
                                Stream.Timings.Connection = ConnSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamCreatedEvent)!.Connection, evt.ProcessId));
                                //Console.WriteLine("Conn Set {0}", evt.ObjectPointer);
                            }
                            break;
                        }
                        case QuicEventId.PacketBatchCreate:
                        {
                            //Console.WriteLine("PacketBatchCreate {0}", evt.ObjectPointer);
                            PacketBatchSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            break;
                        }
                        case QuicEventId.PacketCreated:
                        {
                            //Console.WriteLine("PacketCreated {0} in {1}", evt.ObjectPointer, (evt as QuicPacketCreatedEvent)!.BatchID);
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Packet.Batch = PacketBatchSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicPacketCreatedEvent)!.BatchID, evt.ProcessId));
                            break;
                        }
                        case QuicEventId.StreamWriteFrames:
                        {
                            //Console.WriteLine("StreamWriteFrames {0} in {1}", evt.ObjectPointer, (evt as QuicStreamWriteFramesEvent)!.ID);
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            if (Stream.SendPacket == null)
                            {
                                Stream.Timings.PacketWrite = (ulong)evt.TimeStamp.ToNanoseconds;
                                Stream.SendPacket = PacketSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamWriteFramesEvent)!.ID, evt.ProcessId));
                                if (Stream.Timings.Connection == null || Stream.Timings.Connection.LastProcessingState != QuicScheduleState.Processing ||
                                    Stream.Timings.StreamAlloc > Stream.Timings.Connection.LastProcessingTime)
                                {
                                    Stream.Timings.ConnectionQueueTime += Stream.Timings.PacketWrite - Stream.Timings.StreamAlloc;
                                }
                                else
                                {
                                    Stream.Timings.ConnectionQueueTime += Stream.Timings.Connection.LastProcessingTime - Stream.Timings.StreamAlloc;
                                }
                            }
                            break;
                        }
                        case QuicEventId.PacketEncrypt:
                        {
                            //Console.WriteLine("PacketEncrypt {0}", evt.ObjectPointer);
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Packet.PacketEncrypt = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.PacketFinalize:
                        {
                            //Console.WriteLine("PacketFinalize {0}", evt.ObjectPointer);
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Packet.PacketFinalize = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.PacketBatchSend:
                        {
                            //Console.WriteLine("PacketBatchSend {0}", evt.ObjectPointer);
                            var Batch = PacketBatchSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Batch.PacketSend = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.PacketReceive:
                        {
                            //Console.WriteLine("PacketReceive {0}", evt.ObjectPointer);
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            if (Packet.PacketReceive == 0)
                            {
                                Packet.PacketReceive = (ulong)evt.TimeStamp.ToNanoseconds;
                            }
                            break;
                        }
                        case QuicEventId.PacketDecrypt:
                        {
                            //Console.WriteLine("PacketDecrypt {0}", evt.ObjectPointer);
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            if (Packet.PacketDecrypt == 0)
                            {
                                Packet.PacketDecrypt = (ulong)evt.TimeStamp.ToNanoseconds;
                            }
                            break;
                        }
                        case QuicEventId.StreamReceiveFrame:
                        {
                            //Console.WriteLine("StreamReceiveFrame {0} in {1}", evt.ObjectPointer, (evt as QuicStreamReceiveFrameEvent)!.ID);
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            if (Stream.Timings.PacketRead == 0)
                            {
                                Stream.Timings.PacketRead = (ulong)evt.TimeStamp.ToNanoseconds;
                            }
                            Stream.RecvPacket = PacketSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamReceiveFrameEvent)!.ID, evt.ProcessId));
                            break;
                        }
                        case QuicEventId.StreamFlushRecv:
                        {
                            //Console.WriteLine("StreamFlushRecv {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Stream.Timings.StreamFlush = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamDestroyed:
                        {
                            //Console.WriteLine("StreamDestroyed {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            if (Stream.SendPacket == null)
                            {
                                Console.WriteLine("Missing send packet");
                                break;
                            }
                            if (Stream.SendPacket.Batch == null)
                            {
                                Console.WriteLine("Missing send packet batch");
                                break;
                            }
                            if (Stream.RecvPacket == null)
                            {
                                Console.WriteLine("Missing recv packet");
                                break;
                            }
                            if (Stream.Timings.Connection == null)
                            {
                                Console.WriteLine("Missing connection");
                                break;
                            }
                            /*if (Stream.Timings.Connection.Peer == null)
                            {
                                Console.WriteLine("Missing connection peer");
                                break;
                            }*/
                            Stream.Timings.PacketEncrypt = Stream.SendPacket.PacketEncrypt;
                            Stream.Timings.PacketFinalize = Stream.SendPacket.PacketFinalize;
                            Stream.Timings.PacketSend = Stream.SendPacket.Batch.PacketSend;
                            Stream.Timings.PacketReceive = Stream.RecvPacket.PacketReceive;
                            Stream.Timings.PacketDecrypt = Stream.RecvPacket.PacketDecrypt;
                            Stream.Timings.StreamDelete = (ulong)evt.TimeStamp.ToNanoseconds;
                            if (!Stream.Timings.IsIncomplete)
                            {
                                if (Stream.Timings.IsServer)
                                {
                                    //Console.WriteLine("Added server-side request");
                                    ServerRequests.Add(Stream.Timings);
                                }
                                else
                                {
                                    //Console.WriteLine("Added client-side request");
                                    ClientRequests.Add(Stream.Timings);
                                }
                            }
                            break;
                        }
                        default: break;
                    }
                }
            }

            var clientRequestCount = ClientRequests.Count;
            var serverRequestCount = ServerRequests.Count;
            Console.WriteLine("{0} client and {1} server compelete requests found.\n", clientRequestCount, serverRequestCount);

            if (clientRequestCount == 0)
            {
                Console.WriteLine("No complete client requests!");
                return;
            }

            var ServerDict = ServerRequests.ToDictionary(x => ( x.Connection!.Pointer, x.StreamID ) );
            foreach (var timing in ClientRequests)
            {
                if (timing.Connection!.Peer != null &&
                    ServerDict.TryGetValue(( timing.Connection!.Peer.Pointer, timing.StreamID ), out var peer))
                {
                    timing.Peer = peer;
                    peer.Peer = timing;
                    //Console.WriteLine("Request Peer Set {0}", timing.StreamID);
                }
            }

            var sortedRequests = ClientRequests.OrderBy(t => t.Latency);

            var queueTimes = ClientRequests.OrderBy(t => t.QueueTime);
            var writeTimes = ClientRequests.OrderBy(t => t.WriteTime);
            var encryptTimes = ClientRequests.OrderBy(t => t.EncryptTime);
            var finalizeTimes = ClientRequests.OrderBy(t => t.FinalizeTime);
            var peerTimes = ClientRequests.OrderBy(t => t.PeerTime);
            var udpTimes = ClientRequests.OrderBy(t => t.UdpTime);
            var recvTimes = ClientRequests.OrderBy(t => t.RecvTime);
            var decryptTimes = ClientRequests.OrderBy(t => t.DecryptTime);
            var readTimes = ClientRequests.OrderBy(t => t.ReadTime);
            var flushTimes = ClientRequests.OrderBy(t => t.FlushTime);

            Console.WriteLine("Total, Queue, Write, Encrypt, Finalize, Peer, Udp, Receive, Decrypt, Read, Flush");
            foreach (var timing in sortedRequests)
            {
                timing.WriteLine2();
            }
            Console.WriteLine("");

            Console.WriteLine("Percentile, Total, Queue, Write, Encrypt, Finalize, Peer, Udp, Receive, Decrypt, Read, Flush");
            var Percentiles = new List<double>() { 0, 50, 90, 99, 99.9, 99.99, 99.999 };
            foreach (var percentile in Percentiles)
            {
                var t = sortedRequests.ElementAt((int)((clientRequestCount * percentile) / 100));
                Console.Write("{0}th,", percentile);
                t.WriteLine2();
            }

            Console.WriteLine("\nPercentile, Queue, Write, Encrypt, Finalize, Peer, Udp, Recv, Decrypt, Read, Flush");
            foreach (var percentile in Percentiles)
            {
                var i = (int)((clientRequestCount * percentile) / 100);
                Console.WriteLine(
                    "{0}th,{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}",
                    percentile,
                    queueTimes.ElementAt(i).QueueTime,
                    writeTimes.ElementAt(i).WriteTime,
                    encryptTimes.ElementAt(i).EncryptTime,
                    finalizeTimes.ElementAt(i).FinalizeTime,
                    peerTimes.ElementAt(i).PeerTime,
                    udpTimes.ElementAt(i).UdpTime,
                    recvTimes.ElementAt(i).RecvTime,
                    decryptTimes.ElementAt(i).DecryptTime,
                    readTimes.ElementAt(i).ReadTime,
                    flushTimes.ElementAt(i).FlushTime);
            }
        }

        static void RunCommand(QuicState[] quicStates, string[] args)
        {
            if (args[0] == "--print" || args[0] == "-p")
            {
                if (QuicEvent.ParseMode != QuicEventParseMode.Full)
                {
                    Console.WriteLine("--text option was not initially specified! Please rerun.");
                    return;
                }

                foreach (var evt in quicStates[0].Events)
                {
                    Console.WriteLine(evt);
                }
            }
            else if (args[0] == "--report" || args[0] == "-r")
            {
                RunReport(quicStates[0]);
            }
            else if (args[0] == "--rps" || args[0] == "-s")
            {
                RunRpsAnalysis(quicStates);
            }
            else if (args[0] == "--help" || args[0] == "-h" || args[0] == "-?")
            {
                PrintCommands();
            }
            else
            {
                Console.WriteLine("Unsupported command: {0}", args[0]);
                return;
            }
        }

        static void Main(string[] args)
        {
            var i = 0;
            var traceFiles = new List<string>();

            //
            // Process input args for initial 'option' values.
            //
            for (; i < args.Length; ++i)
            {
                if (args[i] == "--capture" || args[i] == "-c")
                {
                    var traceFile = CaptureLocalTrace();
                    if (traceFile == null)
                    {
                        return;
                    }
                    traceFiles.Add(traceFile);
                }
                else if (args[i] == "--file" || args[i] == "-f")
                {
                    if (i + 1 >= args.Length)
                    {
                        Console.WriteLine("Missing additional argument for --file option!");
                        return;
                    }

                    ++i;
                    traceFiles.Add(args[i]);
                }
                else if (args[i] == "--help" || args[i] == "-h" || args[i] == "-?")
                {
                    PrintArgs();
                    return;
                }
                else if (args[i] == "--text" || args[i] == "-t")
                {
                    //
                    // Enable full event and payload parsing.
                    //
                    QuicEvent.ParseMode = QuicEventParseMode.Full;
                }
                else
                {
                    break;
                }
            }

            //
            // Make sure we have something valid to process.
            //
            if (traceFiles.Count == 0)
            {
                Console.WriteLine("Missing valid option! Run '--help' for additional usage information!");
                return;
            }

            //
            // Process the trace files to generate the QUIC state.
            //
            var quicStates = ProcessTraceFiles(traceFiles);

            if (i == args.Length)
            {
                //
                // Run in interactive mode when no commands were specified.
                //
                while (true)
                {
                    Console.Write("quictrace> ");

                    var input = Console.ReadLine();
                    if (input == null || input == "--exit" || input == "exit" || input == "-e")
                    {
                        return;
                    }

                    if (input.Length > 0)
                    {
                        var cmdArgs = input.Split(" \t\r\n");
                        RunCommand(quicStates, cmdArgs);
                    }
                }
            }
            else
            {
                //
                // Process specified commands inline.
                //
                RunCommand(quicStates, args[i..]);
            }
        }
    }
}
