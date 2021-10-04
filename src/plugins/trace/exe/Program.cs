//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
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

        static QuicState ProcessTraceFile(string filePath)
        {
            //
            // Create our runtime environment, add file, enable cookers, and process.
            //
            var runtime = Engine.Create();
            runtime.AddFile(filePath);
            runtime.EnableCooker(QuicEventCooker.CookerPath);
            Console.WriteLine("Processing...");
            var results = runtime.Process();
            Console.WriteLine("Done.\n");

            //
            // Return our 'cooked' data.
            //
            return results.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
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

            public bool IsIncomplete { get { return StreamAlloc == 0 || PacketWrite == 0 || PacketEncrypt == 0 || PacketFinalize == 0 || PacketSend == 0 || PacketReceive == 0 || PacketDecrypt == 0 || PacketRead == 0 || StreamFlush == 0 || StreamDelete == 0; } }

            public bool IsServer {  get { return PacketReceive < StreamAlloc; } }

            public ulong Latency { get { return StreamDelete - StreamAlloc; } }

            public ulong Min { get { return Math.Min(Math.Min(Math.Min(Math.Min(Math.Min(Math.Min(Math.Min(Math.Min(Math.Min(StreamAlloc, PacketWrite), PacketEncrypt), PacketFinalize), PacketSend), PacketReceive), PacketDecrypt), PacketRead), StreamFlush), StreamDelete); } }

            public ulong QueueTime { get { return PacketWrite - StreamAlloc; } }
            public ulong WriteTime { get { return PacketEncrypt - PacketWrite; } }
            public ulong EncryptTime { get { return PacketFinalize - PacketEncrypt; } }
            public ulong FinalizeTime { get { return PacketSend - PacketFinalize; } }
            public ulong PeerTime { get { return PacketReceive - PacketSend; } }
            public ulong RecvTime { get { return PacketDecrypt - PacketReceive; } }
            public ulong DecryptTime { get { return PacketRead - PacketDecrypt; } }
            public ulong ReadTime { get { return StreamFlush - PacketRead; } }
            public ulong FlushTime { get { return StreamDelete - StreamFlush; } }

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
                    "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}",
                    0,
                    PacketWrite - StreamAlloc,
                    PacketEncrypt - PacketWrite,
                    PacketFinalize - PacketEncrypt,
                    PacketSend - PacketFinalize,
                    PacketReceive - PacketSend,
                    PacketDecrypt - PacketReceive,
                    PacketRead - PacketDecrypt,
                    StreamFlush - PacketRead,
                    StreamDelete - StreamFlush);
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

            public ulong StreamID = ulong.MaxValue;

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

        static void RunRpsAnalysis(QuicState quicState)
        {
            var StreamSet = new QuicObjectSet<QuicStreamRequest>(QuicStreamRequest.CreateEventId, QuicStreamRequest.DestroyedEventId, QuicStreamRequest.New);
            var PacketBatchSet = new QuicObjectSet<QuicPacketBatch>(QuicPacketBatch.CreateEventId, QuicPacketBatch.DestroyedEventId, QuicPacketBatch.New);
            var PacketSet = new QuicObjectSet<QuicPacket>(QuicPacket.CreateEventId, QuicPacket.DestroyedEventId, QuicPacket.New);

            var Requests = new List<RequestTiming>();

            //Console.WriteLine("StreamAlloc, PacketWrite, PacketEncrypt, PacketFinalize, PacketSend, PacketReceive, PacketDecrypt, PacketRead, StreamFlush, StreamDelete");

            foreach (var evt in quicState.Events)
            {
                switch (evt.EventId)
                {
                    case QuicEventId.StreamAlloc:
                    {
                        //Console.WriteLine("StreamAlloc {0}", evt.ObjectPointer);
                        var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                        Stream.Timings.StreamAlloc = (ulong)evt.TimeStamp.ToNanoseconds;
                        break;
                    }
                    case QuicEventId.StreamCreated:
                    {
                        //Console.WriteLine("StreamCreated {0}", evt.ObjectPointer);
                        var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                        Stream.StreamID = (evt as QuicStreamCreatedEvent)!.StreamID;
                        //Stream.Timings.StreamAlloc = (ulong)evt.TimeStamp.ToNanoseconds;
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
                        Packet.PacketReceive = (ulong)evt.TimeStamp.ToNanoseconds;
                        break;
                    }
                    case QuicEventId.PacketDecrypt:
                    {
                        //Console.WriteLine("PacketDecrypt {0}", evt.ObjectPointer);
                        var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                        Packet.PacketDecrypt = (ulong)evt.TimeStamp.ToNanoseconds;
                        break;
                    }
                    case QuicEventId.StreamReceiveFrame:
                    {
                        //Console.WriteLine("StreamReceiveFrame {0} in {1}", evt.ObjectPointer, (evt as QuicStreamReceiveFrameEvent)!.ID);
                        var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                        Stream.Timings.PacketRead = (ulong)evt.TimeStamp.ToNanoseconds;
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
                        Stream.Timings.PacketEncrypt = Stream.SendPacket?.PacketEncrypt ?? 0;
                        Stream.Timings.PacketFinalize = Stream.SendPacket?.PacketFinalize ?? 0;
                        Stream.Timings.PacketSend = Stream.SendPacket?.Batch?.PacketSend ?? 0;
                        Stream.Timings.PacketReceive = Stream.RecvPacket?.PacketReceive ?? 0;
                        Stream.Timings.PacketDecrypt = Stream.RecvPacket?.PacketDecrypt ?? 0;
                        Stream.Timings.StreamDelete = (ulong)evt.TimeStamp.ToNanoseconds;
                        if (!Stream.Timings.IsIncomplete && !Stream.Timings.IsServer)
                        {
                            Requests.Add(Stream.Timings);
                        }
                        break;
                    }
                    default: break;
                }
            }

            var requestCount = Requests.Count;
            var sortedRequests = Requests.OrderBy(t => t.Latency);

            var queueTimes = Requests.OrderBy(t => t.QueueTime);
            var writeTimes = Requests.OrderBy(t => t.WriteTime);
            var encryptTimes = Requests.OrderBy(t => t.EncryptTime);
            var finalizeTimes = Requests.OrderBy(t => t.FinalizeTime);
            var peerTimes = Requests.OrderBy(t => t.PeerTime);
            var recvTimes = Requests.OrderBy(t => t.RecvTime);
            var decryptTimes = Requests.OrderBy(t => t.DecryptTime);
            var readTimes = Requests.OrderBy(t => t.ReadTime);
            var flushTimes = Requests.OrderBy(t => t.FlushTime);

            /*Console.WriteLine("Alloc, Write, Encrypt, Finalize, Send, Receive, Decrypt, Read, Flush, Delete");
            foreach (var timing in sortedRequests)
            {
                timing.WriteLine();
            }*/

            var Percentiles = new List<double>() { 0, 90, 99, 99.9, 99.99, 99.999 };
            foreach (var percentile in Percentiles)
            {
                var t = sortedRequests.ElementAt((int)((requestCount * percentile) / 100));
                Console.WriteLine("{0}th {1}", percentile, t.Latency);
                t.WriteLine2();
            }

            Console.WriteLine("\nPercentile, Queue, Write, Encrypt, Finalize, Peer, Recv, Decrypt, Read, Flush");
            foreach (var percentile in Percentiles)
            {
                var i = (int)((requestCount * percentile) / 100);
                Console.WriteLine(
                    "{0}th,{1},{2},{3},{4},{5},{6},{7},{8},{9}",
                    percentile,
                    queueTimes.ElementAt(i).QueueTime,
                    writeTimes.ElementAt(i).WriteTime,
                    encryptTimes.ElementAt(i).EncryptTime,
                    finalizeTimes.ElementAt(i).FinalizeTime,
                    peerTimes.ElementAt(i).PeerTime,
                    recvTimes.ElementAt(i).RecvTime,
                    decryptTimes.ElementAt(i).DecryptTime,
                    readTimes.ElementAt(i).ReadTime,
                    flushTimes.ElementAt(i).FlushTime);
            }
        }

        static void RunCommand(QuicState quicState, string[] args)
        {
            if (args[0] == "--print" || args[0] == "-p")
            {
                if (QuicEvent.ParseMode != QuicEventParseMode.Full)
                {
                    Console.WriteLine("--text option was not initially specified! Please rerun.");
                    return;
                }

                foreach (var evt in quicState.Events)
                {
                    Console.WriteLine(evt);
                }
            }
            else if (args[0] == "--report" || args[0] == "-r")
            {
                RunReport(quicState);
            }
            else if (args[0] == "--rps" || args[0] == "-s")
            {
                RunRpsAnalysis(quicState);
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
            string? traceFile = null;

            //
            // Process input args for initial 'option' values.
            //
            for (; i < args.Length; ++i)
            {
                if (args[i] == "--capture" || args[i] == "-c")
                {
                    traceFile = CaptureLocalTrace();
                    if (traceFile == null)
                    {
                        return;
                    }
                }
                else if (args[i] == "--file" || args[i] == "-f")
                {
                    if (i + 1 >= args.Length)
                    {
                        Console.WriteLine("Missing additional argument for --file option!");
                        return;
                    }

                    ++i;
                    traceFile = args[i];
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
            if (traceFile == null)
            {
                Console.WriteLine("Missing valid option! Run '--help' for additional usage information!");
                return;
            }

            //
            // Process the trace file to generate the QUIC state.
            //
            var quicState = ProcessTraceFile(traceFile);

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
                        RunCommand(quicState, cmdArgs);
                    }
                }
            }
            else
            {
                //
                // Process specified commands inline.
                //
                RunCommand(quicState, args[i..]);
            }
        }
    }
}
