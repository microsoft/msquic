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
                //Console.Write("Processing {0}...", filePath);
                var results = runtime.Process();
                //Console.WriteLine("Done.\n");

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

        public enum RequestState
        {
            Idle,
            QueueSend,
            ProcessSend,
            Frame,
            Write,
            Encrypt,
            Send,
            Udp,
            AwaitPeer,
            QueueRecv,
            ProcessRecv,
            Decrypt,
            Read,
            AppRecv,
            Complete,
            COUNT
        };

        internal class RequestTiming
        {
            //
            // The time spent in each RequestState.
            //
            public ulong[] Times = new ulong[(int)RequestState.COUNT];

            //
            // The current state of the request.
            //
            public RequestState State = RequestState.Idle;

            //
            // The last time State was updated.
            //
            public ulong LastStateChangeTime = 0;

            //
            // Triggers a state change and updates variables accordingly.
            //
            public void UpdateToState(RequestState state, ulong time, bool allowPrevious = false)
            {
                if (EncounteredError) return;
                if (time < LastStateChangeTime)
                {
                    if (allowPrevious)
                    {
                        State = state; // Just treat it as if we entered this new state instead of the old one
                    }
                    else
                    {
                        Console.WriteLine("ERROR: Invalid state change from {0} to {1}", State, state);
                        EncounteredError = true;
                    }
                    return;
                }
                Times[(int)State] += (time - LastStateChangeTime);
                LastStateChangeTime = time;
                State = state;
            }

            //
            // Returns the sum of all the calculated times for individual layers.
            //
            public ulong TotalTime { get { return Times.Aggregate((temp, x) => temp + x); } }

            //
            // The connection used for this request.
            //
            public QuicRequestConn? Connection = null;

            //
            // The corresponding peer's timings.
            //
            public RequestTiming? Peer = null;

            //
            // The stream identifier for this request.
            //
            public ulong StreamID = ulong.MaxValue;

            //
            // Indicates if this timings is for the client or server side.
            //
            public bool IsServer = false;

            public ulong FirstPacketRecv = 0;
            public ulong FirstPacketSend = 0;

            //
            // Indicates if an error or unexpected state occurred while processing this request.
            //
            public bool EncounteredError = false;

            //
            // Writes the header for the CSV data.
            //
            public static void WriteCsvHeader(bool withTotal = true)
            {
                if (withTotal) Console.Write("Total");
                foreach (var state in Enum.GetValues(typeof(RequestState)).Cast<RequestState>())
                {
                    if (state == RequestState.COUNT) break;
                    Console.Write(",{0}", state);
                }
                Console.WriteLine();
            }

            //
            // Writes all the times in comma seperated vector format.
            //
            public void WriteCsv()
            {
                Console.Write("{0},", TotalTime);
                Console.WriteLine(String.Join(",", Times));
            }
        }

        internal class QuicRequestConn : IQuicObject
        {
            public static QuicRequestConn New(ulong pointer, uint processId) => new QuicRequestConn(pointer, processId);

            public static ushort CreateEventId => (ushort)QuicEventId.ConnCreated;

            public static ushort DestroyedEventId => 0;

            public ulong Id { get; }

            private static ulong NextId = 1;

            public ulong Pointer { get; }

            public uint ProcessId { get; }

            public QuicRequestConn? Peer = null;

            public QuicScheduleState SchedulingState = QuicScheduleState.Idle;
            public ulong LastScheduleTime = 0;

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

            public static ushort CreateEventId => (ushort)QuicEventId.PacketCreated;

            public static ushort DestroyedEventId => 0;

            public ulong Id { get; }

            public ulong Pointer { get; }

            public uint ProcessId { get; }

            public ulong BatchSent = 0;

            public List<QuicPacket> Packets = new List<QuicPacket> { };

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

            public List<QuicStreamRequest> Streams = new List<QuicStreamRequest> { };

            public ulong PacketCreate = 0;
            public ulong PacketEncrypt = 0;
            public ulong PacketFinalize = 0;
            public ulong PacketReceive = 0;
            public ulong PacketDecrypt = 0;

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

            public ulong StreamAlloc = 0;
            public ulong StreamCreate = 0;
            public ulong StreamSend = 0;
            public ulong StreamDelete = 0;
            public ulong PacketWrite = 0;
            public ulong PacketRead = 0;
            public ulong AppRecv = 0;
            public ulong AppRecvComplete = 0;

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

            foreach (var quicState in quicStates)
            {
                foreach (var evt in quicState.Events)
                {
                    switch (evt.EventId)
                    {
                        case QuicEventId.ConnScheduleState:
                        {
                            var Conn = ConnSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Conn.SchedulingState = (evt as QuicConnectionScheduleStateEvent)!.ScheduleState;
                            Conn.LastScheduleTime = (ulong)evt.TimeStamp.ToNanoseconds;
                            //Console.WriteLine("ConnScheduleState {0} {1}", evt.ObjectPointer, Conn.SchedulingState);
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
                            if (Stream.Timings.EncounteredError) break;

                            Stream.Timings.Connection = ConnSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamAllocEvent)!.Connection, evt.ProcessId));
                            //Console.WriteLine("Set Conn {0}", (evt as QuicStreamAllocEvent)!.Connection);
                            Stream.StreamAlloc = (ulong)evt.TimeStamp.ToNanoseconds;
                            Stream.Timings.LastStateChangeTime = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamCreated:
                        {
                            //Console.WriteLine("StreamCreated {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.Timings.StreamID = (evt as QuicStreamCreatedEvent)!.StreamID;
                            Stream.Timings.IsServer = (evt as QuicStreamCreatedEvent)!.IsLocalOwned == 0;
                            Stream.StreamCreate = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamAppSend:
                        {
                            //Console.WriteLine("StreamAppSend {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.StreamSend = (ulong)evt.TimeStamp.ToNanoseconds;
                            if (Stream.Timings.State == RequestState.Idle)
                            {
                                Stream.Timings.UpdateToState(RequestState.QueueSend, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            else
                            {
                                Console.WriteLine("Stream in unexpected state {0} for Send", Stream.Timings.State);
                            }
                            break;
                        }
                        case QuicEventId.PacketCreated:
                        {
                            //Console.WriteLine("PacketCreated {0} in {1}", evt.ObjectPointer, (evt as QuicPacketCreatedEvent)!.BatchID);
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Packet.Batch = PacketBatchSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicPacketCreatedEvent)!.BatchID, evt.ProcessId));
                            Packet.Batch.Packets.Add(Packet);
                            Packet.PacketCreate = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamWriteFrames:
                        {
                            //Console.WriteLine("StreamWriteFrames {0} in {1}", evt.ObjectPointer, (evt as QuicStreamWriteFramesEvent)!.ID);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            if (Stream.Timings.State == RequestState.Write) break; // Already in the Write state

                            if (Stream.Timings.Connection!.SchedulingState != QuicScheduleState.Processing)
                            {
                                Console.WriteLine("ERROR: Connection not in processing state for Write");
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            Stream.SendPacket = PacketSet.FindActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamWriteFramesEvent)!.ID, evt.ProcessId));
                            if (Stream.SendPacket == null)
                            {
                                Console.WriteLine("ERROR: Failed to find Packet {0} for Write", (evt as QuicStreamWriteFramesEvent)!.ID);
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            Stream.SendPacket.Streams.Add(Stream);
                            Stream.PacketWrite = (ulong)evt.TimeStamp.ToNanoseconds;

                            if (Stream.Timings.State == RequestState.QueueSend)
                            {
                                Stream.Timings.UpdateToState(RequestState.ProcessSend, Stream.Timings.Connection.LastScheduleTime, true);
                                Stream.Timings.UpdateToState(RequestState.Frame, Stream.SendPacket.PacketCreate);
                            }
                            else if (Stream.Timings.State == RequestState.Send)
                            {
                                Stream.Timings.State = RequestState.Frame;
                            }
                            else if (Stream.Timings.State == RequestState.Complete ||
                                     Stream.Timings.State == RequestState.AwaitPeer ||
                                     Stream.Timings.State == RequestState.Idle)
                            {
                                Stream.Timings.State = RequestState.ProcessSend; // TODO - What state should we consider this?
                                Stream.Timings.UpdateToState(RequestState.Frame, Stream.SendPacket.PacketCreate);
                            }
                            else
                            {
                                Console.WriteLine("Stream in unexpected state {0} for Write", Stream.Timings.State);
                            }
                            Stream.Timings.UpdateToState(RequestState.Write, (ulong)evt.TimeStamp.ToNanoseconds);
                            break;
                        }
                        case QuicEventId.PacketEncrypt:
                        {
                            //Console.WriteLine("PacketEncrypt {0}", evt.ObjectPointer);
                            var Packet = PacketSet.FindActive(new QuicObjectKey(evt));
                            if (Packet == null)
                            {
                                Console.WriteLine("ERROR: Failed to find Packet {0} for Encrypt", (evt as QuicPacketEncryptEvent)!.ID);
                                break;
                            }
                            Packet.PacketEncrypt = (ulong)evt.TimeStamp.ToNanoseconds;

                            foreach (var Stream in Packet.Streams)
                            {
                                if (Stream.Timings.State != RequestState.Write)
                                {
                                    Console.WriteLine("ERROR: Stream in {0} state for Encrypt", Stream.Timings.State);
                                    Stream.Timings.EncounteredError = true;
                                    continue;
                                }

                                Stream.Timings.UpdateToState(RequestState.Encrypt, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            break;
                        }
                        case QuicEventId.PacketFinalize:
                        {
                            //Console.WriteLine("PacketFinalize {0}", evt.ObjectPointer);
                            var Packet = PacketSet.FindActive(new QuicObjectKey(evt));
                            if (Packet == null)
                            {
                                Console.WriteLine("ERROR: Failed to find Packet {0} for Finalize", (evt as QuicPacketFinalizeEvent)!.ID);
                                break;
                            }
                            Packet.PacketFinalize = (ulong)evt.TimeStamp.ToNanoseconds;

                            foreach (var Stream in Packet.Streams)
                            {
                                if (Stream.Timings.State != RequestState.Encrypt)
                                {
                                    Console.WriteLine("ERROR: Stream in state {0} for Finalize", Stream.Timings.State);
                                    Stream.Timings.EncounteredError = true;
                                    continue;
                                }

                                if (Stream.Timings.FirstPacketSend == 0)
                                {
                                    Stream.Timings.FirstPacketSend = (ulong)evt.TimeStamp.ToNanoseconds;
                                }

                                Stream.SendPacket = null;
                                Stream.Timings.UpdateToState(RequestState.Send, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            break;
                        }
                        case QuicEventId.PacketBatchSent:
                        {
                            //Console.WriteLine("PacketBatchSent {0}", evt.ObjectPointer);
                            var Batch = PacketBatchSet.FindActive(new QuicObjectKey(evt));
                            if (Batch == null) break;
                            Batch.BatchSent = (ulong)evt.TimeStamp.ToNanoseconds;

                            foreach (var Packet in Batch.Packets)
                            {
                                foreach (var Stream in Packet.Streams)
                                {
                                    if (Stream.Timings.State == RequestState.Send)
                                    {
                                        if (Stream.Timings.IsServer)
                                        {
                                            Stream.Timings.UpdateToState(RequestState.Idle, (ulong)evt.TimeStamp.ToNanoseconds);
                                        }
                                        else
                                        {
                                            Stream.Timings.UpdateToState(RequestState.AwaitPeer, (ulong)evt.TimeStamp.ToNanoseconds);
                                        }
                                    }
                                    else if (Stream.Timings.State != RequestState.Idle && Stream.Timings.State != RequestState.AwaitPeer)
                                    {
                                        Console.WriteLine("ERROR: Stream in state {0} for BatchSent", Stream.Timings.State);
                                        Stream.Timings.EncounteredError = true;
                                    }
                                }
                            }
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
                            var Packet = PacketSet.FindActive(new QuicObjectKey(evt));
                            if (Packet == null)
                            {
                                Console.WriteLine("ERROR: Failed to find Packet {0} for Decrypt", (evt as QuicPacketDecryptEvent)!.ID);
                                break;
                            }
                            if (Packet.PacketDecrypt == 0)
                            {
                                Packet.PacketDecrypt = (ulong)evt.TimeStamp.ToNanoseconds;
                            }
                            break;
                        }
                        case QuicEventId.StreamReceiveFrame:
                        {
                            //Console.WriteLine("StreamReceiveFrame {0} in {1}", evt.ObjectPointer, (evt as QuicStreamReceiveFrameEvent)!.ID);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.RecvPacket = PacketSet.FindActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamReceiveFrameEvent)!.ID, evt.ProcessId));
                            if (Stream.RecvPacket == null)
                            {
                                Console.WriteLine("ERROR: Failed to find Packet {0} for Read", (evt as QuicStreamReceiveFrameEvent)!.ID);
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            if (Stream.RecvPacket.PacketDecrypt == 0)
                            {
                                Console.WriteLine("ERROR: No PacketDecrypt for Read");
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            if (Stream.Timings.FirstPacketRecv == 0)
                            {
                                Stream.Timings.FirstPacketRecv = Stream.RecvPacket.PacketReceive;
                            }

                            if (Stream.PacketRead == 0)
                            {
                                Stream.PacketRead = (ulong)evt.TimeStamp.ToNanoseconds;
                                if (Stream.StreamAlloc > Stream.RecvPacket.PacketReceive)
                                {
                                    Stream.Timings.State = RequestState.QueueRecv;
                                    Stream.Timings.LastStateChangeTime = Stream.RecvPacket.PacketReceive;
                                    Stream.Timings.UpdateToState(RequestState.ProcessRecv, Stream.Timings.Connection!.LastScheduleTime, true);
                                    Stream.Timings.UpdateToState(RequestState.Decrypt, Stream.RecvPacket.PacketDecrypt);
                                    Stream.Timings.UpdateToState(RequestState.Read, (ulong)evt.TimeStamp.ToNanoseconds);
                                }
                                else
                                {
                                    Stream.Timings.UpdateToState(RequestState.QueueRecv, Stream.RecvPacket.PacketReceive, true);
                                    Stream.Timings.UpdateToState(RequestState.ProcessRecv, Stream.Timings.Connection!.LastScheduleTime, true);
                                    Stream.Timings.UpdateToState(RequestState.Decrypt, Stream.RecvPacket.PacketDecrypt);
                                    Stream.Timings.UpdateToState(RequestState.Read, (ulong)evt.TimeStamp.ToNanoseconds);
                                }
                            }
                            break;
                        }
                        case QuicEventId.StreamAppReceive:
                        {
                            //Console.WriteLine("StreamAppReceive {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.AppRecv = (ulong)evt.TimeStamp.ToNanoseconds;
                            Stream.Timings.UpdateToState(RequestState.AppRecv, (ulong)evt.TimeStamp.ToNanoseconds);
                            break;
                        }
                        case QuicEventId.StreamAppReceiveComplete:
                        {
                            //Console.WriteLine("StreamAppReceiveComplete {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            if (Stream.Timings.StreamID == ulong.MaxValue)
                            {
                                Console.WriteLine("ERROR: Missing StreamID for AppRecvComplete");
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            Stream.AppRecvComplete = (ulong)evt.TimeStamp.ToNanoseconds;
                            if (Stream.Timings.IsServer)
                            {
                                Stream.Timings.UpdateToState(RequestState.Idle, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            else
                            {
                                Stream.Timings.UpdateToState(RequestState.Complete, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            break;
                        }
                        case QuicEventId.StreamDestroyed:
                        {
                            //Console.WriteLine("StreamDestroyed {0}", evt.ObjectPointer);
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            if (Stream.Timings.StreamID == ulong.MaxValue)
                            {
                                Console.WriteLine("ERROR: Missing StreamID for StreamDestroyed");
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            Stream.Timings.UpdateToState(RequestState.Idle, (ulong)evt.TimeStamp.ToNanoseconds);

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
                            break;
                        }
                        default: break;
                    }
                }
            }

            var clientRequestCount = ClientRequests.Count;
            var serverRequestCount = ServerRequests.Count;
            if (clientRequestCount == 0)
            {
                Console.WriteLine("No complete client requests! Found {0} server requests.", serverRequestCount);
                return;
            }
            Console.WriteLine("{0} client and {1} server complete requests found.\n", clientRequestCount, serverRequestCount);

            var ServerDict = ServerRequests.ToDictionary(x => ( x.Connection!.Pointer, x.StreamID ) );
            foreach (var timing in ClientRequests)
            {
                if (timing.Connection!.Peer == null)
                {
                    Console.WriteLine("WARNING: Missing connection peer!");
                }
                else if(!ServerDict.TryGetValue(( timing.Connection!.Peer.Pointer, timing.StreamID ), out var peer))
                {
                    Console.WriteLine("WARNING: Cannot find matching peer timings!");
                }
                else
                {
                    timing.Peer = peer;
                    peer.Peer = timing;
                    //Console.WriteLine("Request Peer Set {0}", timing.StreamID);

                    var PeerResponseTime = timing.Peer.FirstPacketSend - timing.Peer.FirstPacketRecv;
                    if (PeerResponseTime > timing.Times[(int)RequestState.AwaitPeer])
                    {
                        PeerResponseTime = timing.Times[(int)RequestState.AwaitPeer];
                    }
                    timing.Times[(int)RequestState.Udp] = timing.Times[(int)RequestState.AwaitPeer] - PeerResponseTime;
                    timing.Times[(int)RequestState.AwaitPeer] = PeerResponseTime;
                }
            }

            var sortedRequests = ClientRequests.OrderBy(t => t.TotalTime);

            /*RequestTiming.WriteCsvHeader();
            foreach (var timing in sortedRequests)
            {
                timing.WriteCsv();
            }
            Console.WriteLine();*/

            Console.Write("Percentile,ID,");
            RequestTiming.WriteCsvHeader();
            var Percentiles = new List<double>() { 0, 50, 90, 99, 99.9, 99.99, 99.999 };
            foreach (var percentile in Percentiles)
            {
                var t = sortedRequests.ElementAt((int)((clientRequestCount * percentile) / 100));
                Console.Write("{0}th,{1},", percentile, t.StreamID);
                t.WriteCsv();
            }
            Console.WriteLine();

            var layerTimes = new List<IOrderedEnumerable<RequestTiming>>();
            foreach (var state in Enum.GetValues(typeof(RequestState)).Cast<RequestState>())
            {
                if (state == RequestState.COUNT) break;
                layerTimes.Add(ClientRequests.OrderBy(t => t.Times[(int)state]));
            }

            Console.Write("Percentile");
            RequestTiming.WriteCsvHeader(false);
            foreach (var percentile in Percentiles)
            {
                var i = (int)((clientRequestCount * percentile) / 100);
                Console.Write("{0}th", percentile);
                foreach (var state in Enum.GetValues(typeof(RequestState)).Cast<RequestState>())
                {
                    if (state == RequestState.COUNT) break;
                    Console.Write(",{0}", layerTimes[(int)state].ElementAt(i).Times[(int)state]);
                }
                Console.WriteLine();
            }
            Console.WriteLine();
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
