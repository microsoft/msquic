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
        static bool VerboseMode = false;

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
                "  -t, --text            Enables additional trace processing to allow for full text output\n" +
                "  -v, --verbose         Enables any verbose output"
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
            Create,
            QueueSend,
            ProcessSend,
            Frame,
            Write,
            Encrypt,
            Send,
            IdleSent,
            QueueRecv,
            ProcessRecv,
            Decrypt,
            Read,
            AppRecv,
            IdleRecv,
            COUNT
        };

        internal class RequestTiming
        {
            //
            // The time spent in each RequestState (in nanoseconds).
            //
            public ulong[] Times = new ulong[(int)RequestState.COUNT];

            //
            // Returns time spent in microseconds
            //
            public IEnumerable<double> TimesUs { get { return Times.Select(t => t / 1000.0); } }

            //
            // The current state of the request.
            //
            public RequestState State = RequestState.Create;

            //
            // The last time State was updated.
            //
            public ulong LastStateChangeTime = 0;

            //
            // Triggers a state change and updates variables accordingly.
            //
            public void UpdateToState(RequestState state, ulong time, bool ignorePrevious = false)
            {
                if (EncounteredError) return;
                if (time < LastStateChangeTime)
                {
                    if (!ignorePrevious)
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

            public void FinalizeState(ulong time)
            {
                if (EncounteredError) return;
                if (time < LastStateChangeTime)
                {
                    Console.WriteLine("ERROR: Invalid final time while in {0}", State);
                    EncounteredError = true;
                    return;
                }
                Times[(int)State] += (time - LastStateChangeTime);
                LastStateChangeTime = time;
            }

            //
            // Returns the sum of all the calculated times for individual layers.
            //
            public ulong TotalTime { get { return Times.Aggregate((temp, x) => temp + x); } }

            //
            // An estimate of the network cost from (Client.FirstRecv-Client.FirstSend)-(Server.FirstSend-Server.FirstRecv)
            //
            public ulong ClientNetworkTime
            {
                get
                {
                    var LocalTime = FirstPacketRecv - FirstPacketSend;
                    if (Peer!.ServerResponseTime < LocalTime)
                    {
                        return LocalTime - Peer!.ServerResponseTime;
                    }
                    return 0;
                }
            }
            public ulong ServerResponseTime { get { return FirstPacketSend - FirstPacketRecv; } }

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
            }

            //
            // Writes all the times in comma seperated vector format.
            //
            public void WriteCsv(bool newLine = true)
            {
                Console.Write("{0},", TotalTime/1000.0);
                Console.Write(String.Join(",", TimesUs));
                if (newLine) Console.WriteLine();
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
                            break;
                        }
                        case QuicEventId.ConnSourceCidAdded:
                        {
                            //Console.WriteLine("ConnSourceCidAdded {0}", evt.ObjectPointer);
                            var Conn = ConnSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            try
                            {
                                ConnSourceCIDs.Add((evt as QuicConnectionSourceCidAddedEvent)!.CID, Conn);
                                if (Conn.Peer == null && ConnDestinationCIDs.TryGetValue((evt as QuicConnectionSourceCidAddedEvent)!.CID, out var peer))
                                {
                                    Conn.Peer = peer;
                                    peer.Peer = Conn;
                                }
                            } catch { }
                            break;
                        }
                        case QuicEventId.ConnDestCidAdded:
                        {
                            //Console.WriteLine("ConnDestCidAdded {0}", evt.ObjectPointer);
                            var Conn = ConnSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            try
                            {
                                ConnDestinationCIDs.Add((evt as QuicConnectionDestinationCidAddedEvent)!.CID, Conn);
                                if (Conn.Peer == null && ConnSourceCIDs.TryGetValue((evt as QuicConnectionDestinationCidAddedEvent)!.CID, out var peer))
                                {
                                    Conn.Peer = peer;
                                    peer.Peer = Conn;
                                }
                            } catch { }
                            break;
                        }
                        case QuicEventId.StreamAlloc:
                        {
                            var Stream = StreamSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            if (Stream.Timings.EncounteredError) break;

                            Stream.Timings.Connection = ConnSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamAllocEvent)!.Connection, evt.ProcessId));
                            Stream.Timings.LastStateChangeTime = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamCreated:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.Timings.StreamID = (evt as QuicStreamCreatedEvent)!.StreamID;
                            Stream.Timings.IsServer = (evt as QuicStreamCreatedEvent)!.IsLocalOwned == 0;
                            break;
                        }
                        case QuicEventId.StreamAppSend:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.Timings.UpdateToState(RequestState.QueueSend, (ulong)evt.TimeStamp.ToNanoseconds);
                            break;
                        }
                        case QuicEventId.PacketCreated:
                        {
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Packet.Batch = PacketBatchSet.FindOrCreateActive(new QuicObjectKey(evt.PointerSize, (evt as QuicPacketCreatedEvent)!.BatchID, evt.ProcessId));
                            Packet.Batch.Packets.Add(Packet);
                            Packet.PacketCreate = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamWriteFrames:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            var OldSendPacket = Stream.SendPacket;
                            Stream.SendPacket = PacketSet.FindActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamWriteFramesEvent)!.ID, evt.ProcessId));
                            if (Stream.SendPacket == null)
                            {
                                //Console.WriteLine("ERROR: Failed to find Packet {0} for Write", (evt as QuicStreamWriteFramesEvent)!.ID);
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            if (Stream.SendPacket != OldSendPacket)
                            {
                                Stream.SendPacket.Streams.Add(Stream);
                                Stream.Timings.UpdateToState(RequestState.ProcessSend, Stream.Timings.Connection!.LastScheduleTime, true);
                                Stream.Timings.UpdateToState(RequestState.Frame, Stream.SendPacket.PacketCreate);
                            }

                            Stream.Timings.UpdateToState(RequestState.Write, (ulong)evt.TimeStamp.ToNanoseconds);
                            break;
                        }
                        case QuicEventId.PacketEncrypt:
                        {
                            var Packet = PacketSet.FindActive(new QuicObjectKey(evt));
                            if (Packet == null)
                            {
                                //Console.WriteLine("ERROR: Failed to find Packet {0} for Encrypt", (evt as QuicPacketEncryptEvent)!.ID);
                                break;
                            }
                            Packet.PacketEncrypt = (ulong)evt.TimeStamp.ToNanoseconds;

                            foreach (var Stream in Packet.Streams)
                            {
                                if (Stream.Timings.State != RequestState.Write)
                                {
                                    //Console.WriteLine("ERROR: Stream in {0} state for Encrypt", Stream.Timings.State);
                                    Stream.Timings.EncounteredError = true;
                                    continue;
                                }

                                Stream.Timings.UpdateToState(RequestState.Encrypt, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            break;
                        }
                        case QuicEventId.PacketFinalize:
                        {
                            var Packet = PacketSet.FindActive(new QuicObjectKey(evt));
                            if (Packet == null)
                            {
                                //Console.WriteLine("ERROR: Failed to find Packet {0} for Finalize", (evt as QuicPacketFinalizeEvent)!.ID);
                                break;
                            }
                            Packet.PacketFinalize = (ulong)evt.TimeStamp.ToNanoseconds;

                            foreach (var Stream in Packet.Streams)
                            {
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
                            var Batch = PacketBatchSet.FindActive(new QuicObjectKey(evt));
                            if (Batch == null) break;
                            Batch.BatchSent = (ulong)evt.TimeStamp.ToNanoseconds;

                            foreach (var Packet in Batch.Packets)
                            {
                                foreach (var Stream in Packet.Streams)
                                {
                                    if (Stream.Timings.State == RequestState.Send)
                                    {
                                        Stream.Timings.UpdateToState(RequestState.IdleSent, (ulong)evt.TimeStamp.ToNanoseconds);
                                    }
                                    else if (Stream.Timings.State != RequestState.IdleSent)
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
                            var Packet = PacketSet.FindOrCreateActive((ushort)evt.EventId, new QuicObjectKey(evt));
                            Packet.PacketReceive = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.PacketDecrypt:
                        {
                            var Packet = PacketSet.FindActive(new QuicObjectKey(evt));
                            if (Packet == null)
                            {
                                //Console.WriteLine("ERROR: Failed to find Packet {0} for Decrypt", (evt as QuicPacketDecryptEvent)!.ID);
                                break;
                            }
                            if (Packet.PacketDecrypt != 0)
                            {
                                //Console.WriteLine("ERROR: Duplicate PacketDecrypt for packet");
                                break;
                            }
                            Packet.PacketDecrypt = (ulong)evt.TimeStamp.ToNanoseconds;
                            break;
                        }
                        case QuicEventId.StreamReceiveFrame:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            var OldRecvPacket = Stream.RecvPacket;
                            Stream.RecvPacket = PacketSet.FindActive(new QuicObjectKey(evt.PointerSize, (evt as QuicStreamReceiveFrameEvent)!.ID, evt.ProcessId));
                            if (Stream.RecvPacket == null)
                            {
                                //Console.WriteLine("ERROR: Failed to find Packet {0} for Read", (evt as QuicStreamReceiveFrameEvent)!.ID);
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            if (Stream.RecvPacket.PacketDecrypt == 0)
                            {
                                //Console.WriteLine("ERROR: No PacketDecrypt for Read");
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            if (Stream.Timings.FirstPacketRecv == 0)
                            {
                                Stream.Timings.FirstPacketRecv = Stream.RecvPacket.PacketReceive;
                            }

                            if (OldRecvPacket != Stream.RecvPacket)
                            {
                                if (Stream.Timings.State == RequestState.Create)
                                {
                                    Stream.Timings.State = RequestState.QueueRecv;
                                    Stream.Timings.LastStateChangeTime = Stream.RecvPacket.PacketReceive;
                                }
                                else
                                {
                                    Stream.Timings.UpdateToState(RequestState.QueueRecv, Stream.RecvPacket.PacketReceive, true);
                                }
                                Stream.Timings.UpdateToState(RequestState.ProcessRecv, Stream.Timings.Connection!.LastScheduleTime, true);
                                Stream.Timings.UpdateToState(RequestState.Decrypt, Stream.RecvPacket.PacketDecrypt);
                            }

                            Stream.Timings.UpdateToState(RequestState.Read, (ulong)evt.TimeStamp.ToNanoseconds);
                            break;
                        }
                        case QuicEventId.StreamAppReceive:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            Stream.Timings.UpdateToState(RequestState.AppRecv, (ulong)evt.TimeStamp.ToNanoseconds);
                            break;
                        }
                        case QuicEventId.StreamAppReceiveComplete:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            if (Stream.Timings.State == RequestState.AppRecv)
                            {
                                Stream.Timings.UpdateToState(RequestState.IdleRecv, (ulong)evt.TimeStamp.ToNanoseconds);
                            }
                            break;
                        }
                        case QuicEventId.StreamDestroyed:
                        {
                            var Stream = StreamSet.FindActive(new QuicObjectKey(evt));
                            if (Stream == null || Stream.Timings.EncounteredError) break;

                            if (Stream.Timings.StreamID == ulong.MaxValue)
                            {
                                //Console.WriteLine("ERROR: Missing StreamID for StreamDestroyed");
                                Stream.Timings.EncounteredError = true;
                                break;
                            }

                            Stream.Timings.FinalizeState((ulong)evt.TimeStamp.ToNanoseconds);
                            if (Stream.Timings.EncounteredError) break;

                            if (Stream.Timings.IsServer)
                            {
                                ServerRequests.Add(Stream.Timings);
                            }
                            else
                            {
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
            Console.WriteLine("{0} client and {1} server complete requests found.", clientRequestCount, serverRequestCount);

            var CompleteClientRequests = new List<RequestTiming>();

            var MissingPeer = 0;
            var MissingPeerTimings = 0;
            var ServerDict = ServerRequests.ToDictionary(x => ( x.Connection!.Pointer, x.StreamID ) );
            foreach (var timing in ClientRequests)
            {
                if (timing.Connection!.Peer == null)
                {
                    //Console.WriteLine("WARNING: Missing connection peer!");
                    MissingPeer++;
                }
                else if(!ServerDict.TryGetValue(( timing.Connection!.Peer.Pointer, timing.StreamID ), out var peer))
                {
                    //Console.WriteLine("WARNING: Cannot find matching peer timings!");
                    MissingPeerTimings++;
                }
                else
                {
                    timing.Peer = peer;
                    peer.Peer = timing;
                    CompleteClientRequests.Add(timing);
                }
            }

            var sortedRequests = CompleteClientRequests.OrderBy(t => t.TotalTime);
            clientRequestCount = CompleteClientRequests.Count;

            if (MissingPeer > 0) Console.WriteLine("WARNING: {0} connections missing peer!", MissingPeer);
            if (MissingPeerTimings > 0) Console.WriteLine("WARNING: {0} connections missing peer timings!", MissingPeerTimings);
            Console.WriteLine("{0} complete, matching requests found.", clientRequestCount);
            Console.WriteLine();

            if (VerboseMode)
            {
                RequestTiming.WriteCsvHeader();
                RequestTiming.WriteCsvHeader(false);
                Console.WriteLine();
                foreach (var timing in sortedRequests)
                {
                    timing.WriteCsv(false);
                    Console.Write(",");
                    Console.WriteLine(String.Join(",", timing.Peer!.TimesUs));
                }
                Console.WriteLine();
            }

            Console.Write("Percentile,ID,");
            RequestTiming.WriteCsvHeader();
            Console.Write(",Network,PeerResponse,");
            RequestTiming.WriteCsvHeader(false);
            Console.WriteLine();
            var Percentiles = new List<double>() { 0, 50, 90, 99, 99.9, 99.99, 99.999 };
            foreach (var percentile in Percentiles)
            {
                var t = sortedRequests.ElementAt((int)((clientRequestCount * percentile) / 100));
                Console.Write("{0}th,{1},", percentile, t.StreamID);
                t.WriteCsv(false);
                Console.Write(",{0},{1},", t.ClientNetworkTime/1000.0, t.Peer!.ServerResponseTime/1000.0);
                Console.WriteLine(String.Join(",", t.Peer.TimesUs));
            }
            Console.WriteLine();

            var layerTimes = new List<IOrderedEnumerable<RequestTiming>>();
            foreach (var state in Enum.GetValues(typeof(RequestState)).Cast<RequestState>())
            {
                if (state == RequestState.COUNT) break;
                layerTimes.Add(CompleteClientRequests.OrderBy(t => t.Times[(int)state]));
            }

            Console.Write("Percentile");
            RequestTiming.WriteCsvHeader(false);
            Console.WriteLine();
            foreach (var percentile in Percentiles)
            {
                var i = (int)((clientRequestCount * percentile) / 100);
                Console.Write("{0}th", percentile);
                foreach (var state in Enum.GetValues(typeof(RequestState)).Cast<RequestState>())
                {
                    if (state == RequestState.COUNT) break;
                    Console.Write(",{0}", layerTimes[(int)state].ElementAt(i).TimesUs.ElementAt((int)state));
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
                else if (args[i] == "--verbose" || args[i] == "-v")
                {
                    VerboseMode = true;
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
