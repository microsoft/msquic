//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.Toolkit.Engine;
using QuicTrace.Cookers;
using QuicTrace.DataModel;

namespace QuicTrace
{
    class Program
    {
        static bool VerboseMode = false;

        internal enum FileType : ushort
        {
            None = 0,
            ETL,
            CTF, // lttng
        }

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

        static QuicState[] ProcessTraceFiles(IEnumerable<string> filePaths, FileType fileType)
        {
            var quicStates = new List<QuicState>();
            var cookerPath = fileType == FileType.ETL ? QuicEtwEventCooker.CookerPath : QuicLTTngEventCooker.CookerPath;
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
                runtime.EnableCooker(cookerPath);
                //Console.Write("Processing {0}...", filePath);
                var results = runtime.Process();
                //Console.WriteLine("Done.\n");

                //
                // Return our 'cooked' data.
                //
                quicStates.Add(results.QueryOutput<QuicState>(new DataOutputPath(cookerPath, "State")));
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
        public sealed class SequentialByteComparer : IEqualityComparer<byte[]>
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
            var ConnSourceCIDs = new Dictionary<byte[], QuicConnection>(new SequentialByteComparer());
            var ConnDestinationCIDs = new Dictionary<byte[], QuicConnection>(new SequentialByteComparer());

            var ClientRequests = new List<QuicStream>();
            var ServerRequests = new List<QuicStream>();

            foreach (var quicState in quicStates)
            {
                foreach (var conn in quicState.Connections)
                {
                    foreach (var src in conn.SourceCIDs)
                    {
                        try
                        {
                            ConnSourceCIDs.Add(src, conn);
                            if (conn.Peer == null && ConnDestinationCIDs.TryGetValue(src, out var peer))
                            {
                                conn.Peer = peer;
                                peer.Peer = conn;
                            }
                        }
                        catch { }
                    }

                    foreach (var dst in conn.DestinationCIDs)
                    {
                        try
                        {
                            ConnDestinationCIDs.Add(dst, conn);
                            if (conn.Peer == null && ConnSourceCIDs.TryGetValue(dst, out var peer))
                            {
                                conn.Peer = peer;
                                peer.Peer = conn;
                            }
                        }
                        catch { }
                    }
                }

                foreach (var stream in quicState.Streams)
                {
                    /*Console.WriteLine("\nConn {0}, Stream {1}, {2}, {3}", stream.Connection.Id, stream.Id, stream.Timings.IsServer ? "Server" : "Client", stream.Timings.EncounteredError ? "Errors" : "Success");
                    var t0 = stream.Timings.StateChanges[0].Item2;
                    foreach (var state in stream.Timings.StateChanges)
                    {
                        Console.WriteLine("  {0,-16}{1,6:F1}", state.Item1, (state.Item2 - t0).ToNanoseconds / 1000.0);
                    }*/

                    if (stream.Connection != null &&
                        !stream.Timings.EncounteredError &&
                        stream.Timings.IsFinalized)
                    {
                        if (stream.Timings.IsServer)
                        {
                            ServerRequests.Add(stream);
                        }
                        else
                        {
                            ClientRequests.Add(stream);
                        }
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

            var CompleteClientRequests = new List<QuicStream>();

            var MissingConnection = 0;
            var MissingPeer = 0;
            var MissingPeerTimings = 0;
            var ServerDict = new Dictionary<(ulong, ulong), QuicStream>();
            foreach (var x in ServerRequests) ServerDict.TryAdd((x.Connection!.Pointer, x.StreamId), x);
            foreach (var stream in ClientRequests)
            {
                if (stream.Connection == null)
                {
                    MissingConnection++;
                }
                else if (stream.Connection.Peer == null)
                {
                    MissingPeer++;
                }
                else if(!ServerDict.TryGetValue((stream.Connection.Peer.Pointer, stream.StreamId), out var peer))
                {
                    MissingPeerTimings++;
                }
                else
                {
                    stream.Timings.Peer = peer.Timings;
                    peer.Timings.Peer = stream.Timings;
                    CompleteClientRequests.Add(stream);
                }
            }

            clientRequestCount = CompleteClientRequests.Count;
            if (MissingConnection > 0) Console.WriteLine("WARNING: {0} requests missing connection!", MissingConnection);
            if (MissingPeer > 0) Console.WriteLine("WARNING: {0} requests missing peer connection!", MissingPeer);
            if (MissingPeerTimings > 0) Console.WriteLine("WARNING: {0} requests missing peer timings!", MissingPeerTimings);
            Console.WriteLine("{0} complete, matching requests found.", clientRequestCount);
            Console.WriteLine();

            if (clientRequestCount == 0) return;

            var Percentiles = new List<double>() { 0, 50, 90, 99, 99.9, 99.99, 99.999 };

            var sortedRequests = CompleteClientRequests.OrderBy(t => t.Timings.TotalTime);

            //
            // Percentile based on client request total time breakdown.
            //
            Console.WriteLine("Percentile,ID,Total,Net/2,Server,{0},{0}", string.Join(",", QuicStreamTiming.States));
            foreach (var percentile in Percentiles)
            {
                var s = sortedRequests.ElementAt((int)((clientRequestCount * percentile) / 100));
                var t = s.Timings;
                Console.WriteLine(
                    "{0}th,{1},{2},{3},{4},{5},{6}",
                    percentile,                                         // Percentile
                    s.StreamId,                                         // ID
                    t.TotalTime / 1000.0,                               // Total
                    t.ClientNetworkTime.ToNanoseconds / 2000.0,         // (Net/2)
                    t.Peer!.ServerResponseTime.ToNanoseconds / 1000.0,  // Server
                    string.Join(",", t.TimesUs),
                    string.Join(",", t.Peer.TimesUs));
            }
            Console.WriteLine();

            //
            // Full state changes for each percentile request above.
            //
            foreach (var percentile in Percentiles)
            {
                var s = sortedRequests.ElementAt((int)((clientRequestCount * percentile) / 100));
                var t = s.Timings;
                Console.WriteLine("\n{0}th Percentile, Conn {1}, Stream {2}\nClient", percentile, s.Connection!.Id, s.Id);
                var t0 = s.Timings.InitialStateTime;
                var prev = t0;
                foreach (var state in s.Timings.StateChanges)
                {
                    Console.WriteLine("  {0,-16}{1,6:F1}", state.Item1, (prev - t0).ToNanoseconds / 1000.0);
                    prev = state.Item2;
                }
                Console.WriteLine("Server");
                t0 = t.Peer!.InitialStateTime;
                prev = t0;
                foreach (var state in t.Peer!.StateChanges)
                {
                    Console.WriteLine("  {0,-16}{1,6:F1}", state.Item1, (prev - t0).ToNanoseconds / 1000.0);
                    prev = state.Item2;
                }
            }
            Console.WriteLine();

            //
            // Percentile based on individual layer breakdown.
            //
            var clientLayerTimes = new List<IOrderedEnumerable<QuicStream>>();
            var serverLayerTimes = new List<IOrderedEnumerable<QuicStream>>();
            foreach (var state in QuicStreamTiming.States)
            {
                clientLayerTimes.Add(CompleteClientRequests.OrderBy(s => s.Timings.Times[(int)state]));
                serverLayerTimes.Add(CompleteClientRequests.OrderBy(s => s.Timings.Peer!.Times[(int)state]));
            }

            Console.WriteLine("Percentile,{0},{0}", string.Join(",", QuicStreamTiming.States));
            foreach (var percentile in Percentiles)
            {
                var i = (int)((clientRequestCount * percentile) / 100);
                Console.Write("{0}th", percentile);
                foreach (var state in QuicStreamTiming.States)
                {
                    Console.Write(",{0}", clientLayerTimes[(int)state].ElementAt(i).Timings.TimesUs.ElementAt((int)state));
                }
                foreach (var state in QuicStreamTiming.States)
                {
                    Console.Write(",{0}", serverLayerTimes[(int)state].ElementAt(i).Timings.Peer!.TimesUs.ElementAt((int)state));
                }
                Console.WriteLine();
            }
            Console.WriteLine();

            //
            // Full breakdown of every request.
            //
            if (VerboseMode)
            {
                Console.WriteLine("ID,Total,Net/2,Server,{0},{0}", string.Join(",", QuicStreamTiming.States));
                foreach (var s in sortedRequests)
                {
                    var t = s.Timings;
                    Console.WriteLine(
                        "{0},{1},{2},{3},{4},{5}",
                        s.StreamId,                                         // ID
                        t.TotalTime / 1000.0,                               // Total
                        t.ClientNetworkTime.ToNanoseconds / 2000.0,         // (Net/2)
                        t.Peer!.ServerResponseTime.ToNanoseconds / 1000.0,  // Server
                        string.Join(",", t.TimesUs),
                        string.Join(",", t.Peer.TimesUs));
                }
                Console.WriteLine();
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
            var fileType = FileType.None;

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
                    fileType = FileType.ETL;
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
                    if (fileType == FileType.ETL && traceFiles.Last().EndsWith(".ctf") ||
                        fileType == FileType.CTF && traceFiles.Last().EndsWith(".etl") ||
                        (!traceFiles.Last().EndsWith(".ctf") && !traceFiles.Last().EndsWith(".etl")))
                    {
                        Console.WriteLine("Invalid file extension. Use .etl or .ctf. Use same if using multiple files");
                        return;
                    }

                    fileType = traceFiles.Last().EndsWith(".etl") ? FileType.ETL : FileType.CTF;
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
            var quicStates = ProcessTraceFiles(traceFiles, fileType);

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
