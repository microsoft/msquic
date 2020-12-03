//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.Toolkit.Engine;
using MsQuicTracing;
using MsQuicTracing.DataModel;

namespace MsQuicEtw
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Sample *.etl file required");
                return;
            }

            //
            // Enable full event and payload parsing.
            //
            QuicEvent.ParseMode = QuicEventParseMode.Full;

            //
            // Create our runtime environment, enabling cookers and adding inputs.
            //
            var runtime = Engine.Create();
            runtime.AddFile(args[0]);
            runtime.EnableCooker(QuicEventCooker.CookerPath);
            Console.WriteLine("Processing...");
            var results = runtime.Process();

            //
            // Access our cooked data.
            //
            var quicState = results.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));

            /*foreach (var evt in quicState.Events)
            {
                Console.WriteLine(evt);
            }*/

            Console.WriteLine("Conn, Process ID, Pointer");
            foreach (var conn in quicState.Connections)
            {
                Console.WriteLine($"{conn.Id}, {conn.ProcessId}, {conn.Pointer}");
                foreach (var evt in conn.Events)
                {
                    Console.WriteLine(evt);
                }
            }
        }
    }
}
