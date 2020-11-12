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

            var sampleFile = args[0];

            //
            // Create our runtime environment, enabling cookers and
            // adding inputs.
            //

            var runtime = Engine.Create(
                new EngineCreateInfo
                {
                    //
                    // Set this to from where you want to load your
                    // addins. The SDK by default will deploy your project,
                    // which is why we used that here. Production applications
                    // will more than likely use a different location (or
                    // a location specified by the user.)
                    //

                    ExtensionDirectory = Environment.CurrentDirectory
                });

            runtime.AddFile(sampleFile);

            //
            // Enable the cooker to data processing
            //

            runtime.EnableCooker(QuicEventCooker.CookerPath);

            //
            // Process our data.
            //

            var results = runtime.Process();

            //
            // Access our cooked data.
            //

            var quicState = results.QueryOutput<QuicState>(new DataOutputPath(QuicEventCooker.CookerPath, "State"));
            if (quicState == null)
            {
                return;
            }

            Console.WriteLine("Timestamp, ID");

            foreach (var evt in quicState.Events)
            {
                Console.WriteLine($"{evt.TimeStamp}, {evt.ID}");
            }
        }
    }
}
