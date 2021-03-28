//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Runtime.InteropServices;
using Microsoft.Quic;

namespace tool
{
    class Program
    {
        static unsafe void Main(string[] args)
        {
            // This code lets us pass in an argument of where to search for the library at.
            // Very helpful for testing
            if (args.Length > 0)
            {
                NativeLibrary.SetDllImportResolver(typeof(MsQuic).Assembly, (libraryName, assembly, searchPath) =>
                {
                    if (libraryName != "msquic") return IntPtr.Zero;
                    if (NativeLibrary.TryLoad(args[0], out var ptr))
                    {
                        return ptr;
                    }
                    return IntPtr.Zero;
                });
            }

            // TODO make this an actual unit test
            var ApiTable = MsQuic.Open();
            try
            {

                QUIC_SETTINGS Settings;
                uint SettingsSize = (uint)sizeof(QUIC_SETTINGS);
                int Status = ApiTable->GetParam(null, QUIC_PARAM_LEVEL.QUIC_PARAM_LEVEL_GLOBAL, MsQuic.QUIC_PARAM_GLOBAL_SETTINGS, &SettingsSize, &Settings);
                MsQuic.ThrowIfFailure(Status);
                Console.WriteLine("Ran Successfully!");
            }
            finally
            {
                MsQuic.Close(ApiTable);
            }
            

        }
    }
}
