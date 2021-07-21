//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Quic;
using MsQuicTool;

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

            using ThroughputClient tp = new();
            var rate = tp.Upload(100000000);
            Console.WriteLine(rate);



            //using var Api = new QuicApi();
            //using var Registration = Api.OpenRegistration(null);

            //byte* alpn = stackalloc byte[] { (byte)'h', (byte)'3' };
            //QUIC_BUFFER buffer = new();
            //buffer.Buffer = alpn;
            //buffer.Length = 2;
            //QUIC_SETTINGS settings = new();
            //settings.IsSetFlags = 0;
            //settings.IsSet.PeerBidiStreamCount = 1;
            //settings.PeerBidiStreamCount = 1;
            //settings.IsSet.PeerUnidiStreamCount = 1;
            //settings.PeerUnidiStreamCount = 3;
            //using var Configuration = Registration.OpenConfiguration(&buffer, 1, &settings, (uint)sizeof(QUIC_SETTINGS), null);
            //QUIC_CREDENTIAL_CONFIG config = new();
            //config.Flags = QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_CLIENT;
            //Configuration.LoadCredential(&config);
            //using var Connection = Registration.OpenClientConnection(&NativeCallback, null);
            //byte* google = stackalloc byte[50];
            //int written = Encoding.UTF8.GetBytes("google.com", new Span<byte>(google, 50));
            //google[written] = 0;
            //Connection.Start(Configuration, 0, google, 443);
            //Thread.Sleep(1000);
        }
        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private unsafe static int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_CONNECTION_EVENT* evnt)
        {
            Console.WriteLine(evnt->Type);
            if (evnt->Type == QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT)
            {
                Console.WriteLine(evnt->SHUTDOWN_INITIATED_BY_TRANSPORT.Status.ToString("X8"));
            } else if (evnt->Type == QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED)
            {
                return MsQuic.QUIC_STATUS_ABORTED;
            }
            return MsQuic.QUIC_STATUS_SUCCESS;

        }
    }
}
