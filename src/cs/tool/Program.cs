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

namespace MsQuicTool
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

            var ApiTable = MsQuic.Open();
            QUIC_HANDLE* registration = null;
            QUIC_HANDLE* configuration = null;
            QUIC_HANDLE* connection = null;
            try
            {

                MsQuic.ThrowIfFailure(ApiTable->RegistrationOpen(null, &registration));
                byte* alpn = stackalloc byte[] { (byte)'h', (byte)'3' };
                QUIC_BUFFER buffer = new();
                buffer.Buffer = alpn;
                buffer.Length = 2;
                QUIC_SETTINGS settings = new();
                settings.IsSetFlags = 0;
                settings.IsSet.PeerBidiStreamCount = 1;
                settings.PeerBidiStreamCount = 1;
                settings.IsSet.PeerUnidiStreamCount = 1;
                settings.PeerUnidiStreamCount = 3;
                MsQuic.ThrowIfFailure(ApiTable->ConfigurationOpen(registration, &buffer, 1, &settings, (uint)sizeof(QUIC_SETTINGS), null, &configuration));
                QUIC_CREDENTIAL_CONFIG config = new();
                config.Flags = QUIC_CREDENTIAL_FLAGS.CLIENT;
                MsQuic.ThrowIfFailure(ApiTable->ConfigurationLoadCredential(configuration, &config));
                MsQuic.ThrowIfFailure(ApiTable->ConnectionOpen(registration, &NativeCallback, ApiTable, &connection));
                sbyte* google = stackalloc sbyte[50];
                int written = Encoding.UTF8.GetBytes("google.com", new Span<byte>(google, 50));
                google[written] = 0;
                MsQuic.ThrowIfFailure(ApiTable->ConnectionStart(connection, configuration, 0, google, 443));
                Thread.Sleep(1000);
            }
            finally
            {
                if (connection != null)
                {
                    ApiTable->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAGS.NONE, 0);
                    ApiTable->ConnectionClose(connection);
                }
                if (configuration != null)
                {
                    ApiTable->ConfigurationClose(configuration);
                }
                if (registration != null)
                {
                    ApiTable->RegistrationClose(registration);
                }
                MsQuic.Close(ApiTable);
            }
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private static unsafe int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_CONNECTION_EVENT* evnt)
        {
            Console.WriteLine(evnt->Type);
            if (evnt->Type == QUIC_CONNECTION_EVENT_TYPE.CONNECTED)
            {
                QUIC_API_TABLE* ApiTable = (QUIC_API_TABLE*)context;
                void* buf = stackalloc byte[128];
                uint len = 128;
                if (MsQuic.StatusSucceeded(ApiTable->GetParam(handle, MsQuic.QUIC_PARAM_CONN_REMOTE_ADDRESS, &len, buf)))
                {
                    QuicAddr* addr = (QuicAddr*)(buf);
                    Console.WriteLine($"Connected Family: {addr->Family}");
                }
            }
            if (evnt->Type == QUIC_CONNECTION_EVENT_TYPE.PEER_STREAM_STARTED)
            {
                Console.WriteLine("Aborting Stream");
                return MsQuic.QUIC_STATUS_ABORTED;
            }
            if (evnt->Type == QUIC_CONNECTION_EVENT_TYPE.SHUTDOWN_INITIATED_BY_TRANSPORT)
            {
                Console.WriteLine($"{evnt->SHUTDOWN_INITIATED_BY_TRANSPORT.Status.ToString("X8")}: {MsQuicException.GetErrorCodeForStatus(evnt->SHUTDOWN_INITIATED_BY_TRANSPORT.Status)}");
            }
            return MsQuic.QUIC_STATUS_SUCCESS;
        }
    }
}
