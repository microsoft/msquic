using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace QuicChatLib
{
    public class ClientConnection : IAsyncDisposable, IConnection
    {
        private readonly Registration registration;
        private readonly ClientConfiguration configuration;
        private unsafe readonly QUIC_HANDLE* connHandle;
        private readonly IDataReceiver receiver;

        public unsafe QUIC_HANDLE* Handle => connHandle;

        private readonly GCHandle gcHandle;
        private readonly SemaphoreSlim shutdownMutex = new(0);
        private readonly SemaphoreSlim connectedMutex = new(0);
        private Stream? stream;

        public unsafe ClientConnection(Registration registration, IDataReceiver receiver)
        {
            this.receiver = receiver;
            this.registration = registration;
            configuration = new ClientConfiguration(registration);
            gcHandle = GCHandle.Alloc(this);
            QUIC_HANDLE* handle = null;
            int status = registration.Table.ConnectionOpen(registration.Handle, &NativeCallback, (void*)(IntPtr)gcHandle, &handle);
            if (MsQuic.StatusFailed(status))
            {
                gcHandle.Free();
                MsQuic.ThrowIfFailure(status);
            }
            connHandle = handle;
        }

        public async Task<Stream?> Start(string serverName, CancellationToken token)
        {
            unsafe void NonAsyncCall()
            {
                int len = Encoding.UTF8.GetMaxByteCount(serverName.Length);
                byte* rawName = stackalloc byte[len + 1];
                Span<byte> rawNameSpan = new Span<byte>(rawName, len);
                int actualLen = Encoding.UTF8.GetBytes(serverName, rawNameSpan);
                rawName[actualLen] = 0;

                int status = registration.Table.ConnectionStart(connHandle, configuration.Handle, MsQuic.QUIC_ADDRESS_FAMILY_INET, rawName, Constants.Port);
                MsQuic.ThrowIfFailure(status);
            }
            NonAsyncCall();
            await connectedMutex.WaitAsync(token);
            return stream;
        }

        private int HandleCallback(ref QUIC_CONNECTION_EVENT evnt)
        {
            Console.WriteLine(evnt.Type);
            switch (evnt.Type)
            {
                case QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_CONNECTED:
                    stream = Stream.CreateClient(receiver, registration, this);
                    connectedMutex.Release();
                    break;
                case QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                    connectedMutex.Release();
                    shutdownMutex.Release();
                    break;
            }
            return MsQuic.QUIC_STATUS_SUCCESS;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private unsafe static int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_CONNECTION_EVENT* evnt)
        {
            var @this = (ClientConnection)GCHandle.FromIntPtr((IntPtr)context).Target!;
            return @this.HandleCallback(ref *evnt);

        }

        public unsafe void Shutdown()
        {
            registration.Table.ConnectionShutdown(connHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }

        public async ValueTask DisposeAsync()
        {
            unsafe
            {
                registration.Table.ConnectionShutdown(connHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            }
            await shutdownMutex.WaitAsync();
            unsafe
            {
                registration.Table.ConnectionClose(connHandle);
            }
            configuration.Dispose();
            shutdownMutex.Dispose();
            connectedMutex.Dispose();
        }
    }
}
