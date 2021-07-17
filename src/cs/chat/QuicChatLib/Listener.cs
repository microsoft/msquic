using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Quic;

namespace QuicChatLib
{
    public unsafe class Listener : IDisposable
    {
        private readonly Registration registration;
        private readonly ServerConfiguration configuration;
        private readonly IDataReceiver receiver;
        private readonly IServerHandler serverHandler;
        private readonly QUIC_HANDLE* handle;
        private readonly GCHandle gcHandle;
        private bool running;

        public Listener(IDataReceiver receiver, IServerHandler serverHandler, Registration registration, ServerConfiguration configuration)
        {
            this.receiver = receiver;
            this.serverHandler = serverHandler;
            this.configuration = configuration;
            this.registration = registration;
            QUIC_HANDLE* handle = null;
            GCHandle gcHandle = GCHandle.Alloc(this);
            int status = registration.Table.ListenerOpen(registration.Handle, &NativeCallback, (void*)(IntPtr)gcHandle, &handle);
            if (MsQuic.StatusFailed(status))
            {
                gcHandle.Free();
                MsQuic.ThrowIfFailure(status);
            }
            this.gcHandle = gcHandle;
            this.handle = handle;
        }

        private int HandleCallback(ref QUIC_LISTENER_EVENT evnt)
        {
            switch (evnt.Type)
            {
                case QUIC_LISTENER_EVENT_TYPE.QUIC_LISTENER_EVENT_NEW_CONNECTION:
                    ServerConnection serverConn = new ServerConnection(receiver, serverHandler, registration, evnt.NEW_CONNECTION.Connection);
                    registration.Table.ConnectionSetConfiguration(evnt.NEW_CONNECTION.Connection, configuration.Handle);
                    // TODO load connection
                    break;
            }
            return 0;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private static int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_LISTENER_EVENT* evnt)
        {
            Listener @this = (Listener)GCHandle.FromIntPtr((IntPtr)context).Target!;
            return @this.HandleCallback(ref *evnt);

        }

        public void Dispose()
        {
            if (handle != null)
            {
                Stop();
                registration.Table.ListenerClose(handle);
                gcHandle.Free();
            }

        }

        public void Start()
        {
            if (running)
            {
                return;
            }

            fixed (byte* alpn = Constants.Alpn)
            {
                QUIC_BUFFER buffer = new();
                buffer.Buffer = alpn;
                buffer.Length = (uint)Constants.Alpn.Length;

                int status = registration.Table.ListenerStart(handle, &buffer, 1, null);
                MsQuic.ThrowIfFailure(status);
                running = true;
            }            
        }

        public void Stop()
        {
            if (!running)
            {
                return;
            }
            registration.Table.ListenerStop(handle);
            running = false;
        }
    }
}
