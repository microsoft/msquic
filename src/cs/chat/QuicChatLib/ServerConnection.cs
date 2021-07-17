using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace QuicChatLib
{
    internal unsafe class ServerConnection : IConnection
    {
        private readonly Registration registration;
        private readonly QUIC_HANDLE* connHandle;
        private readonly GCHandle gcHandle;
        private readonly IDataReceiver receiver;
        private readonly IServerHandler serverHandler;

        internal ServerConnection(IDataReceiver receiver, IServerHandler serverHandler, Registration registration, QUIC_HANDLE* connHandle)
        {
            this.serverHandler = serverHandler;
            this.receiver = receiver;
            this.registration = registration;
            this.connHandle = connHandle;
            gcHandle = GCHandle.Alloc(this);
            delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_CONNECTION_EVENT*, int> cb = &NativeCallback;
            registration.Table.SetCallbackHandler(connHandle, (void*)cb, (void*)(IntPtr)gcHandle);
        }

        private int HandleCallback(ref QUIC_CONNECTION_EVENT evnt)
        {
            switch (evnt.Type)
            {
                case QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
                    {
                        var stream = new Stream(receiver, registration, this, evnt.PEER_STREAM_STARTED.Stream);
                        if (!serverHandler.AddStream(stream))
                        {
                            stream.Reject();
                            return MsQuic.QUIC_STATUS_ABORTED;
                        }
                        break;
                    }

                case QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                    {
                        gcHandle.Free();
                        registration.Table.ConnectionClose(connHandle);
                        break;
                    }
            }
            return MsQuic.QUIC_STATUS_SUCCESS;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private static int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_CONNECTION_EVENT* evnt)
        {
            var @this = (ServerConnection)GCHandle.FromIntPtr((IntPtr)context).Target!;
            return @this.HandleCallback(ref *evnt);

        }

        public void Shutdown()
        {
            registration.Table.ConnectionShutdown(connHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
}
