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
    internal unsafe class ServerConnection
    {
        private readonly Registration registration;
        private readonly QUIC_HANDLE* connHandle;
        private readonly GCHandle gcHandle;

        internal ServerConnection(Registration registration, QUIC_HANDLE* connHandle)
        {
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
                case QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                {
                    // Post shutdown event to our queue
                    break;
                }
            }
            return 0;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private static int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_CONNECTION_EVENT* evnt)
        {
            var @this = (ServerConnection)GCHandle.FromIntPtr((IntPtr)context).Target!;
            return @this.HandleCallback(ref *evnt);

        }
    }
}
