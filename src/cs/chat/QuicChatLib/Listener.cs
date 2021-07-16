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
        private readonly QUIC_HANDLE* handle;
        private readonly IntPtr gcHandle;
        private bool running;

        public Listener(Registration registration)
        {
            this.registration = registration;
            QUIC_HANDLE* handle = null;
            GCHandle gcHandle = GCHandle.Alloc(this);
            int status = registration.Table.ListenerOpen(registration.Handle, &NativeCallback, (void*)(IntPtr)gcHandle, &handle);
            if (MsQuic.StatusFailed(status))
            {
                gcHandle.Free();
                MsQuic.ThrowIfFailure(status);
            }
            this.gcHandle = (IntPtr)gcHandle;
            this.handle = handle;
        }

        private int HandleCallback(ref QUIC_LISTENER_EVENT evnt)
        {
            switch (evnt.Type)
            {
                case QUIC_LISTENER_EVENT_TYPE.QUIC_LISTENER_EVENT_NEW_CONNECTION:
                    // TODO handle certificates
                    ref var conn = ref evnt.NEW_CONNECTION;
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
                GCHandle.FromIntPtr(gcHandle).Free();
            }

        }

        public void Start(ReadOnlySpan<char> alpn)
        {
            if (running)
            {
                return;
            }

            if (alpn.Length > 255)
            {
                throw new ArgumentException(nameof(alpn), "ALPN too long");
            }
            int len = Encoding.UTF8.GetMaxByteCount(alpn.Length);
            byte* rawAlpn = stackalloc byte[len];
            Span<byte> rawAlpnSpan = new Span<byte>(rawAlpn, len);
            int actualLen = Encoding.UTF8.GetBytes(alpn, rawAlpnSpan);
            QUIC_BUFFER buffer;
            buffer.Buffer = rawAlpn;
            buffer.Length = (uint)actualLen;

            int status = registration.Table.ListenerStart(handle, &buffer, 1, null);
            MsQuic.ThrowIfFailure(status);
            running = true;
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
