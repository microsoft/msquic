using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Quic;

namespace QuicChatLib
{
    public unsafe struct StreamSendData
    {
        private int refCount;
        private QUIC_BUFFER buffer;

        public QUIC_BUFFER* Buffer
        {
            get
            {
                return (QUIC_BUFFER*)Unsafe.AsPointer(ref buffer);
            }
        }

        public void Release()
        {
            if (Interlocked.Decrement(ref refCount) == 0)
            {
                Marshal.FreeHGlobal((IntPtr)Unsafe.AsPointer(ref this));
            }
        }

        public static StreamSendData* GetStreamData(int bufferLen, int connCount)
        {
            StreamSendData* sendData = (StreamSendData*)Marshal.AllocHGlobal(sizeof(StreamSendData) + bufferLen);
            sendData->refCount = connCount;
            sendData->buffer.Length = (uint)bufferLen;
            sendData->buffer.Buffer = (byte*)(sendData + 1);
            return sendData;
        }
    }
}
