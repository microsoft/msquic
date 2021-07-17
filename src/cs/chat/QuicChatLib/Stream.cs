using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Quic;

namespace QuicChatLib
{
    public unsafe class Stream
    {
        private readonly Registration registration;
        private readonly IConnection connection;
        private readonly QUIC_HANDLE* streamHandle;
        private readonly GCHandle gcHandle;
        private readonly IDataReceiver receiver;
        private int currentTag = -1;
        private int currentLength = -1;
        private Memory<byte>? currentData;

        public static Stream? CreateClient(IDataReceiver receiver, Registration registration, ClientConnection conn)
        {
            Stream? stream = new(receiver, registration, conn, out var status);
            if (MsQuic.StatusFailed(status))
            {
                stream = null;
            }
            return stream;
        }


        private Stream(IDataReceiver receiver, Registration registration, ClientConnection conn, out int status)
        {
            this.registration = registration;
            this.connection = conn;
            this.receiver = receiver;
            gcHandle = GCHandle.Alloc(this);
            QUIC_HANDLE* handle = null;
            status = registration.Table.StreamOpen(conn.Handle, QUIC_STREAM_OPEN_FLAGS.QUIC_STREAM_OPEN_FLAG_NONE, &NativeCallback, (void*)(IntPtr)gcHandle, &handle);
            if (MsQuic.StatusFailed(status))
            {
                gcHandle.Free();
                return;
            }
            this.streamHandle = handle;
            registration.Table.StreamStart(handle, QUIC_STREAM_START_FLAGS.QUIC_STREAM_START_FLAG_ASYNC | QUIC_STREAM_START_FLAGS.QUIC_STREAM_START_FLAG_IMMEDIATE | QUIC_STREAM_START_FLAGS.QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL);
        }

        internal Stream(IDataReceiver receiver, Registration registration, ServerConnection conn, QUIC_HANDLE* handle)
        {
            this.registration = registration;
            this.connection = conn;
            this.streamHandle = handle;
            this.receiver = receiver;
            gcHandle = GCHandle.Alloc(this);
            delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_STREAM_EVENT*, int> cb = &NativeCallback;
            registration.Table.SetCallbackHandler(handle, (void*)cb, (void*)(IntPtr)gcHandle);
        }

        private void ProcessFullReceiveBuffer()
        {
            var channel = receiver.ReceiveChannel;
            // TODO handle write failure
            channel.Writer.TryWrite(new StreamReceiveData()
            {
                Stream = this,
                Buffer = currentData!.Value,
                Tag = (DataReceiveTag)currentTag
            });
            currentData = null;
            currentTag = -1;
        }

        private void HandleReceive(ref QUIC_STREAM_EVENT evnt)
        {
            ref var receive = ref evnt.RECEIVE;

            ulong bufferLength = receive.TotalBufferLength;
            ulong currentBufferIndex = 0;
            ulong currentBufferOffset = 0;
            while (bufferLength > 0)
            {
                Debug.Assert(currentBufferIndex < receive.BufferCount);
                Debug.Assert(currentBufferOffset < receive.Buffers[currentBufferIndex].Length);

                if (currentTag < 0)
                {
                    currentTag = receive.Buffers[currentBufferIndex].Buffer[currentBufferOffset];
                    currentBufferOffset++;
                    bufferLength--;
                    currentData = null;
                    currentLength = -1;
                }
                else if (currentData == null)
                {
                    if (currentLength >= 0)
                    {
                        // We have 1 byte of our length, read the other
                        int toReadLength = (currentLength << 8) | receive.Buffers[currentBufferIndex].Buffer[currentBufferOffset];
                        currentBufferOffset++;
                        currentLength = 0;
                        bufferLength--;
                        currentData = new byte[toReadLength];
                    }
                    else
                    {
                        currentLength = receive.Buffers[currentBufferIndex].Buffer[currentBufferOffset];
                        currentBufferOffset++;
                        bufferLength--;
                    }
                }
                else
                {
                    // Reading data
                    var buffer = receive.Buffers[currentBufferIndex];
                    Span<byte> incomingData = new(buffer.Buffer + currentBufferOffset, (int)(buffer.Length - currentBufferOffset));
                    Span<byte> currentDataSpan = currentData.Value.Span.Slice(currentLength);
                    if (incomingData.Length > currentDataSpan.Length)
                    {
                        incomingData.Slice(0, currentDataSpan.Length);
                    }
                    incomingData.CopyTo(currentDataSpan);
                    currentBufferOffset += (ulong)incomingData.Length;
                    bufferLength -= (ulong)incomingData.Length;
                    currentLength += incomingData.Length;
                    Debug.Assert(currentLength <= currentData.Value.Length);
                    if (currentLength == currentData.Value.Length)
                    {
                        ProcessFullReceiveBuffer();
                        currentTag = 0;
                    }
                }

                Debug.Assert(currentBufferOffset <= receive.Buffers[currentBufferIndex].Length);
                if (currentBufferOffset == receive.Buffers[currentBufferIndex].Length)
                {
                    currentBufferOffset = 0;
                    currentBufferIndex++;
                }
            }
        }

        public void Send(StreamSendData* sendData)
        {
            int status = registration.Table.StreamSend(streamHandle, sendData->Buffer, 1, QUIC_SEND_FLAGS.QUIC_SEND_FLAG_NONE, sendData);
            if (MsQuic.StatusFailed(status))
            {
                sendData->Release();
            }
        }

        public void Shutdown()
        {
            registration.Table.StreamShutdown(streamHandle, QUIC_STREAM_SHUTDOWN_FLAGS.QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE | QUIC_STREAM_SHUTDOWN_FLAGS.QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }

        public void Close()
        {
            connection.Shutdown();
            registration.Table.StreamClose(streamHandle);
            gcHandle.Free();
        }

        public void Reject()
        {
            connection.Shutdown();
            registration.Table.SetCallbackHandler(streamHandle, null, null);
            gcHandle.Free();
        }

        private int HandleCallback(ref QUIC_STREAM_EVENT evnt)
        {
            Console.WriteLine(evnt.Type);
            switch (evnt.Type)
            {
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_RECEIVE:
                    HandleReceive(ref evnt);
                    break;
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SEND_COMPLETE:
                    ((StreamSendData*)evnt.SEND_COMPLETE.ClientContext)->Release();
                    break;
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                    receiver.ReceiveChannel.Writer.TryWrite(new StreamReceiveData
                    {
                        Stream = this,
                        Buffer = null,
                        Tag = (DataReceiveTag)(-1)
                    });
                    break;
            }
            return 0;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private static int NativeCallback(QUIC_HANDLE* handle, void* context, QUIC_STREAM_EVENT* evnt)
        {
            var @this = (Stream)GCHandle.FromIntPtr((IntPtr)context).Target!;
            return @this.HandleCallback(ref *evnt);

        }
    }
}
