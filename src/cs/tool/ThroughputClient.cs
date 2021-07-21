using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace MsQuicTool
{
    public unsafe class ThroughputClient : IDisposable
    {
        private readonly QUIC_API_TABLE* apiTable;
        private readonly QUIC_HANDLE* registration;
        private readonly QUIC_HANDLE* configuration;
        private QUIC_HANDLE* connection;
        private QUIC_HANDLE* stream;
        private readonly GCHandle gcHandle;

        private bool complete;
        private long outstandingBytes;
        private long idealSendBuffer = 0x20000;
        private Stopwatch stopWatch;
        private long uploadLength;
        private long bytesSent;

        private readonly QUIC_BUFFER* dataBuffer;
        private QUIC_BUFFER* lastBuffer;
        private const int IoSize = 0x10000;
        private readonly SemaphoreSlim semaphore = new(0);
        private long bytesCompleted = 0;
        private long downloadLength = 0;

        long rate = 0;

        private int ConnCallback(ref QUIC_CONNECTION_EVENT connEvent)
        {
            if (connEvent.Type == QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE)
            {
                // Set event
                semaphore.Release();
            }
            return 0;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private unsafe static int ConnCallback(QUIC_HANDLE* handle, void* context, QUIC_CONNECTION_EVENT* evnt)
        {
            return ((ThroughputClient)GCHandle.FromIntPtr((IntPtr)context).Target).ConnCallback(ref *evnt);
        }

        private int StreamCallback(ref QUIC_STREAM_EVENT streamEvent)
        {
            switch (streamEvent.Type)
            {
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_RECEIVE:
                    bytesCompleted += (long)streamEvent.RECEIVE.TotalBufferLength;
                    if (bytesCompleted == downloadLength)
                    {
                        complete = true;
                    }
                    break;
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SEND_COMPLETE:
                    if (uploadLength != 0)
                    {
                        outstandingBytes -= ((QUIC_BUFFER*)streamEvent.SEND_COMPLETE.ClientContext)->Length;
                        if (streamEvent.SEND_COMPLETE.Canceled == 0)
                        {
                            bytesCompleted += ((QUIC_BUFFER*)streamEvent.SEND_COMPLETE.ClientContext)->Length;
                            SendQuicData();
                        }
                    }
                    break;
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
                    apiTable->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAGS.QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
                    break;
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                    OnStreamShutdownComplete();
                    break;
                case QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
                    if (uploadLength != 0 && (ulong)idealSendBuffer < streamEvent.IDEAL_SEND_BUFFER_SIZE.ByteCount)
                    {
                        idealSendBuffer = (long)streamEvent.IDEAL_SEND_BUFFER_SIZE.ByteCount;
                        SendQuicData();
                    }
                    break;
            }
            return 0;
        }

        [UnmanagedCallersOnly(CallConvs = new Type[] { typeof(CallConvCdecl) })]
        private unsafe static int StreamCallback(QUIC_HANDLE* handle, void* context, QUIC_STREAM_EVENT* evnt)
        {
            return ((ThroughputClient)GCHandle.FromIntPtr((IntPtr)context).Target).StreamCallback(ref *evnt);
        }

        public ThroughputClient()
        {
            try
            {
                apiTable = MsQuic.Open();
                QUIC_HANDLE* tmpHandle = null;
                MsQuic.ThrowIfFailure(apiTable->RegistrationOpen(null, &tmpHandle));
                registration = tmpHandle;
                tmpHandle = null;
                byte* alpn = stackalloc byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'f' };
                QUIC_BUFFER buffer = new();
                buffer.Buffer = alpn;
                buffer.Length = 4;
                QUIC_SETTINGS settings = new();
                settings.IdleTimeoutMs = 1000;
                settings.IsSet.IdleTimeoutMs = 1;
                MsQuic.ThrowIfFailure(apiTable->ConfigurationOpen(registration, &buffer, 1, &settings, (uint)sizeof(QUIC_SETTINGS), null, &tmpHandle));
                configuration = tmpHandle;
                tmpHandle = null;
                QUIC_CREDENTIAL_CONFIG credConfig = new();
                credConfig.Flags = QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
                MsQuic.ThrowIfFailure(apiTable->ConfigurationLoadCredential(configuration, &credConfig));
                gcHandle = GCHandle.Alloc(this);
                dataBuffer = (QUIC_BUFFER*)Marshal.AllocHGlobal(sizeof(QUIC_BUFFER) + sizeof(QUIC_BUFFER) + IoSize);
                lastBuffer = dataBuffer + 1;
                dataBuffer->Buffer = (byte*)(dataBuffer + 2);
                dataBuffer->Length = IoSize;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        private void OnStreamShutdownComplete()
        {
            stopWatch.Stop();
            long sendRate = (bytesCompleted * 1000 * 1000 * 8) / (1000 * 1000 * stopWatch.ElapsedMilliseconds);
            rate = sendRate;

            if (complete)
            {
                Console.WriteLine($"Complete {bytesCompleted} bytes @ {sendRate} kbps");
            }
            else if (bytesCompleted != 0)
            {
                Console.WriteLine($"Partial complete {bytesCompleted} bytes @ {sendRate} kbps");
            }
            else
            {
                Console.WriteLine("Failed to complete any bytes");
            }
        }

        private void SendQuicData()
        {
            while (!complete && outstandingBytes < idealSendBuffer)
            {
                long bytesLeftToSend = uploadLength - bytesSent;
                int dataLength = IoSize;
                QUIC_BUFFER* buffer = dataBuffer;
                QUIC_SEND_FLAGS flags = QUIC_SEND_FLAGS.QUIC_SEND_FLAG_NONE;

                if (dataLength >= bytesLeftToSend)
                {
                    dataLength = (int)bytesLeftToSend;
                    lastBuffer->Buffer = buffer->Buffer;
                    lastBuffer->Length = (uint)dataLength;
                    buffer = lastBuffer;
                    flags = QUIC_SEND_FLAGS.QUIC_SEND_FLAG_FIN;
                    complete = true;
                }

                bytesSent += dataLength;
                outstandingBytes += dataLength;

                apiTable->StreamSend(stream, buffer, 1, flags, buffer);
            }
        }

        private void Start()
        {
            QUIC_HANDLE* tmpHandle = null;
            MsQuic.ThrowIfFailure(apiTable->ConnectionOpen(registration, &ConnCallback, (void*)(IntPtr)gcHandle, &tmpHandle));
            connection = tmpHandle;
            tmpHandle = null;
            QUIC_SETTINGS settings = new();
            settings.IsSet.SendBufferingEnabled = 1;
            settings.SendBufferingEnabled = 0;
            MsQuic.ThrowIfFailure(apiTable->SetParam(connection, QUIC_PARAM_LEVEL.QUIC_PARAM_LEVEL_CONNECTION, MsQuic.QUIC_PARAM_CONN_SETTINGS, (uint)sizeof(QUIC_SETTINGS), &settings));
            MsQuic.ThrowIfFailure(apiTable->StreamOpen(connection, QUIC_STREAM_OPEN_FLAGS.QUIC_STREAM_OPEN_FLAG_NONE, &StreamCallback, (void*)(IntPtr)gcHandle, &tmpHandle));
            stream = tmpHandle;
            MsQuic.ThrowIfFailure(apiTable->StreamStart(stream, QUIC_STREAM_START_FLAGS.QUIC_STREAM_START_FLAG_NONE));
        }

        private void StartConn()
        {

            byte* addr = stackalloc byte[512];
            Span<byte> addrSpan = new(addr, 512);
            int len = Encoding.UTF8.GetBytes("localhost", addrSpan);
            addrSpan[len] = 0;
            stopWatch = Stopwatch.StartNew();
            MsQuic.ThrowIfFailure(apiTable->ConnectionStart(connection, configuration, 0, addr, 4433));
        }

        private void Wait()
        {
            semaphore.Wait();
        }

        public long Upload(long bytes)
        {
            Start();
            uploadLength = bytes;
            SendQuicData();
            StartConn();
            Wait();
            return rate;
        }

        public void Dispose()
        {
            if (apiTable != null)
            {
                // Shutdown registration
                if (registration != null)
                {
                    apiTable->RegistrationShutdown(registration, QUIC_CONNECTION_SHUTDOWN_FLAGS.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                }
                if (stream != null)
                {
                    apiTable->StreamClose(stream);
                }
                if (connection != null)
                {
                    apiTable->ConnectionClose(connection);
                }
                if (configuration != null)
                {
                    apiTable->ConfigurationClose(configuration);
                }
                if (registration != null)
                {
                    apiTable->RegistrationClose(registration);
                }
            }
            if (gcHandle.IsAllocated)
            {
                gcHandle.Free();
            }
            if (dataBuffer != null)
            {
                Marshal.FreeHGlobal((IntPtr)dataBuffer);
            }
        }
    }
}
