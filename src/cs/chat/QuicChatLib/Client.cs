using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace QuicChatLib
{
    public class Client : IDataReceiver, IAsyncDisposable
    {
        public Channel<StreamReceiveData> ReceiveChannel { get; } = Channel.CreateUnbounded<StreamReceiveData>();

        private Registration registration;
        private ClientConnection clientConn;
        private Stream? stream;

        public Client()
        {
            registration = new Registration();
            clientConn = new ClientConnection(registration, this);
        }

        public async Task<bool> Start(string hostname, CancellationToken token)
        {
            
            stream = await clientConn.Start(hostname, token);
            return stream != null;
        }

        public async Task<string?> Read(CancellationToken token)
        {
            StreamReceiveData recvData = await ReceiveChannel.Reader.ReadAsync(token);
            Debug.Assert(recvData.Stream == stream);
            if (recvData.Buffer == null)
            {
                // Stream shutting down, call close and break
                recvData.Stream.Close();
                stream = null;
                return null;
            }
            else if (recvData.Tag == DataReceiveTag.Chat)
            {
                return Encoding.UTF8.GetString(recvData.Buffer.Value.Span);
            }
            return null;
        }

        public string Name { get; set; } = "NotSet";

        public unsafe void Send(string msg)
        {
            if (stream == null)
            {
                throw new InvalidOperationException("Connection must have been started");
            }

            int byteCount = Encoding.UTF8.GetByteCount(msg);
            byteCount += Encoding.UTF8.GetByteCount(Name) + 2;
            StreamSendData* sendData = StreamSendData.GetStreamData(byteCount, 1);
            var dataSpan = sendData->Buffer->Span;
            var added = Encoding.UTF8.GetBytes(Name, dataSpan);
            dataSpan = dataSpan.Slice(added);
            added = Encoding.UTF8.GetBytes(": ", dataSpan);
            dataSpan = dataSpan.Slice(added);
            added = Encoding.UTF8.GetBytes(msg, dataSpan);
            dataSpan = dataSpan.Slice(added);
            stream?.Send(sendData);
        }

        public async ValueTask DisposeAsync()
        {
            if (stream != null)
            {
                stream.Shutdown();
                string? data;
                do
                {
                    data = await Read(default);
                } while (data != null);
            }
            await clientConn.DisposeAsync();
            registration.Dispose();
        }
    }
}
