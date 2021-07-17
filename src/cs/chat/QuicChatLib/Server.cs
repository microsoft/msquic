using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace QuicChatLib
{
    public class Server : IDataReceiver, IServerHandler, IAsyncDisposable
    {
        private readonly Registration registration;
        private readonly ServerConfiguration configuration;
        private readonly Listener listener;
        private readonly List<Stream> streams = new();
        private readonly object streamLock = new();
        private bool disposing = false;
        private readonly SemaphoreSlim allStreamsCleanedUp = new(0);
        private readonly Task runTask;
        private readonly CancellationTokenSource tokenSource = new();

        public Server(string thumbprint)
        {
            registration = new();
            configuration = new(registration, thumbprint);
            listener = new(this, this, registration, configuration);
            runTask = RunLoop(tokenSource.Token);
            listener.Start();
        }

        private async Task RunLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var newData = await ReceiveChannel.Reader.ReadAsync(token);
                if (newData.Buffer == null)
                {
                    lock (streamLock)
                    {
                        streams.Remove(newData.Stream);
                        if (disposing && streams.Count == 0)
                        {
                            allStreamsCleanedUp.Release();
                        }
                    }
                    newData.Stream.Close();
                }
                else if (newData.Tag == DataReceiveTag.Chat)
                {
                    unsafe
                    {
                        Console.WriteLine(Encoding.UTF8.GetString(newData.Buffer.Value.Span));
                        lock (streamLock)
                        {
                            if (streams.Count == 1 && streams[0] == newData.Stream) continue;
                            StreamSendData* sendData = StreamSendData.GetStreamData(newData.Buffer.Value.Length, streams.Count);
                            newData.Buffer.Value.Span.CopyTo(sendData->Buffer->Span);
                            foreach (var stream in streams)
                            {
                                if (stream == newData.Stream)
                                {
                                    sendData->Release();
                                    continue;
                                }
                                stream.Send(sendData);
                            }
                        }
                    }
                }
            }
        }

        public Channel<StreamReceiveData> ReceiveChannel { get; } = Channel.CreateUnbounded<StreamReceiveData>();

        public bool AddStream(Stream stream)
        {
            lock (streamLock)
            {
                if (disposing)
                {
                    return false;
                }
                streams.Add(stream);
            }
            return true;
        }

        public async ValueTask DisposeAsync()
        {
            listener.Stop();
            lock (streamLock)
            {
                disposing = true;
                foreach (var stream in streams)
                {
                    stream.Shutdown();
                }
                if (streams.Count == 0)
                {
                    allStreamsCleanedUp.Release();
                }
            }
            await allStreamsCleanedUp.WaitAsync();
            tokenSource.Cancel();
            try
            {
                await runTask;
            }
            catch (OperationCanceledException)
            {

            }
            listener.Dispose();
            configuration.Dispose();
            registration.Dispose();
        }
    }
}
