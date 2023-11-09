/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Defines the types used for the performance client-side.

--*/

#pragma once

#include "PerfHelpers.h"
#include "PerfCommon.h"

struct PerfClientConnection {
    struct PerfClient& Client;
    struct PerfClientWorker& Worker;
    union {
    HQUIC Handle {nullptr};
    TcpConnection* TcpConn;
    };
    HashTable StreamTable;
    uint64_t StreamsCreated {0};
    uint64_t StreamsActive {0};
    PerfClientConnection(_In_ PerfClient& Client, _In_ PerfClientWorker& Worker) : Client(Client), Worker(Worker) { }
    ~PerfClientConnection();
    void Initialize();
    void StartNewStream();
    void OnConnectionComplete();
    void OnShutdownComplete();
    void OnStreamShutdownComplete();
    QUIC_STATUS ConnectionCallback(_Inout_ QUIC_CONNECTION_EVENT* Event);
    static QUIC_STATUS s_ConnectionCallback(HQUIC, void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        return ((PerfClientConnection*)Context)->ConnectionCallback(Event);
    }
    static void TcpConnectCallback(_In_ TcpConnection* Connection, bool IsConnected);
    static void TcpSendCompleteCallback(_In_ TcpConnection* Connection, _In_ TcpSendData* SendDataChain);
    static void
    TcpReceiveCallback(
        _In_ TcpConnection* Connection,
        uint32_t StreamID,
        bool Open,
        bool Fin,
        bool Abort,
        uint32_t Length,
        _In_ uint8_t* Buffer
        );
    struct PerfClientStream* GetTcpStream(uint32_t ID);
};

struct PerfClientStream {
    CXPLAT_HASHTABLE_ENTRY Entry; // To TCP StreamTable (must be first)
    PerfClientStream(_In_ PerfClientConnection& Connection) : Connection{Connection} { }
    ~PerfClientStream() { if (Handle) { MsQuic->StreamClose(Handle); } }
    static QUIC_STATUS s_StreamCallback(HQUIC, void* Context, QUIC_STREAM_EVENT* Event) {
        return ((PerfClientStream*)Context)->StreamCallback(Event);
    }
    PerfClientConnection& Connection;
    HQUIC Handle {nullptr};
    uint64_t StartTime {CxPlatTimeUs64()};
    uint64_t RecvStartTime {0};
    uint64_t SendEndTime {0};
    uint64_t RecvEndTime {0};
    uint64_t IdealSendBuffer {PERF_DEFAULT_SEND_BUFFER_SIZE};
    uint64_t BytesSent {0};
    uint64_t BytesOutstanding {0};
    uint64_t BytesAcked {0};
    uint64_t BytesReceived {0};
    bool SendComplete {false};
    QUIC_BUFFER LastBuffer;
    QUIC_STATUS StreamCallback(_Inout_ QUIC_STREAM_EVENT* Event);
    void Send();
    void OnSendComplete(_In_ uint32_t Length, _In_ bool Canceled);
    void OnSendShutdownComplete();
    void OnReceive(_In_ uint64_t Length, _In_ bool Finished);
    void OnStreamShutdownComplete();
};

struct QUIC_CACHEALIGN PerfClientWorker {
    PerfClient* Client {nullptr};
    CxPlatLock Lock;
    CXPLAT_THREAD Thread;
    CxPlatEvent WakeEvent;
    bool ThreadStarted {false};
    uint16_t Processor {UINT16_MAX};
    uint64_t ConnectionsQueued {0};
    uint64_t ConnectionsCreated {0};
    uint64_t ConnectionsConnected {0};
    uint64_t ConnectionsActive {0};
    uint64_t ConnectionsCompleted {0};
    uint64_t StreamsStarted {0};
    uint64_t StreamsCompleted {0};
    UniquePtr<char[]> Target;
    QuicAddr LocalAddr;
    QuicAddr RemoteAddr;
    QuicPoolAllocator<PerfClientConnection> ConnectionAllocator;
    QuicPoolAllocator<PerfClientStream> StreamAllocator;
    QuicPoolAllocator<TcpConnection> TcpConnectionAllocator;
    QuicPoolAllocator<TcpSendData> TcpSendDataAllocator;
    PerfClientWorker() { }
    ~PerfClientWorker() { WaitForThread(); }
    void Uninitialize() { WaitForThread(); }
    void QueueNewConnection() {
        InterlockedIncrement64((int64_t*)&ConnectionsQueued);
        WakeEvent.Set();
    }
    void OnConnectionComplete();
    static CXPLAT_THREAD_CALLBACK(s_WorkerThread, Context) {
        ((PerfClientWorker*)Context)->WorkerThread();
        CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
    }
private:
    void WaitForThread() {
        if (ThreadStarted) {
            WakeEvent.Set();
            CxPlatThreadWait(&Thread);
            CxPlatThreadDelete(&Thread);
            ThreadStarted = false;
        }
    }
    void StartNewConnection();
    void WorkerThread();
};

struct PerfClient : public PerfBase {
    PerfClient() {
        for (uint32_t i = 0; i < PERF_MAX_THREAD_COUNT; ++i) {
            Workers[i].Client = this;
        }
    }
    ~PerfClient() override { Running = false; delete Engine; }
    QUIC_STATUS Init(_In_ int argc, _In_reads_(argc) _Null_terminated_ char* argv[]) override;
    QUIC_STATUS Start(_In_ CXPLAT_EVENT* StopEvent) override;
    QUIC_STATUS Wait(_In_ int Timeout) override;
    void GetExtraDataMetadata(_Out_ PerfExtraDataMetadata* Result) override;
    QUIC_STATUS GetExtraData(_Out_writes_bytes_(*Length) uint8_t* Data, _Inout_ uint32_t* Length) override;

    MsQuicRegistration Registration {
        "perf-client",
        PerfDefaultExecutionProfile,
        true};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(PERF_ALPN),
        MsQuicSettings()
            .SetDisconnectTimeoutMs(PERF_DEFAULT_DISCONNECT_TIMEOUT)
            .SetIdleTimeoutMs(PERF_DEFAULT_IDLE_TIMEOUT)
            .SetSendBufferingEnabled(false)
            .SetCongestionControlAlgorithm(PerfDefaultCongestionControl)
            .SetEcnEnabled(PerfDefaultEcnEnabled)
            .SetEncryptionOffloadAllowed(PerfDefaultQeoAllowed),
        MsQuicCredentialConfig(
            QUIC_CREDENTIAL_FLAG_CLIENT |
            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)};
    // Target parameters
    UniquePtr<char[]> Target;
    QUIC_ADDRESS_FAMILY TargetFamily {QUIC_ADDRESS_FAMILY_UNSPEC};
    uint16_t TargetPort {PERF_DEFAULT_PORT};
    uint32_t CibirIdLength {0};
    uint8_t CibirId[7]; // {offset, values}
    uint8_t IncrementTarget {FALSE};
    // Local execution parameters
    uint32_t WorkerCount;
    uint8_t AffinitizeWorkers {FALSE};
    uint8_t SpecificLocalAddresses {FALSE};
#ifdef QUIC_COMPARTMENT_ID
    uint16_t CompartmentId {UINT16_MAX};
#endif
    // General parameters
    uint8_t UseTCP {FALSE};
    uint8_t UseEncryption {TRUE};
    uint8_t UsePacing {TRUE};
    uint8_t UseSendBuffering {FALSE};
    uint8_t PrintThroughput {FALSE};
    uint8_t PrintConnections {FALSE};
    uint8_t PrintStreams {FALSE};
    uint8_t PrintLatency {FALSE};
    // Scenario parameters
    uint32_t ConnectionCount {1};
    uint32_t StreamCount {0};
    uint32_t IoSize {PERF_DEFAULT_IO_SIZE};
    uint32_t Upload {0};
    uint32_t Download {0};
    uint8_t Timed {FALSE};
    //uint8_t SendInline {FALSE};
    uint8_t RepeatConnections {FALSE};
    uint8_t RepeatStreams {FALSE};
    uint32_t RunTime {0};

    struct PerfIoBuffer {
        QUIC_BUFFER* Buffer {nullptr};
        operator QUIC_BUFFER* () noexcept { return Buffer; }
        ~PerfIoBuffer() noexcept { if (Buffer) { CXPLAT_FREE(Buffer, QUIC_POOL_PERF); } }
        void Init(uint32_t IoSize, uint64_t Initial) noexcept {
            Buffer = (QUIC_BUFFER*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + IoSize, QUIC_POOL_PERF);
            Buffer->Length = IoSize;
            Buffer->Buffer = (uint8_t*)(Buffer + 1);
            *(uint64_t*)(Buffer->Buffer) = CxPlatByteSwapUint64(Initial);
            for (uint32_t i = 0; i < IoSize; ++i) {
                Buffer->Buffer[sizeof(uint64_t) + i] = (uint8_t)i;
            }
        }
    } RequestBuffer;

    CXPLAT_EVENT* CompletionEvent {nullptr};
    UniquePtr<uint32_t[]> LatencyValues {nullptr}; // TODO - Move to Worker
    uint64_t MaxLatencyIndex {0};
    uint64_t CurLatencyIndex {0};
    uint64_t LatencyCount {0};
    PerfClientWorker Workers[PERF_MAX_THREAD_COUNT];
    TcpEngine* Engine {nullptr};
    bool Running {true};

    uint32_t GetConnectedConnections() const {
        uint32_t ConnectedConnections = 0;
        for (uint32_t i = 0; i < WorkerCount; ++i) {
            ConnectedConnections += Workers[i].ConnectionsConnected;
        }
        return ConnectedConnections;
    }
    uint32_t GetConnectionsActive() const {
        uint32_t ConnectionsActive = 0;
        for (uint32_t i = 0; i < WorkerCount; ++i) {
            ConnectionsActive += Workers[i].ConnectionsActive;
        }
        return ConnectionsActive;
    }
    uint32_t GetConnectionsCompleted() const {
        uint32_t ConnectionsCompleted = 0;
        for (uint32_t i = 0; i < WorkerCount; ++i) {
            ConnectionsCompleted += Workers[i].ConnectionsCompleted;
        }
        return ConnectionsCompleted;
    }
    uint64_t GetStreamsStarted() const {
        uint64_t StreamsStarted = 0;
        for (uint32_t i = 0; i < WorkerCount; ++i) {
            StreamsStarted += Workers[i].StreamsStarted;
        }
        return StreamsStarted;
    }
    uint64_t GetStreamsCompleted() const {
        uint64_t StreamsCompleted = 0;
        for (uint32_t i = 0; i < WorkerCount; ++i) {
            StreamsCompleted += Workers[i].StreamsCompleted;
        }
        return StreamsCompleted;
    }

    void OnConnectionsComplete() { // Called when a worker has completed its set of connections
        if (GetConnectionsCompleted() == ConnectionCount) {
            CxPlatEventSet(*CompletionEvent);
        }
    }
};
