/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Defines the types used for the performance client-side.

--*/


#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

struct PerfClientConnection;
struct PerfClientStream;
struct PerfClientWorker;
class PerfClient;

struct PerfClientConnection : public MsQuicConnection {
    CXPLAT_LIST_ENTRY Link; // For Worker's connection queue
    PerfClient& Client;
    PerfClientWorker* Worker {nullptr};
    uint32_t StreamCount {0};
    PerfClientConnection(_In_ const MsQuicRegistration& Registration, _In_ PerfClient& Client)
        : MsQuicConnection(Registration, CleanUpManual, s_ConnectionCallback), Client(Client) { }
    QUIC_STATUS ConnectionCallback(_Inout_ QUIC_CONNECTION_EVENT* Event);
    static QUIC_STATUS s_ConnectionCallback(MsQuicConnection* /* Conn */, void* Context, QUIC_CONNECTION_EVENT* Event) {
        return ((PerfClientConnection*)Context)->ConnectionCallback(Event);
    }
    QUIC_STATUS StreamCallback(_In_ PerfClientStream* StrmContext, _In_ HQUIC StreamHandle, _Inout_ QUIC_STREAM_EVENT* Event);
    void SendRequest(bool DelaySend);
};

struct PerfClientStream {
    PerfClientStream(_In_ PerfClientConnection& Connection, _In_ uint64_t StartTime)
        : Connection{Connection}, StartTime{StartTime} { }
    static QUIC_STATUS
    s_StreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
        return ((PerfClientStream*)Context)->Connection.StreamCallback((PerfClientStream*)Context, Stream, Event);
    }
    PerfClientConnection& Connection;
    uint64_t StartTime;
#if DEBUG
    uint8_t Padding[12];
#endif
};

struct PerfClientWorker {
    PerfClient* Client {nullptr};
    CxPlatLock Lock;
    CXPLAT_LIST_ENTRY Connections;
    CXPLAT_THREAD Thread;
    CxPlatEvent WakeEvent;
    bool ThreadStarted {false};
    uint32_t ConnectionCount {0};
    uint32_t CompletionCount {0};
    uint16_t Processor {UINT16_MAX};
    PerfClientWorker() {
        CxPlatListInitializeHead(&Connections);
    }
    ~PerfClientWorker() {
        WaitForThread();
    }
    void WaitForThread() {
        if (ThreadStarted) {
            WakeEvent.Set();
            CxPlatThreadWait(&Thread);
            CxPlatThreadDelete(&Thread);
            ThreadStarted = false;
        }
    }
    void Uninitialize() {
        Lock.Acquire();
        CxPlatListInitializeHead(&Connections); // TODO - Cleanup
        Lock.Release();
        WaitForThread();
    }
    PerfClientConnection* GetConnection() {
        PerfClientConnection* Connection = nullptr;
        Lock.Acquire();
        if (!CxPlatListIsEmpty(&Connections)) {
            Connection =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Connections),
                    PerfClientConnection,
                    Link);
            CxPlatListInsertTail(&Connections, &Connection->Link);
        }
        Lock.Release();
        return Connection;
    }
    void QueueNewConnection() {
        Lock.Acquire();
        bool Wake = 0 == ConnectionCount++;
        Lock.Release();
        if (Wake) WakeEvent.Set();
    }
    void UpdateConnection(PerfClientConnection* Connection) {
        if (this != Connection->Worker) {
            Connection->Worker->Lock.Acquire();
            CxPlatListEntryRemove(&Connection->Link);
            Connection->Worker->Lock.Release();
            QueueConnection(Connection);
        }
    }
    void QueueSendRequest();

    void WorkerThread();
    CXPLAT_THREAD_CALLBACK(s_WorkerThread, Context) {
        ((PerfClientWorker*)Context)->WorkerThread();
        CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
    }
};

class PerfClient : public PerfBase {
public:

    PerfClient() {
        CxPlatZeroMemory(LocalAddresses, sizeof(LocalAddresses));
        for (uint32_t i = 0; i < PERF_MAX_THREAD_COUNT; ++i) {
            Workers[i].Client = this;
        }
    }

    ~PerfClient() override {
        if (Connections.get()) {
            for (uint32_t i = 0 ; i < ConnectionCount; ++i) {
                delete Connections[i];
            }
        }
        Running = false;
    }

    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) override;

    QUIC_STATUS Start(_In_ CXPLAT_EVENT* StopEvent) override;
    QUIC_STATUS Wait(_In_ int Timeout) override;
    void GetExtraDataMetadata(_Out_ PerfExtraDataMetadata* Result) override;

    QUIC_STATUS
    GetExtraData(
        _Out_writes_bytes_(*Length) uint8_t* Data,
        _Inout_ uint32_t* Length
        ) override;

    QUIC_STATUS StartWorkers();
    void StopWorkers();

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
    QUIC_ADDR RemoteAddr;
    uint16_t TargetPort {PERF_DEFAULT_PORT};
    uint32_t CibirIdLength {0};
    uint8_t CibirId[7]; // {offset, values}
    // Local execution parameters
    QUIC_ADDR LocalAddresses[PERF_MAX_CLIENT_PORT_COUNT];
    uint32_t MaxLocalAddrCount {PERF_MAX_CLIENT_PORT_COUNT};
    uint32_t WorkerCount;
    uint8_t AffinitizeWorkers {FALSE};
    uint8_t SpecificLocalAddresses {FALSE};
#ifdef QUIC_COMPARTMENT_ID
    uint16_t CompartmentId {UINT16_MAX};
#endif
    // General parameters
    uint8_t UseEncryption {TRUE};
    uint8_t UsePacing {TRUE};
    uint8_t UseSendBuffering {FALSE};
    uint8_t PrintStats {FALSE};
    uint8_t PrintStreamStats {FALSE};
    uint8_t PrintLatencyStats {FALSE};
    // Scenario parameters
    uint32_t ConnectionCount {1};
    uint32_t StreamCount {0};
    uint32_t IoSize {PERF_DEFAULT_IO_SIZE};
    uint32_t Upload {0};
    uint32_t Download {0};
    uint8_t Timed {FALSE};
    uint32_t HandshakeWaitTime {0};
    uint8_t SendInline {FALSE};
    uint8_t RepeateConnections {FALSE};
    uint8_t RepeatStreams {FALSE};
    uint32_t RunTime {0};

    struct PerfIoBuffer {
        QUIC_BUFFER* Buffer {nullptr};
        operator QUIC_BUFFER* () noexcept { return Buffer; }
        ~PerfIoBuffer() noexcept { if (Buffer) { CXPLAT_FREE(Buffer, QUIC_POOL_PERF); } }
        void Init(uint32_t IoSize, uint64_t Initial) noexcept {
            Buffer = (QUIC_BUFFER*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + sizeof(uint64_t) + IoSize, QUIC_POOL_PERF);
            Buffer->Length = sizeof(uint64_t) + IoSize;
            Buffer->Buffer = (uint8_t*)(Buffer + 1);
            *(uint64_t*)(Buffer->Buffer) = CxPlatByteSwapUint64(Initial);
            for (uint32_t i = 0; i < IoSize; ++i) {
                Buffer->Buffer[sizeof(uint64_t) + i] = (uint8_t)i;
            }
        }
    } RequestBuffer;

    CXPLAT_EVENT* CompletionEvent {nullptr};
    uint32_t ActiveConnections {0};
    CxPlatEvent AllConnected {true};
    uint64_t StartedRequests {0};
    uint64_t SendCompletedRequests {0};
    uint64_t CompletedRequests {0};
    uint64_t CachedCompletedRequests {0};
    UniquePtr<uint32_t[]> LatencyValues {nullptr};
    uint64_t MaxLatencyIndex {0};
    QuicPoolAllocator<PerfClientStream> StreamAllocator;
    PerfClientWorker Workers[PERF_MAX_THREAD_COUNT];
    bool Running {true};
};
