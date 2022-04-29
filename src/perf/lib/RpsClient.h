/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf RPS Client declaration. Defines the functions and
    variables used in the RpsClient class.

--*/


#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

struct RpsConnectionContext;
struct RpsWorkerContext;
class RpsClient;

struct StreamContext {
    StreamContext(
        _In_ RpsConnectionContext* Connection,
        _In_ uint64_t StartTime)
        : Connection{Connection}, StartTime{StartTime} { }
    RpsConnectionContext* Connection;
    uint64_t StartTime;
#if DEBUG
    uint8_t Padding[12];
#endif
};

struct RpsConnectionContext {
    CXPLAT_LIST_ENTRY Link; // For Worker's connection queue
    RpsClient* Client {nullptr};
    RpsWorkerContext* Worker {nullptr};
    HQUIC Handle {nullptr};
    operator HQUIC() const { return Handle; }
    ~RpsConnectionContext() noexcept { if (Handle) { MsQuic->ConnectionClose(Handle); } }
    QUIC_STATUS
    ConnectionCallback(
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );
    QUIC_STATUS
    StreamCallback(
        _In_ StreamContext* StrmContext,
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event
        );
    void SendRequest(bool DelaySend);
};

struct RpsWorkerContext {
    class RpsClient* Client {nullptr};
    CXPLAT_LOCK Lock;
    CXPLAT_LIST_ENTRY Connections;
    CXPLAT_THREAD Thread;
    CXPLAT_EVENT WakeEvent;
    bool ThreadStarted {false};
    uint32_t RequestCount {0};
    RpsWorkerContext() {
        CxPlatLockInitialize(&Lock);
        CxPlatEventInitialize(&WakeEvent, FALSE, FALSE);
        CxPlatListInitializeHead(&Connections);
    }
    ~RpsWorkerContext() {
        WaitForWorker();
        CxPlatEventUninitialize(WakeEvent);
        CxPlatLockUninitialize(&Lock);
    }
    void WaitForWorker() {
        if (ThreadStarted) {
            CxPlatEventSet(WakeEvent);
            CxPlatThreadWait(&Thread);
            CxPlatThreadDelete(&Thread);
            ThreadStarted = false;
        }
    }
    void Uninitialize() {
        CxPlatLockAcquire(&Lock);
        CxPlatListInitializeHead(&Connections);
        CxPlatLockRelease(&Lock);
        WaitForWorker();
    }
    RpsConnectionContext* GetConnection() {
        RpsConnectionContext* Connection = nullptr;
        CxPlatLockAcquire(&Lock);
        if (!CxPlatListIsEmpty(&Connections)) {
            Connection =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Connections),
                    RpsConnectionContext,
                    Link);
            CxPlatListInsertTail(&Connections, &Connection->Link);
        }
        CxPlatLockRelease(&Lock);
        return Connection;
    }
    void QueueConnection(RpsConnectionContext* Connection) {
        Connection->Worker = this;
        CxPlatLockAcquire(&Lock);
        CxPlatListInsertTail(&Connections, &Connection->Link);
        CxPlatLockRelease(&Lock);
    }
    void UpdateConnection(RpsConnectionContext* Connection) {
        if (this != Connection->Worker) {
            CxPlatLockAcquire(&Connection->Worker->Lock);
            CxPlatListEntryRemove(&Connection->Link);
            CxPlatLockRelease(&Connection->Worker->Lock);
            QueueConnection(Connection);
        }
    }
    void QueueSendRequest();
};

class RpsClient : public PerfBase {
public:

    RpsClient() {
        for (uint32_t i = 0; i < PERF_MAX_THREAD_COUNT; ++i) {
            Workers[i].Client = this;
        }
    }

    ~RpsClient() override {
        Running = false;
    }

    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) override;

    QUIC_STATUS
    Start(
        _In_ CXPLAT_EVENT* StopEvent
        ) override;

    QUIC_STATUS
    Wait(
        _In_ int Timeout
        ) override;

    void
    GetExtraDataMetadata(
        _Out_ PerfExtraDataMetadata* Result
        ) override;

    QUIC_STATUS
    GetExtraData(
        _Out_writes_bytes_(*Length) uint8_t* Data,
        _Inout_ uint32_t* Length
        ) override;

    MsQuicRegistration Registration {
        "secnetperf-client-rps",
        QUIC_EXECUTION_PROFILE_LOW_LATENCY,
        true};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(PERF_ALPN),
        MsQuicSettings()
            .SetDisconnectTimeoutMs(PERF_DEFAULT_DISCONNECT_TIMEOUT)
            .SetIdleTimeoutMs(PERF_DEFAULT_IDLE_TIMEOUT)
            .SetSendBufferingEnabled(false),
        MsQuicCredentialConfig(
            QUIC_CREDENTIAL_FLAG_CLIENT |
            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)};
    uint32_t WorkerCount;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_ADDRESS_FAMILY RemoteFamily {QUIC_ADDRESS_FAMILY_UNSPEC};
    UniquePtr<char[]> Target;
    uint8_t UseEncryption {TRUE};
    uint8_t SendInline {FALSE};
    uint32_t RunTime {RPS_DEFAULT_RUN_TIME};
    uint32_t ConnectionCount {RPS_DEFAULT_CONNECTION_COUNT};
    uint32_t RequestCount {RPS_DEFAULT_CONNECTION_COUNT * 2};
    uint32_t RequestLength {RPS_DEFAULT_REQUEST_LENGTH};
    uint32_t ResponseLength {RPS_DEFAULT_RESPONSE_LENGTH};
    uint32_t CibirIdLength {0};
    uint8_t CibirId[7]; // {offset, values}

    struct QuicBufferScopeQuicAlloc {
        QUIC_BUFFER* Buffer;
        QuicBufferScopeQuicAlloc() noexcept : Buffer(nullptr) { }
        operator QUIC_BUFFER* () noexcept { return Buffer; }
        ~QuicBufferScopeQuicAlloc() noexcept { if (Buffer) { CXPLAT_FREE(Buffer, QUIC_POOL_PERF); } }
    };

    QuicBufferScopeQuicAlloc RequestBuffer;
    CXPLAT_EVENT* CompletionEvent {nullptr};
    QUIC_ADDR LocalAddresses[RPS_MAX_CLIENT_PORT_COUNT];
    uint32_t ActiveConnections {0};
    CxPlatEvent AllConnected {true};
    uint64_t StartedRequests {0};
    uint64_t SendCompletedRequests {0};
    uint64_t CompletedRequests {0};
    uint64_t CachedCompletedRequests {0};
    UniquePtr<uint32_t[]> LatencyValues {nullptr};
    uint64_t MaxLatencyIndex {0};
    QuicPoolAllocator<StreamContext> StreamContextAllocator;
    RpsWorkerContext Workers[PERF_MAX_THREAD_COUNT];
    UniquePtr<RpsConnectionContext[]> Connections {nullptr};
    bool Running {true};
    bool AffinitizeWorkers {false};
};
