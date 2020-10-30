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

struct RpsWorkerContext;

struct RpsConnectionContext {
    QUIC_LIST_ENTRY Link; // For Worker's connection queue
    RpsWorkerContext* Worker {nullptr};
    HQUIC Handle {nullptr};
    operator HQUIC() const { return Handle; }
    QUIC_STATUS
    StreamCallback(
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event
        );
    void SendRequest();
};

struct RpsWorkerContext {
    class RpsClient* Client {nullptr};
    QUIC_LOCK Lock;
    QUIC_LIST_ENTRY Connections;
    QUIC_THREAD Thread;
    QUIC_EVENT WakeEvent;
    bool ThreadStarted {false};
    uint32_t RequestCount {0};
    RpsWorkerContext() {
        QuicLockInitialize(&Lock);
        QuicEventInitialize(&WakeEvent, FALSE, FALSE);
        QuicListInitializeHead(&Connections);
    }
    ~RpsWorkerContext() {
        WaitForWorker();
        QuicEventUninitialize(WakeEvent);
        QuicLockUninitialize(&Lock);
    }
    void WaitForWorker() {
        if (ThreadStarted) {
            QuicEventSet(WakeEvent);
            QuicThreadWait(&Thread);
            QuicThreadDelete(&Thread);
            ThreadStarted = false;
        }
    }
    void Uninitialize() {
        QuicLockAcquire(&Lock);
        QuicListInitializeHead(&Connections);
        QuicLockRelease(&Lock);
    }
    RpsConnectionContext* GetConnection() {
        RpsConnectionContext* Connection = nullptr;
        QuicLockAcquire(&Lock);
        if (!QuicListIsEmpty(&Connections)) {
            Connection =
                QUIC_CONTAINING_RECORD(
                    QuicListRemoveHead(&Connections),
                    RpsConnectionContext,
                    Link);
            QuicListInsertTail(&Connections, &Connection->Link);
        }
        QuicLockRelease(&Lock);
        return Connection;
    }
    void QueueConnection(RpsConnectionContext* Connection) {
        Connection->Worker = this;
        QuicLockAcquire(&Lock);
        QuicListInsertTail(&Connections, &Connection->Link);
        QuicLockRelease(&Lock);
    }
    void QueueSendRequest() {
        if (ThreadStarted) {
            InterlockedIncrement((long*)&RequestCount);
            QuicEventSet(WakeEvent);
        } else {
            GetConnection()->SendRequest(); // Inline if thread isn't running
        }
    }
};

class RpsClient : public PerfBase {
public:

    RpsClient() {
        for (uint32_t i = 0; i < PERF_MAX_THREAD_COUNT; ++i) {
            Workers[i].Client = this;
        }
    }

    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) override;

    QUIC_STATUS
    Start(
        _In_ QUIC_EVENT* StopEvent
        ) override;

    QUIC_STATUS
    Wait(
        _In_ int Timeout
        ) override;

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    MsQuicRegistration Registration {true};
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
    UniquePtr<char[]> Target;
    uint32_t RunTime {RPS_DEFAULT_RUN_TIME};
    uint32_t ConnectionCount {RPS_DEFAULT_CONNECTION_COUNT};
    uint32_t RequestCount {RPS_DEFAULT_CONNECTION_COUNT * 2};
    uint32_t RequestLength {RPS_DEFAULT_REQUEST_LENGTH};
    uint32_t ResponseLength {RPS_DEFAULT_RESPONSE_LENGTH};

    struct QuicBufferScopeQuicAlloc {
        QUIC_BUFFER* Buffer;
        QuicBufferScopeQuicAlloc() noexcept : Buffer(nullptr) { }
        operator QUIC_BUFFER* () noexcept { return Buffer; }
        ~QuicBufferScopeQuicAlloc() noexcept { if (Buffer) { QUIC_FREE(Buffer); } }
    };

    QuicBufferScopeQuicAlloc RequestBuffer;
    QUIC_EVENT* CompletionEvent {nullptr};
    QUIC_ADDR LocalAddresses[RPS_MAX_CLIENT_PORT_COUNT];
    uint32_t ActiveConnections {0};
    EventScope AllConnected {true};
    uint64_t StartedRequests {0};
    uint64_t SendCompletedRequests {0};
    uint64_t CompletedRequests {0};
    RpsWorkerContext Workers[PERF_MAX_THREAD_COUNT];
    UniquePtr<RpsConnectionContext[]> Connections {nullptr};
    bool Running {true};
};
