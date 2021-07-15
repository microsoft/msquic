/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf HPS Client declaration. Defines the functions and
    variables used in the HpsClient class.

--*/


#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

struct HpsWorkerContext {
    class HpsClient* pThis {nullptr};
    UniquePtr<char[]> Target;
    QUIC_ADDR RemoteAddr;
    QUIC_ADDR LocalAddrs[HPS_BINDINGS_PER_WORKER];
    uint16_t Processor {0};
    long OutstandingConnections {0};
    uint32_t NextLocalAddr {0};
    CXPLAT_EVENT WakeEvent;
    CXPLAT_THREAD Thread;
    bool RemoteAddrSet {false};
    bool ThreadStarted {false};
    HpsWorkerContext() {
        CxPlatZeroMemory(&RemoteAddr, sizeof(RemoteAddr));
        CxPlatZeroMemory(&LocalAddrs, sizeof(LocalAddrs));
        CxPlatEventInitialize(&WakeEvent, FALSE, TRUE);
    }
    ~HpsWorkerContext() {
        WaitForWorker();
        CxPlatEventUninitialize(WakeEvent);
    }
    void WaitForWorker() {
        if (ThreadStarted) {
            CxPlatEventSet(WakeEvent);
            CxPlatThreadWait(&Thread);
            CxPlatThreadDelete(&Thread);
            ThreadStarted = false;
        }
    }
};

class HpsClient : public PerfBase {
public:
    HpsClient() { }

    ~HpsClient() override {
        Shutdown = true;
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

    QUIC_STATUS
    ConnectionCallback(
        _In_ HpsWorkerContext* Context,
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    void StartConnection(HpsWorkerContext* Context);

    HpsWorkerContext Contexts[PERF_MAX_THREAD_COUNT];
    MsQuicRegistration Registration {
        "secnetperf-client-hps",
        QUIC_EXECUTION_PROFILE_LOW_LATENCY,
        false};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(PERF_ALPN),
        MsQuicSettings()
            .SetDisconnectTimeoutMs(PERF_DEFAULT_DISCONNECT_TIMEOUT)
            .SetIdleTimeoutMs(HPS_DEFAULT_IDLE_TIMEOUT),
        MsQuicCredentialConfig(
            QUIC_CREDENTIAL_FLAG_CLIENT |
            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)};
    uint32_t ActiveProcCount;
    uint16_t Port {PERF_DEFAULT_PORT};
    UniquePtr<char[]> Target;
    uint32_t RunTime {HPS_DEFAULT_RUN_TIME};
    uint32_t Parallel {HPS_DEFAULT_PARALLEL_COUNT};
    uint8_t IncrementTarget {FALSE};
    CXPLAT_EVENT* CompletionEvent {nullptr};
    uint64_t CreatedConnections {0};
    uint64_t StartedConnections {0};
    uint64_t CompletedConnections {0};
    bool Shutdown {false};
};
