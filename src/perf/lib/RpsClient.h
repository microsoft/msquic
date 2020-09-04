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

class RpsClient : public PerfBase {
public:
    RpsClient();

    ~RpsClient() override;

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

private:

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    QUIC_STATUS
    StreamCallback(
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    QUIC_STATUS
    SendRequest(
        _In_ HQUIC Handle
        );

    static
    const QUIC_SETTINGS*
    GetSettings()
    {
        static QUIC_SETTINGS Settings {0};
        Settings.DisconnectTimeoutMs = PERF_DEFAULT_DISCONNECT_TIMEOUT;
        Settings.IsSet.DisconnectTimeoutMs = TRUE;
        Settings.IdleTimeoutMs = PERF_DEFAULT_IDLE_TIMEOUT;
        Settings.IsSet.IdleTimeoutMs = TRUE;
        return &Settings;
    }

    MsQuicRegistration Registration;
    MsQuicSession Session {Registration, GetSettings(), PERF_ALPN, true};
    uint16_t Port {PERF_DEFAULT_PORT};
    UniquePtr<char[]> Target;
    uint32_t RunTime {RPS_DEFAULT_RUN_TIME};
    uint32_t ConnectionCount {RPS_DEFAULT_CONNECTION_COUNT};
    uint32_t ParallelRequests {RPS_DEFAULT_PARALLEL_REQUEST_COUNT};
    uint32_t RequestLength {RPS_DEFAULT_REQUEST_LENGTH};
    uint32_t ResponseLength {RPS_DEFAULT_RESPONSE_LENGTH};
    QUIC_BUFFER* RequestBuffer {nullptr};
    QUIC_EVENT* CompletionEvent {nullptr};
    QUIC_ADDR LocalAddresses[RPS_MAX_CLIENT_PORT_COUNT];
    uint32_t ActiveConnections {0};
    QUIC_EVENT AllConnected;
    uint64_t StartedRequests {0};
    uint64_t SendCompletedRequests {0};
    uint64_t CompletedRequests {0};
};
