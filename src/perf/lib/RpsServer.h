/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf RPS Server declaration. Defines the functions and variables used
    in the RpsServer class.

--*/

#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

class RpsServer : public PerfBase {
public:
    RpsServer(
        _In_ PerfSelfSignedConfiguration* SelfSignedConfig
        );

    ~RpsServer() override;

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
        int Timeout
        ) override;

private:

    QUIC_STATUS
    ListenerCallback(
        _In_ HQUIC ListenerHandle,
        _Inout_ QUIC_LISTENER_EVENT* Event
        );

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

    MsQuicRegistration Registration;
    MsQuicSession Session {Registration, RPS_ALPN};
    MsQuicListener Listener {Session};
    PerfSelfSignedConfiguration* SelfSignedConfig;
    PerfSecurityConfig SecurityConfig;
    uint32_t Iterations {RPS_DEFAULT_ITERATIONS};
    uint16_t Port {RPS_DEFAULT_PORT};
    uint32_t ResponseLength {RPS_DEFAULT_RESPONSE_LENGTH};
    uint32_t ActiveConnectionCount {0};
    QUIC_BUFFER* ResponseBuffer {nullptr};
    QUIC_EVENT* CompletionEvent {nullptr};
};
