/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Throughput Server declaration. Defines the functions and
    variables used in the ThroughputServer class.

--*/

#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

class ThroughputServer : public PerfBase {
public:
    ThroughputServer(
        _In_ PerfSelfSignedConfiguration* SelfSignedConfig
        );

    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) override;

    QUIC_STATUS
    Start(
        _In_ QUIC_EVENT StopEvent
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
    MsQuicSession Session {Registration, THROUGHPUT_ALPN};
    MsQuicListener Listener {Session};
    PerfSelfSignedConfiguration* SelfSignedConfig;
    PerfSecurityConfig SecurityConfig;
    QUIC_ADDR Address{};
    uint32_t NumberOfConnections {0};
    CountHelper RefCount;
};
