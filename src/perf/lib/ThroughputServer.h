/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Throughput Server declaration. Definites the functions and
    variables used in the ThroughputServer class.

--*/

#pragma once

#include "PerfHelpers.h"
#include "ThroughputCommon.h"

class ThroughputServer : public PerfRunner {
public:
    ThroughputServer();

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

    struct ConnectionData {
        ThroughputServer* Server;
    };
    struct StreamData {
        ThroughputServer* Server;
    };

    QUIC_STATUS
    ListenerCallback(
        _In_ HQUIC ListenerHandle,
        _Inout_ QUIC_LISTENER_EVENT* Event
        );

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event,
        _Inout_ ConnectionData* Connection
        );

    QUIC_STATUS
    StreamCallback(
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event,
        _Inout_ StreamData* Stream
        );

    MsQuicRegistration Registration;
    MsQuicSession Session{Registration, THROUGHPUT_ALPN};
    MsQuicListener Listener{Session};
    MsQuicSecurityConfig SecurityConfig;
    QUIC_ADDR Address{};
    uint32_t NumberOfConnections {0};
    CountHelper RefCount;
};
