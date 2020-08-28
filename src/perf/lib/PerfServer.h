/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Server declaration. Defines the functions and
    variables used in the PerfServer class.

--*/

#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

class PerfServer : public PerfBase {
public:
    PerfServer(
        _In_ PerfSelfSignedConfiguration* SelfSignedConfig
        );

    ~PerfServer() override;

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

    struct StreamContext {
        StreamContext(
            PerfServer* Server, bool Unidirectional) :
            Server{Server}, Unidirectional{Unidirectional} { }
        PerfServer* Server;
        bool Unidirectional;
        bool BufferedIo{false};
        bool ResponseSizeSet{false};
        uint64_t ResponseSize{0};
        uint64_t BytesSent{0};
        uint32_t OutstandingSends{0};
        uint32_t MaxOutstandingSends{PERF_DEFAULT_SEND_COUNT_NONBUFFERED};
        uint32_t IoSize{PERF_DEFAULT_IO_SIZE_NONBUFFERED};
        QUIC_BUFFER LastBuffer;
    };

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
        _In_ StreamContext* Context,
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    void
    SendResponse(
        _In_ StreamContext* Context,
        _In_ HQUIC StreamHandle
        );

    MsQuicRegistration Registration;
    MsQuicSession Session {Registration, PERF_ALPN};
    MsQuicListener Listener {Session};
    PerfSelfSignedConfiguration* SelfSignedConfig;
    PerfSecurityConfig SecurityConfig;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_EVENT* StopEvent {nullptr};
    QUIC_BUFFER* DataBufferBuffered {nullptr};
    QUIC_BUFFER* DataBufferNonBuffered {nullptr};
    QuicPoolAllocator<StreamContext> StreamContextAllocator;
};
