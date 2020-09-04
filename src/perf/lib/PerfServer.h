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
        ) : SelfSignedConfig{SelfSignedConfig} { }

    ~PerfServer() override {
        if (DataBuffer) {
            QUIC_FREE(DataBuffer);
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
        int Timeout
        ) override;

private:

    struct StreamContext {
        StreamContext(
            PerfServer* Server, bool Unidirectional, bool BufferedIo) :
            Server{Server}, Unidirectional{Unidirectional}, BufferedIo{BufferedIo} {
            if (BufferedIo) {
                IdealSendBuffer = 1; // Hack to get just do 1 send at a time.
            }
        }
        PerfServer* Server;
        bool Unidirectional;
        bool BufferedIo;
        bool ResponseSizeSet{false};
        uint64_t IdealSendBuffer{PERF_DEFAULT_SEND_BUFFER_SIZE};
        uint64_t ResponseSize{0};
        uint64_t BytesSent{0};
        uint64_t OutstandingBytes{0};
        uint32_t IoSize{PERF_DEFAULT_IO_SIZE};
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

    static
    const QUIC_SETTINGS*
    GetSettings()
    {
        static QUIC_SETTINGS Settings {0};
        Settings.BidiStreamCount = PERF_DEFAULT_STREAM_COUNT;
        Settings.IsSet.BidiStreamCount = TRUE;
        Settings.UnidiStreamCount = PERF_DEFAULT_STREAM_COUNT;
        Settings.IsSet.UnidiStreamCount = TRUE;
        Settings.DisconnectTimeoutMs = PERF_DEFAULT_DISCONNECT_TIMEOUT;
        Settings.IsSet.DisconnectTimeoutMs = TRUE;
        Settings.IdleTimeoutMs = PERF_DEFAULT_IDLE_TIMEOUT;
        Settings.IsSet.IdleTimeoutMs = TRUE;
        return &Settings;
    }

    MsQuicRegistration Registration;
    MsQuicSession Session {Registration, GetSettings(), PERF_ALPN, true};
    MsQuicListener Listener {Session};
    PerfSelfSignedConfiguration* SelfSignedConfig;
    PerfSecurityConfig SecurityConfig;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_EVENT* StopEvent {nullptr};
    QUIC_BUFFER* DataBuffer {nullptr};
    QuicPoolAllocator<StreamContext> StreamContextAllocator;
};
