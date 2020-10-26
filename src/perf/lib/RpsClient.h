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

    void
    GetExtraDataMetadata(
        _Out_ PerfExtraDataMetadata* Result
        ) override;

    QUIC_STATUS
    GetExtraData(
        _Out_writes_bytes_(*Length) uint8_t* Data,
        _Inout_ uint8_t* Length
        ) override;

private:
    struct StreamContext {
        StreamContext(
            _In_ RpsClient* Client,
            _In_ uint64_t StartTime)
            : Client{Client}, StartTime{StartTime} { }
        RpsClient* Client;
        uint64_t StartTime;
#if DEBUG
        uint8_t Padding[12];
#endif
    };

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    QUIC_STATUS
    StreamCallback(
        _In_ StreamContext* StrmContext,
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    QUIC_STATUS
    SendRequest(
        _In_ HQUIC Handle
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
    uint16_t Port {PERF_DEFAULT_PORT};
    UniquePtr<char[]> Target;
    uint32_t RunTime {RPS_DEFAULT_RUN_TIME};
    uint32_t ConnectionCount {RPS_DEFAULT_CONNECTION_COUNT};
    uint32_t ParallelRequests {RPS_DEFAULT_PARALLEL_REQUEST_COUNT};
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
    UniquePtr<uint32_t[]> LatencyValues {nullptr};
    uint64_t MaxLatencyIndex {0};
    QuicPoolAllocator<StreamContext> StreamContextAllocator;
    UniquePtr<ConnectionScope[]> Connections {nullptr};
    bool Running {true};
};
