/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Throughput Client declaration. Defines the functions and
    variables used in the ThroughputClient class.

--*/


#pragma once

#include "PerfHelpers.h"
#include "PerfBase.h"
#include "PerfCommon.h"

class ThroughputClient : public PerfBase {
public:
    ThroughputClient() {
        QuicZeroMemory(&LocalIpAddr, sizeof(LocalIpAddr));
    }

    ~ThroughputClient() override {
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
        _In_ int Timeout
        ) override;

private:

    struct ConnectionData {
        ConnectionData(_In_ ThroughputClient* Client) : Client{Client} { }
        ThroughputClient* Client;
        ConnectionScope Connection;
        uint8_t Padding[16]; // Padding for Pools
    };

    struct StreamContext {
        StreamContext(
            _In_ ThroughputClient* Client,
            _In_ HQUIC Connection)
            : Client{Client}, Connection{Connection} { }
        ThroughputClient* Client;
        HQUIC Connection;
        StreamScope Stream;
        uint64_t IdealSendBuffer{PERF_DEFAULT_SEND_BUFFER_SIZE};
        uint64_t OutstandingBytes{0};
        uint64_t BytesSent{0};
        uint64_t BytesCompleted{0};
        uint64_t StartTime{0};
        uint64_t EndTime{0};
        QUIC_BUFFER LastBuffer;
    };

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event,
        _Inout_ ConnectionData* ConnectionData
        );

    QUIC_STATUS
    StreamCallback(
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event,
        _Inout_ StreamContext* StrmData
        );

    void
    SendData(
        _In_ StreamContext* Context
        );

    MsQuicRegistration Registration {true};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(PERF_ALPN),
        MsQuicSettings()
            .SetIdleTimeoutMs(TPUT_DEFAULT_IDLE_TIMEOUT),
        MsQuicCredentialConfig(
            QUIC_CREDENTIAL_FLAG_CLIENT |
            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)};
    QuicPoolAllocator<StreamContext> StreamContextAllocator;
    QuicPoolAllocator<ConnectionData> ConnectionDataAllocator;
    UniquePtr<char[]> TargetData;
    QUIC_EVENT* StopEvent {nullptr};
    QUIC_BUFFER* DataBuffer {nullptr};
    uint8_t UseSendBuffer {TRUE};
    uint8_t UseEncryption {TRUE};
    QUIC_ADDR LocalIpAddr;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_ADDRESS_FAMILY RemoteFamily {QUIC_ADDRESS_FAMILY_UNSPEC};
    uint64_t Length {0};
    uint32_t IoSize {0};
};
