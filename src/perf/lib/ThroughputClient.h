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
        CxPlatZeroMemory(&LocalIpAddr, sizeof(LocalIpAddr));
    }

    ~ThroughputClient() override {
        if (DataBuffer) {
            CXPLAT_FREE(DataBuffer, QUIC_POOL_PERF);
        }
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

private:

    struct ConnectionData {
        ConnectionData(_In_ ThroughputClient* Client) : Client{Client} { }
        ThroughputClient* Client;
        ConnectionScope Connection;
#if DEBUG
        uint8_t Padding[16]; // Padding for Pools
#endif
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
        bool Complete{0};
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
    CXPLAT_EVENT* StopEvent {nullptr};
    QUIC_BUFFER* DataBuffer {nullptr};
    uint8_t UseSendBuffer {TRUE};
    uint8_t UsePacing {TRUE};
    uint8_t UseEncryption {TRUE};
    uint8_t TimedTransfer {FALSE};
    QUIC_ADDR LocalIpAddr;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_ADDRESS_FAMILY RemoteFamily {QUIC_ADDRESS_FAMILY_UNSPEC};
    uint64_t UploadLength {0};
    uint64_t DownloadLength {0};
    uint32_t IoSize {0};
};
