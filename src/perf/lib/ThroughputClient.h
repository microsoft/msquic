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
    ThroughputClient() : Engine(nullptr, TcpConnectCallback, TcpReceiveCallback, TcpSendCompleteCallback) {
        CxPlatZeroMemory(&LocalIpAddr, sizeof(LocalIpAddr));
        CxPlatLockInitialize(&TcpLock);
    }

    ~ThroughputClient() override {
        if (DataBuffer) {
            CXPLAT_FREE(DataBuffer, QUIC_POOL_PERF);
        }
        CxPlatLockUninitialize(&TcpLock);
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

    struct StreamContext {
        StreamContext(_In_ ThroughputClient* Client) : Client{Client} { }
        ThroughputClient* Client;
        StreamScope Stream;
        uint64_t IdealSendBuffer{PERF_DEFAULT_SEND_BUFFER_SIZE};
        uint64_t OutstandingBytes{0};
        uint64_t BytesSent{0};
        uint64_t BytesCompleted{0};
        uint64_t StartTime{CxPlatTimeUs64()};
        uint64_t EndTime{0};
        QUIC_BUFFER LastBuffer;
        bool Complete{false};
        bool SendShutdown{false};
        bool RecvShutdown{false};
    };

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    QUIC_STATUS
    StreamCallback(
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event,
        _Inout_ StreamContext* StrmData
        );

    QUIC_STATUS StartQuic();

    void
    SendQuicData(
        _In_ StreamContext* Context
        );

    QUIC_STATUS StartTcp();

    void
    SendTcpData(
        _In_ TcpConnection* Connection,
        _In_ StreamContext* Context
        );

    void OnStreamShutdownComplete(_In_ StreamContext* Context);

    MsQuicRegistration Registration {
        "secnetperf-client-tput",
        QUIC_EXECUTION_PROFILE_LOW_LATENCY,
        true};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(PERF_ALPN),
        MsQuicSettings()
            .SetConnFlowControlWindow(PERF_DEFAULT_CONN_FLOW_CONTROL)
            .SetIdleTimeoutMs(TPUT_DEFAULT_IDLE_TIMEOUT),
        MsQuicCredentialConfig(
            QUIC_CREDENTIAL_FLAG_CLIENT |
            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)};
    QuicPoolAllocator<StreamContext> StreamContextAllocator;
    UniquePtr<char[]> TargetData;
    CXPLAT_EVENT* StopEvent {nullptr};
    QUIC_BUFFER* DataBuffer {nullptr};
    uint8_t UseTcp {FALSE};
    uint8_t UseSendBuffer {FALSE};
    uint8_t UsePacing {TRUE};
    uint8_t UseEncryption {TRUE};
    uint8_t TimedTransfer {FALSE};
    uint8_t PrintStats {FALSE};
    QUIC_ADDR LocalIpAddr;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_ADDRESS_FAMILY RemoteFamily {QUIC_ADDRESS_FAMILY_UNSPEC};
    uint64_t UploadLength {0};
    uint64_t DownloadLength {0};
    uint32_t IoSize {0};
    uint32_t CibirIdLength {0};
    uint8_t CibirId[7]; // {offset, values}

    TcpEngine Engine;
    CXPLAT_LOCK TcpLock;
    TcpConnection* TcpConn{nullptr};
    StreamContext* TcpStrmContext{nullptr};

    _IRQL_requires_max_(DISPATCH_LEVEL)
    void
    OnTcpConnectionComplete(
        );

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(TcpConnectCallback)
    static
    void
    TcpConnectCallback(
        _In_ TcpConnection* Connection,
        bool IsConnected
        );

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(TcpReceiveCallback)
    static
    void
    TcpReceiveCallback(
        _In_ TcpConnection* Connection,
        uint32_t StreamID,
        bool Open,
        bool Fin,
        bool Abort,
        uint32_t Length,
        uint8_t* Buffer
        );

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(TcpSendCompleteCallback)
    static
    void
    TcpSendCompleteCallback(
        _In_ TcpConnection* Connection,
        TcpSendData* SendDataChain
        );
};
