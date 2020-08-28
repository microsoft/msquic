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
#include "SendRequest.h"

class ThroughputClient : public PerfBase {
public:
    ThroughputClient();

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
        ConnectionData(
            _In_ ThroughputClient* Client)
            : Client{Client} {

        }
        ThroughputClient* Client{ nullptr };
        ConnectionScope Connection;
        uint8_t Padding[16]; // Padding for Pools
    };

    struct StreamData {
        StreamData(
            _In_ ThroughputClient* Client,
            _In_ HQUIC Connection)
            : Client{Client}, Connection{Connection} {

        }
        ThroughputClient* Client{ nullptr };
        HQUIC Connection;
        StreamScope Stream;
        uint64_t BytesSent{0};
        uint64_t BytesCompleted{0};
        uint64_t StartTime{0};
        uint64_t EndTime{0};
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
        _Inout_ StreamData* StrmData
        );

    MsQuicRegistration Registration;
    MsQuicSession Session{Registration, PERF_ALPN};
    QuicPoolAllocator<StreamData> StreamDataAllocator;
    QuicPoolAllocator<ConnectionData> ConnectionDataAllocator;
    QuicPoolAllocator<SendRequest> SendRequestAllocator;
    QuicPoolBufferAllocator BufferAllocator;
    UniquePtr<char[]> TargetData;
    uint16_t Port {PERF_DEFAULT_PORT};
    QUIC_EVENT* StopEvent {nullptr};
    uint64_t Length {0};
    // FIXME: unused: bool ConstructionSuccess {false};
    uint8_t UseSendBuffer {TRUE};
    QUIC_ADDR LocalIpAddr;
    uint16_t RemoteFamily {AF_UNSPEC};
    uint32_t IoSize {0};
    uint32_t IoCount {0};
    uint8_t UseEncryption {TRUE};
};
