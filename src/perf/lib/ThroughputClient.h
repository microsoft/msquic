#pragma once

#include "PerfHelpers.h"
#include "ThroughputCommon.h"

class ThroughputClient : public PerfRunner {
public:
    ThroughputClient();

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
        _In_ int Timeout
        ) override;

private:

    struct ConnectionData {
        ThroughputClient* Client{ nullptr };
        ConnectionScope Connection;
    };

    struct StreamData {
        ThroughputClient* Client{ nullptr };
        HQUIC Connection;
        StreamScope Stream;
        uint64_t BytesSent{0};
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
    MsQuicSession Session{Registration, THROUGHPUT_ALPN};
    UniquePtr<char[]> TargetData;
    uint16_t Port{ 0 };
    QUIC_EVENT StopEvent{};
    uint64_t Length{0};
    bool ConstructionSuccess {false};
};
