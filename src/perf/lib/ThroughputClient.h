#pragma once

#include "PerfHelpers.h"
#include "ThroughputCommon.h"

class ThroughputClient : public PerfRunner {
public:
    ThroughputClient();

    QUIC_STATUS Init(int argc, char** argv) override;
    QUIC_STATUS Start(QUIC_EVENT StopEvent) override;
    QUIC_STATUS Wait(int Timeout) override;

private:

    struct ConnectionData {
        ThroughputClient* Client{ nullptr };
        ConnectionScope Connection;
    };

    struct StreamData {
        ThroughputClient* Client{ nullptr };
        StreamScope Stream;
        uint64_t BytesSent{0};
    };

    QUIC_STATUS ConnectionCallback(HQUIC ConnectionHandle, QUIC_CONNECTION_EVENT* Event, ConnectionData* ConnectionData);
    QUIC_STATUS StreamCallback(HQUIC StreamHandle, QUIC_STREAM_EVENT* Event, StreamData* StrmData);

    MsQuicRegistration Registration;
    MsQuicSession Session{Registration, THROUGHPUT_ALPN};

    UniquePtr<char[]> TargetData;
    uint16_t Port{ 0 };
    QUIC_EVENT StopEvent{};
    uint64_t Length{0};
    bool ConstructionSuccess {false};
};
