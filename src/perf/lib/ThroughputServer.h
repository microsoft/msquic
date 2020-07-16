#pragma once

#include "PerfHelpers.h"
#include "ThroughputCommon.h"

class ThroughputServer : public TestRunner {
public:
    bool IsValid() const override { return ConstructionSuccess; }

    ThroughputServer(int argc, char** argv);

    QUIC_STATUS Init() override;
    QUIC_STATUS Run(QUIC_EVENT StopEvent, QUIC_EVENT ReadyEvent) override;

private:

    struct ConnectionData {
        ThroughputServer* Server;
    };
    struct StreamData {
        ThroughputServer* Server;
    };

    QUIC_STATUS ListenerCallback(HQUIC ListenerHandle, QUIC_LISTENER_EVENT* Event);
    QUIC_STATUS ConnectionCallback(HQUIC ConnectionHandle, QUIC_CONNECTION_EVENT* Event, ConnectionData* Connection);
    QUIC_STATUS StreamCallback(HQUIC StreamHandle, QUIC_STREAM_EVENT* Event, StreamData* Stream);

    MsQuicRegistration Registration;
    MsQuicSession Session{Registration, THROUGHPUT_ALPN};
    MsQuicListener Listener{Session};
    MsQuicSecurityConfig SecurityConfig;
    QUIC_ADDR Address{};
    uint32_t NumberOfConnections {0};
    bool ConstructionSuccess {false};

};
