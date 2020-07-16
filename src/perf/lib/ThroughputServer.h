#pragma once

#include "PerfHelpers.h"
#include "ThroughputCommon.h"

class ThroughputServer : public TestRunner {
public:
    ThroughputServer(int argc, char** argv);

    QUIC_STATUS Init() override;
    QUIC_STATUS Start(QUIC_EVENT StopEvent) override;
    QUIC_STATUS Stop(int Timeout) override;

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
    CountHelper RefCount;
};
