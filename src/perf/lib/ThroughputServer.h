#pragma once

#include "PerfHelpers.h"
#include "ThroughputCommon.h"

class ThroughputServer : public TestRunner {
public:
    bool IsValid() const override { return ConstructionSuccess; }

    ThroughputServer(int argc, char** argv);

    QUIC_STATUS Init() override;
    QUIC_STATUS Run(QUIC_EVENT StopEvent, QUIC_EVENT ReadyEvent) override;

    QUIC_STATUS ListenerCallback(HQUIC ListenerHandle, QUIC_LISTENER_EVENT* Event);

private:
    MsQuicRegistration Registration;
    MsQuicSession Session{Registration, THROUGHPUT_ALPN};
    MsQuicListener Listener{Session};
    MsQuicSecurityConfig SecurityConfig;
    QUIC_ADDR Address;
    int NumberOfConnections {0};
    bool ConstructionSuccess {false};

};
