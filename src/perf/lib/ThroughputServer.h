#pragma once

#include "PerfHelpers.h"

class ThroughputServer {
 public:
    bool IsValid() const {
        return Listener.IsValid();
    }

    ThroughputServer();

    void Run(QUIC_EVENT StopEvent, QUIC_ADDR* Address, int NumberOfConnections);

    QUIC_STATUS ListenerCallback(HQUIC ListenerHandle, QUIC_LISTENER_EVENT* Event);

 private:
    MsQuicRegistration Registration;
    MsQuicSession Session{Registration, "Throughput"};
    MsQuicListener Listener{Session};
};
