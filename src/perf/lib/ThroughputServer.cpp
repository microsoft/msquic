#ifdef QUIC_CLOG
#include "ThroughputServer.cpp.clog.h"
#endif

#include "ThroughputServer.h"
#include "msquichelper.h"
#include "ThroughputCommon.h"

ThroughputServer::ThroughputServer(int argc, char** argv) {
    if (!Listener.IsValid()) {
        return;
    }
    if (Session.IsValid()) {
        Session.SetAutoCleanup();
    }

    uint16_t port = THROUGHPUT_DEFAULT_PORT;
    TryGetValue(argc, argv, "port", &port);

    const char* localAddress = nullptr;
    TryGetValue(argc, argv, "listen", &localAddress);
    if (!ConvertArgToAddress(localAddress, port, &Address)) {
        WriteOutput("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", localAddress);
        return;
    }

    QUIC_STATUS Status = SecurityConfig.Initialize(argc, argv, Registration);

    if (QUIC_FAILED(Status)) {
        return;
    }

    ConstructionSuccess = true;
}

QUIC_STATUS ThroughputServer::Init() {
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::Run(QUIC_EVENT StopEvent, QUIC_EVENT ReadyEvent) {
    
    QUIC_STATUS Status = Listener.Start(&Address, Function{ &ThroughputServer::ListenerCallback, this });
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    if (NumberOfConnections > 0) {
        CountHelper RefCounter{StopEvent};
        for (int i = 0; i < NumberOfConnections; i++) {
            RefCounter.AddItem();
        }
        QuicEventSet(ReadyEvent);
        RefCounter.WaitForever();
    } else {
        QuicEventWaitForever(StopEvent);
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ThroughputServer::ListenerCallback(HQUIC ListenerHandle, QUIC_LISTENER_EVENT* Event) {
    UNREFERENCED_PARAMETER(ListenerHandle);
    UNREFERENCED_PARAMETER(Event);
    return QUIC_STATUS_SUCCESS;

}
