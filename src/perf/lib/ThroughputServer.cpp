#ifdef QUIC_CLOG
#include "ThroughputServer.cpp.clog.h"
#endif

#include "ThroughputServer.h"

ThroughputServer::ThroughputServer() {
    if (Session.IsValid()) {
        Session.SetAutoCleanup();
    }
}

void ThroughputServer::Run(QUIC_EVENT StopEvent, QUIC_ADDR* Address, int NumberOfConnections) {
    Function f{ &ThroughputServer::ListenerCallback, this };
    Listener.Start(Address, f);
    if (NumberOfConnections > 0) {
        CountHelper RefCounter{StopEvent};
        for (int i = 0; i < NumberOfConnections; i++) {
            RefCounter.AddItem();
        }
        printf("Ready For Connections!\n\n");
        //
        // An explicit flush is needed in order to be detected in real time by the test runner
        //
        fflush(stdout);
        RefCounter.WaitForever();
    } else {
        QuicEventWaitForever(StopEvent);
    }
}

QUIC_STATUS ThroughputServer::ListenerCallback(HQUIC ListenerHandle, QUIC_LISTENER_EVENT* Event) {
    UNREFERENCED_PARAMETER(ListenerHandle);
    UNREFERENCED_PARAMETER(Event);
    return QUIC_STATUS_SUCCESS;

}
