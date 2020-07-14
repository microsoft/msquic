#ifdef QUIC_CLOG
#include "quicmain.cpp.clog.h"
#endif

#include "quic_driver_run.h"

#include "ThroughputServer.h"

const QUIC_API_TABLE* MsQuic;

int
QuicMain(int /*Argc*/, char ** /*Argv*/, QUIC_EVENT /*StopEvent*/) {
    if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
        return -1;
    }


    ThroughputServer server;

    printf("server %d\n", server.IsValid());

    MsQuicClose(MsQuic);

    return 0;
}
