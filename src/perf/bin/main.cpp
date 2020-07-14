#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

#include "quic_driver_run.h"

int
QUIC_MAIN_EXPORT
main(int argc, char** argv) {
    QUIC_EVENT StopEvent;
    QuicEventInitialize(&StopEvent, true, false);
    int RetVal = QuicMain(argc, argv, &StopEvent);
    QuicEventUninitialize(StopEvent);
    return RetVal;
}
