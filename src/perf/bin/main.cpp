#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

#define QUIC_TEST_APIS 1
#include "quic_driver_run.h"
#include "PerfHelpers.h"

#include <future>
#include <atomic>

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

int
QuicUserMain(int argc, char** argv) {
    QUIC_EVENT StopEvent, ReadyEvent;
    std::atomic_bool FinishedByExit {false};
    QuicEventInitialize(&StopEvent, true, false);
    QuicEventInitialize(&ReadyEvent, true, false);
    auto ReadyFuture = std::async(std::launch::async, [&]() {
        QuicEventWaitForever(ReadyEvent);
        if (!FinishedByExit.load()) {
            printf("Ready For Connections!\n\n");
            fflush(stdout);
        }
    });
    int RetVal = QuicMain(argc, argv, StopEvent, ReadyEvent);
    FinishedByExit.store(true);
    QuicEventSet(ReadyEvent);
    ReadyFuture.wait();
    QuicEventUninitialize(StopEvent);
    QuicEventUninitialize(ReadyEvent);
    return RetVal;
}

int QuicKernelMain(int argc, char** argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    return 0;
}

int
QUIC_MAIN_EXPORT
main(int argc, char** argv) {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    auto SelfSignedParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    if (SelfSignedParams) {
        static_assert(sizeof(SelfSignedSecurityHash) == sizeof(SelfSignedParams->Thumbprint));
        QuicCopyMemory(SelfSignedSecurityHash, SelfSignedParams->Thumbprint, 20);
        IsSelfSignedValid = true;
    }

    bool TestingKernelMode = false;

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
            TestingKernelMode = true;
            break;
        }
    }

    int RetVal = 0;

    if (TestingKernelMode) {
        RetVal = QuicKernelMain(argc, argv);
    } else {
        RetVal = QuicUserMain(argc, argv);
    }

    if (SelfSignedParams) {
        QuicPlatFreeSelfSignedCert(SelfSignedParams);
    }
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
    
    return RetVal;
}