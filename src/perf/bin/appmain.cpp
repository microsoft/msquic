/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution runner.

--*/

#ifdef QUIC_CLOG
#include "appmain.cpp.clog.h"
#endif

#define QUIC_TEST_APIS 1
#include "quic_driver_main.h"
#include "PerfHelpers.h"
#include <quic_trace.h>

#ifdef _WIN32

//
// Name of the driver service for quicperf.sys.
// Must be defined before quic_driver_helpers.h is included
//
#define QUIC_DRIVER_NAME   "quicperf"

#include <winioctl.h>
#include "perfioctls.h"
#include "quic_driver_helpers.h"

#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

int
QuicUserMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait
    ) {
    QUIC_EVENT StopEvent;
    QuicEventInitialize(&StopEvent, true, false);

    int RetVal = QuicMainStart(argc, argv, StopEvent);
    if (RetVal != 0) {
        return RetVal;
    }
    printf("Ready For Connections!\n\n");
    fflush(stdout);
    if (KeyboardWait) {
        printf("Press enter to exit\n");
        getchar();
        QuicEventSet(StopEvent);
    }
    RetVal = QuicMainStop(0);
    QuicEventUninitialize(StopEvent);
    return RetVal;
}

#ifdef _WIN32

int
QuicKernelMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait,
    _In_ QUIC_SEC_CONFIG_PARAMS* SelfSignedParams
    ) {
    size_t TotalLength = 0;

    // Get total length
    for (int i = 0; i < argc; ++i) {
        //
        // Length of string, plus null terminator, plus length
        //
        TotalLength += strlen(argv[i]) + sizeof(size_t) + 1;
    }

    TotalLength += sizeof(TotalLength);

    char* Data = static_cast<char*>(QuicAlloc(TotalLength));
    if (!Data) {
        printf("Failed to allocate arguments to pass\n");
        return QUIC_RUN_FAILED_TEST_INITIALIZE;
    }

    char* DataCurrent = Data;

    QuicCopyMemory(DataCurrent, &TotalLength, sizeof(TotalLength));

    DataCurrent += sizeof(TotalLength);

    for (int i = 0; i < argc; ++i) {
        size_t ArgLen = strlen(argv[i]) + 1;
        QuicCopyMemory(DataCurrent, &ArgLen, sizeof(ArgLen));
        DataCurrent += sizeof(ArgLen);
        QuicCopyMemory(DataCurrent, argv[i], ArgLen);
        DataCurrent += ArgLen;
        DataCurrent[0] = '\0';
        ++DataCurrent;
    }

    QUIC_DBG_ASSERT(DataCurrent == (Data + TotalLength));
    QUIC_DBG_ASSERT(TotalLength <= UINT_MAX);

    constexpr DWORD OutBufferSize = 1024 * 1000;
    char* OutBuffer = (char*)QuicAlloc(OutBufferSize); // 1 MB
    if (!OutBuffer) {
        printf("Failed to allocate space for output buffer\n");
        QuicFree(Data);
        return QUIC_RUN_FAILED_TEST_INITIALIZE;
    }

    QuicDriverService DriverService;
    QuicDriverClient DriverClient;
    DriverService.Initialize();
    DriverService.Start();
    DriverClient.Initialize(SelfSignedParams);

    if (!DriverClient.Run(IOCTL_QUIC_RUN_PERF, Data, (uint32_t)TotalLength)) {
        QuicFree(Data);
        QuicFree(OutBuffer);
        return QUIC_RUN_FAILED_TEST_INITIALIZE;
    }
    printf("Ready For Connections!\n\n");
    fflush(stdout);

    DWORD OutBufferWritten = 0;
    bool RunSuccess =
        DriverClient.Read(
            IOCTL_QUIC_READ_DATA,
            OutBuffer,
            OutBufferSize,
            &OutBufferWritten);

    if (RunSuccess) {
        printf("%s", OutBuffer);
    }

    QuicFree(Data);
    QuicFree(OutBuffer);

    return RunSuccess ? QUIC_RUN_SUCCESS : QUIC_RUN_STOP_FAILURE;
}

#endif

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    bool TestingKernelMode = false;
    bool KeyboardWait = false;

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
            TestingKernelMode = true;
        } else if (strcmp("--kbwait", argv[i]) == 0) {
            KeyboardWait = true;
        }
    }

    QUIC_SEC_CONFIG_PARAMS* SelfSignedConfig =
        QuicPlatGetSelfSignedCert(
            TestingKernelMode ?
                QUIC_SELF_SIGN_CERT_MACHINE :
                QUIC_SELF_SIGN_CERT_USER);
    if (SelfSignedConfig) {
#ifdef _KERNEL_MODE
        static_assert(sizeof(SelfSignedSecurityHash) == sizeof(SelfSignedConfig->Thumbprint));
        QuicCopyMemory(SelfSignedSecurityHash, SelfSignedConfig->Thumbprint, 20);
#else
        SelfSignedParams = SelfSignedConfig;
#endif
        IsSelfSignedValid = true;
    }

    int RetVal = 0;
    if (TestingKernelMode) {
#ifdef _WIN32
        RetVal = QuicKernelMain(argc, argv, KeyboardWait, SelfSignedParams);
#else
        printf("Cannot run kernel mode tests on non windows platforms\n");
        RetVal = QUIC_RUN_INVALID_MODE;
#endif
    } else {
        RetVal = QuicUserMain(argc, argv, KeyboardWait);
    }

    if (SelfSignedParams) {
        QuicPlatFreeSelfSignedCert(SelfSignedParams);
    }
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return RetVal;
}
