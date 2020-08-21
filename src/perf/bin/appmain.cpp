/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution runner.

--*/

#include "PerfHelpers.h"

#ifdef QUIC_CLOG
#include "appmain.cpp.clog.h"
#endif

#ifdef _WIN32

#include <winioctl.h>
#include "PerfIoctls.h"
#include "quic_driver_helpers.h"

#define QUIC_DRIVER_NAME   "quicperf"

#endif



extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

QUIC_STATUS
QuicUserMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    ) {
    EventScope StopEvent {true};

    QUIC_STATUS Status;

    Status = QuicMainStart(argc, argv, &StopEvent.Handle, SelfSignedConfig);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    printf("Started!\n\n");
    fflush(stdout);

    if (KeyboardWait) {
        printf("Press enter to exit\n");
        getchar();
        QuicEventSet(StopEvent);
    }

    Status = QuicMainStop(0);

    return Status;
}

#ifdef _WIN32

QUIC_STATUS
QuicKernelMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool /*KeyboardWait*/,
    _In_ QUIC_SEC_CONFIG_PARAMS* SelfSignedParams
    ) {
    size_t TotalLength = sizeof(argc);

    //
    // Get total length
    //
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
            continue;
        }
        TotalLength += strlen(argv[i]) + 1;
    }

    if (TotalLength > UINT_MAX) {
        printf("Too many arguments to pass to the driver\n");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    char* Data = static_cast<char*>(QUIC_ALLOC_NONPAGED(TotalLength));
    if (!Data) {
        printf("Failed to allocate arguments to pass\n");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    char* DataCurrent = Data;

    QuicCopyMemory(DataCurrent, &argc, sizeof(argc));

    DataCurrent += sizeof(argc);

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
            continue;
        }
        size_t ArgLen = strlen(argv[i]);
        QuicCopyMemory(DataCurrent, argv[i], ArgLen);
        DataCurrent += ArgLen;
        DataCurrent[0] = '\0';
        ++DataCurrent;
    }
    QUIC_DBG_ASSERT(DataCurrent == (Data + TotalLength));

    constexpr uint32_t OutBufferSize = 1024 * 1000;
    char* OutBuffer = (char*)QUIC_ALLOC_NONPAGED(OutBufferSize); // 1 MB
    if (!OutBuffer) {
        printf("Failed to allocate space for output buffer\n");
        QUIC_FREE(Data);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QuicDriverService DriverService;
    QuicDriverClient DriverClient;

    if (!DriverService.Initialize(QUIC_DRIVER_NAME, "msquicpriv\0")) {
        printf("Failed to initialize driver service\n");
        QUIC_FREE(Data);
        return QUIC_STATUS_INVALID_STATE;
    }
    if (!DriverService.Start()) {
        printf("Starting Driver Service Failed\n");
        DriverService.Uninitialize();
        QUIC_FREE(Data);
        return QUIC_STATUS_INVALID_STATE;
    }

    if (!DriverClient.Initialize(SelfSignedParams, QUIC_DRIVER_NAME)) {
        printf("Intializing Driver Client Failed.\n");
        DriverService.Uninitialize();
        QUIC_FREE(Data);
        return QUIC_STATUS_INVALID_STATE;
    }

    printf("Right before run\n");
    uint32_t OutBufferWritten = 0;
    bool RunSuccess = false;
    if (!DriverClient.Run(IOCTL_QUIC_RUN_PERF, Data, (uint32_t)TotalLength, 30000)) {
        printf("Failed To Run\n");
        QUIC_FREE(Data);

        RunSuccess =
            DriverClient.Read(
                IOCTL_QUIC_READ_DATA,
                OutBuffer,
                OutBufferSize,
                &OutBufferWritten,
                10000);
        printf("OutBufferWritten %d\n", OutBufferWritten);
        if (RunSuccess) {
            printf("%s\n", OutBuffer);
        } else {
            printf("Failed to exit\n");
        }
        QUIC_FREE(OutBuffer);
        DriverClient.Uninitialize();
        DriverService.Uninitialize();
        return QUIC_STATUS_INVALID_STATE;
    }
    printf("Started!\n\n");
    fflush(stdout);

    RunSuccess =
        DriverClient.Read(
            IOCTL_QUIC_READ_DATA,
            OutBuffer,
            OutBufferSize,
            &OutBufferWritten,
            240000);
    if (RunSuccess) {
        printf("%s\n", OutBuffer);
    } else {
        printf("Run end failed\n");
    }

    QUIC_FREE(Data);
    QUIC_FREE(OutBuffer);

    DriverClient.Uninitialize();
    DriverService.Uninitialize();

    return RunSuccess ? QUIC_STATUS_SUCCESS : QUIC_STATUS_INTERNAL_ERROR;
}

#endif

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    QUIC_SEC_CONFIG_PARAMS* SelfSignedParams = nullptr;
    PerfSelfSignedConfiguration SelfSignedConfig;
    QUIC_STATUS RetVal = 0;
    bool TestingKernelMode = false;
    bool KeyboardWait = false;

    QuicPlatformSystemLoad();
    if (QUIC_FAILED(QuicPlatformInitialize())) {
        printf("Platform failed to initialize\n");
        goto Exit;
    }

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
#ifdef _WIN32
            TestingKernelMode = true;
#else
            printf("Cannot run kernel mode tests on non windows platforms\n");
            RetVal = QUIC_STATUS_NOT_SUPPORTED;
            goto Exit;
#endif
        } else if (strcmp("--kbwait", argv[i]) == 0) {
            KeyboardWait = true;
        }
    }

    SelfSignedParams =
        QuicPlatGetSelfSignedCert(
            TestingKernelMode ?
                QUIC_SELF_SIGN_CERT_MACHINE :
                QUIC_SELF_SIGN_CERT_USER);
    if (!SelfSignedParams) {
        printf("Creating self signed certificate failed\n");
        RetVal = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    SelfSignedConfig.SelfSignedParams = SelfSignedParams;

    if (TestingKernelMode) {
#ifdef _WIN32
        printf("Entering kernel mode main\n");
        RetVal = QuicKernelMain(argc, argv, KeyboardWait, SelfSignedParams);
#else
        QUIC_FRE_ASSERT(FALSE);
#endif
    } else {
        RetVal = QuicUserMain(argc, argv, KeyboardWait, &SelfSignedConfig);
    }

Exit:
    if (SelfSignedParams) {
        QuicPlatFreeSelfSignedCert(SelfSignedParams);
    }

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return RetVal;
}
