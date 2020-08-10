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

//
// Name of the driver service for quicperf.sys.
// Must be defined before quic_driver_helpers.h is included
//
#define QUIC_DRIVER_NAME   "quicperf"

#include <winioctl.h>
#include "PerfIoctls.h"
#include "quic_driver_helpers.h"

#endif

#include "quic_datapath.h"

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

QUIC_DATAPATH_RECEIVE_CALLBACK DatapathReceiveUserMode;
QUIC_DATAPATH_UNREACHABLE_CALLBACK DatapathUnreachable;

QUIC_STATUS
QuicUserMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    ) {
    EventScope StopEvent {true};

    uint8_t ServerMode = 0;
    TryGetValue(argc, argv, "ServerMode", &ServerMode);

    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_DATAPATH_BINDING* Binding = nullptr;

    if (ServerMode) {
        Status = QuicDataPathInitialize(0, DatapathReceiveUserMode, DatapathUnreachable, &Datapath);
        if (QUIC_FAILED(Status)) {
            return Status;
        }

        QuicAddr LocalAddress {AF_INET, (uint16_t)9999};
        Status = QuicDataPathBindingCreate(Datapath, &LocalAddress.SockAddr, nullptr, &StopEvent.Handle, &Binding);
        if (QUIC_FAILED(Status)) {
            QuicDataPathUninitialize(Datapath);
            return Status;
        }
    }

    Status = QuicMainStart(argc, argv, &StopEvent.Handle, SelfSignedConfig);
    if (QUIC_FAILED(Status)) {
        if (ServerMode) {
            QuicDataPathBindingDelete(Binding);
            QuicDataPathUninitialize(Datapath);
        }
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

    if (ServerMode) {
        QuicDataPathBindingDelete(Binding);
        QuicDataPathUninitialize(Datapath);
    }

    return Status;
}

#ifdef _WIN32

QUIC_STATUS
QuicKernelMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait,
    _In_ QUIC_SEC_CONFIG_PARAMS* SelfSignedParams
    ) {
    size_t TotalLength = sizeof(argc);

    //
    // Get total length
    //
    for (int i = 0; i < argc; ++i) {
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

    QuicCopyMemory(DataCurrent, &argc, sizeof(TotalLength));

    DataCurrent += sizeof(argc);

    for (int i = 0; i < argc; ++i) {
        size_t ArgLen = strlen(argv[i]) + 1;
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
    if (!DriverService.Initialize()) {
        printf("Failed to initialize driver service\n");
        QUIC_FREE(Data);
        return QUIC_STATUS_INVALID_STATE;
    }
    DriverService.Start();

    if (!DriverClient.Initialize(SelfSignedParams)) {
        printf("Failed to initialize driver client\n");
        QUIC_FREE(Data);
        return QUIC_STATUS_INVALID_STATE;
    }

    if (!DriverClient.Run(IOCTL_QUIC_RUN_PERF, Data, (uint32_t)TotalLength)) {
        QUIC_FREE(Data);
        QUIC_FREE(OutBuffer);
        return QUIC_STATUS_INVALID_STATE;
    }
    printf("Started!\n\n");
    fflush(stdout);

    uint32_t OutBufferWritten = 0;
    bool RunSuccess =
        DriverClient.Read(
            IOCTL_QUIC_READ_DATA,
            OutBuffer,
            OutBufferSize,
            &OutBufferWritten);
    if (RunSuccess) {
        printf("%s", OutBuffer);
    }

    QUIC_FREE(Data);
    QUIC_FREE(OutBuffer);

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

void
DatapathReceiveUserMode(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{
    QUIC_EVENT* Event = static_cast<QUIC_EVENT*>(Context);
    QuicEventSet(*Event);
}

void
DatapathUnreachable(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    //
    // Do nothing, we never send
    //
}
