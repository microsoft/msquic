/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution runner.

--*/

#include "PerfHelpers.h"
#include "LatencyHelpers.h"
#include "histogram/hdr_histogram.h"

#ifdef QUIC_CLOG
#include "appmain.cpp.clog.h"
#endif

#ifdef _WIN32

#include <winioctl.h>
#include "PerfIoctls.h"
#include "quic_driver_helpers.h"

#define QUIC_DRIVER_NAME            "quicperfdrv"
#define QUIC_DRIVER_NAME_PRIVATE    "quicperfdrvpriv"

#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

QUIC_STATUS
QuicHandleRpsClient(
    _In_reads_(Length) uint8_t* ExtraData,
    _In_ uint32_t Length,
    _In_opt_z_ const char* FileName)
{
    if (Length < sizeof(uint32_t) + sizeof(uint32_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    uint32_t RunTime;
    uint32_t CachedCompletedRequests;
    QuicCopyMemory(&RunTime, ExtraData, sizeof(RunTime));
    ExtraData += sizeof(RunTime);
    QuicCopyMemory(&CachedCompletedRequests, ExtraData, sizeof(CachedCompletedRequests));
    ExtraData += sizeof(CachedCompletedRequests);
    uint32_t RestOfBufferLength = Length - sizeof(RunTime) - sizeof(CachedCompletedRequests);
    RestOfBufferLength &= 0xFFFFFFFC; // Round down to nearest multiple of 4
    uint32_t MaxCount = min(CachedCompletedRequests, RestOfBufferLength);

    uint32_t RPS = (uint32_t)((CachedCompletedRequests * 1000ull) / (uint64_t)RunTime);
    if (RPS == 0) {
        printf("Error: No requests were completed\n");
        return QUIC_STATUS_SUCCESS;
    }

    uint32_t* Data = (uint32_t*)ExtraData;
    Statistics LatencyStats;
    Percentiles PercentileStats;
    GetStatistics(Data, MaxCount, &LatencyStats, &PercentileStats);
    WriteOutput(
        "Result: %u RPS, Min: %d, Max: %d, 50th: %f, 90th: %f, 99th: %f, 99.9th: %f, 99.99th: %f, 99.999th: %f, 99.9999th: %f, StdErr: %f\n",
        RPS,
        LatencyStats.Min,
        LatencyStats.Max,
        PercentileStats.P50,
        PercentileStats.P90,
        PercentileStats.P99,
        PercentileStats.P99p9,
        PercentileStats.P99p99,
        PercentileStats.P99p999,
        PercentileStats.P99p9999,
        LatencyStats.StandardError);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (FileName != nullptr) {
        FILE* FilePtr = nullptr;

#ifdef _WIN32
        errno_t FileErr = fopen_s(&FilePtr, FileName, "w");
#else
        FilePtr = fopen(FileName, "w");
        int FileErr = (FilePtr == nullptr) ? 1 : 0;
#endif
        if (FileErr == 0) {
            struct hdr_histogram* histogram = nullptr;
            int HstStatus = hdr_init(1, LatencyStats.Max, 3, &histogram);
            if (HstStatus == 0) {
                for (size_t i = 0; i < MaxCount; i++) {
                    hdr_record_value(histogram, Data[i]);
                }
                hdr_percentiles_print(histogram, FilePtr, 5, 1.0, CLASSIC);
            } else {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
            }
            fclose(FilePtr);
        } else {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        }
    }
    return Status;
}

QUIC_STATUS
QuicUserMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig,
    _In_opt_z_ const char* FileName
    ) {
    EventScope StopEvent {true};

    QUIC_STATUS Status;

    Status = QuicMainStart(argc, argv, &StopEvent.Handle, SelfSignedCredConfig);
    if (QUIC_FAILED(Status)) {
        QuicMainFree();
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
    if (QUIC_FAILED(Status)) {
        printf("Stop failed with status %d\n", Status);
        QuicMainFree();
        return Status;
    }

    PerfExtraDataMetadata Metadata;
    Status = QuicMainGetExtraDataMetadata(&Metadata);
    if (QUIC_FAILED(Status)) {
        printf("Get Extra Metadata failed with status %d\n", Status);
        QuicMainFree();
        return Status;
    }

    if (Metadata.TestType == PerfTestType::RpsClient) {
        UniquePtr<uint8_t[]> Buffer = UniquePtr<uint8_t[]>(new (std::nothrow) uint8_t[Metadata.ExtraDataLength]);
        if (Buffer.get() == nullptr) {
            QuicMainFree();
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        Status = QuicMainGetExtraData(Buffer.get(), &Metadata.ExtraDataLength);
        if (QUIC_FAILED(Status)) {
            printf("Get Extra Data failed with status %d\n", Status);
            QuicMainFree();
            return Status;
        }
        Status = QuicHandleRpsClient(Buffer.get(), Metadata.ExtraDataLength, FileName);
    }

    printf("App Main returning status %d\n", Status);
    QuicMainFree();
    return Status;
}

#ifdef _WIN32

QUIC_STATUS
QuicKernelMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool /*KeyboardWait*/,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedParams,
    _In_ bool PrivateTestLibrary,
    _In_opt_z_ const char* FileName
    )
{
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

    char* Data = static_cast<char*>(QUIC_ALLOC_NONPAGED(TotalLength, QUIC_POOL_PERF));
    if (!Data) {
        printf("Failed to allocate arguments to pass\n");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    char* DataCurrent = Data;

    QuicCopyMemory(DataCurrent, &argc, sizeof(argc));

    DataCurrent += sizeof(argc);

    for (int i = 0; i < argc; ++i) {
        size_t ArgLen = strlen(argv[i]);
        QuicCopyMemory(DataCurrent, argv[i], ArgLen);
        DataCurrent += ArgLen;
        DataCurrent[0] = '\0';
        ++DataCurrent;
    }
    QUIC_DBG_ASSERT(DataCurrent == (Data + TotalLength));

    constexpr uint32_t OutBufferSize = 1024 * 1000;
    char* OutBuffer = (char*)QUIC_ALLOC_NONPAGED(OutBufferSize, QUIC_POOL_PERF); // 1 MB
    if (!OutBuffer) {
        printf("Failed to allocate space for output buffer\n");
        QUIC_FREE(Data, QUIC_POOL_PERF);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QuicDriverService DriverService;
    QuicDriverClient DriverClient;

    const char* DriverName;
    const char* DependentDriverNames;
    if (PrivateTestLibrary) {
        DriverName = QUIC_DRIVER_NAME_PRIVATE;
        DependentDriverNames = "msquicpriv\0";
    } else {
        DriverName = QUIC_DRIVER_NAME;
        DependentDriverNames = "msquic\0";
    }

    if (!DriverService.Initialize(DriverName, DependentDriverNames)) {
        printf("Failed to initialize driver service\n");
        QUIC_FREE(Data, QUIC_POOL_PERF);
        return QUIC_STATUS_INVALID_STATE;
    }
    if (!DriverService.Start()) {
        printf("Starting Driver Service Failed\n");
        DriverService.Uninitialize();
        QUIC_FREE(Data, QUIC_POOL_PERF);
        return QUIC_STATUS_INVALID_STATE;
    }

    if (!DriverClient.Initialize((QUIC_CERTIFICATE_HASH*)(SelfSignedParams + 1), DriverName)) {
        printf("Intializing Driver Client Failed.\n");
        DriverService.Uninitialize();
        QUIC_FREE(Data, QUIC_POOL_PERF);
        return QUIC_STATUS_INVALID_STATE;
    }

    uint32_t OutBufferWritten = 0;
    bool RunSuccess = false;
    if (!DriverClient.Run(IOCTL_QUIC_RUN_PERF, Data, (uint32_t)TotalLength, 30000)) {
        printf("Failed To Run\n");
        QUIC_FREE(Data, QUIC_POOL_PERF);

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
        QUIC_FREE(OutBuffer, QUIC_POOL_PERF);
        DriverClient.Run(IOCTL_QUIC_FREE_PERF);
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

        PerfExtraDataMetadata Metadata;
        Metadata.TestType = PerfTestType::Server;
        RunSuccess =
            DriverClient.Read(
                IOCTL_QUIC_GET_METADATA,
                (void*)&Metadata,
                sizeof(Metadata),
                &OutBufferWritten,
                10000);
        if (RunSuccess && Metadata.TestType == PerfTestType::RpsClient) {
            UniquePtr<uint8_t[]> Buffer = UniquePtr<uint8_t[]>(new (std::nothrow) uint8_t[Metadata.ExtraDataLength]);
            if (Buffer.get() != nullptr) {
                RunSuccess =
                    DriverClient.Read(
                        IOCTL_QUIC_GET_EXTRA_DATA,
                        (void*)Buffer.get(),
                        Metadata.ExtraDataLength,
                        &Metadata.ExtraDataLength, 10000);
                if (RunSuccess) {
                    QUIC_STATUS Status =
                        QuicHandleRpsClient(Buffer.get(), Metadata.ExtraDataLength, FileName);
                    if (QUIC_FAILED(Status)) {
                        RunSuccess = false;
                        printf("Handle RPS Data Failed\n");
                    }
                } else {
                    printf("Failed to get extra data\n");
                }
            } else {
                printf("Out of memory\n");
                RunSuccess = false;
            }
        } else if (!RunSuccess) {
            printf("Failed to get metadata\n");
        }

    } else {
        printf("Run end failed\n");
    }

    QUIC_FREE(Data, QUIC_POOL_PERF);
    QUIC_FREE(OutBuffer, QUIC_POOL_PERF);
    DriverClient.Run(IOCTL_QUIC_FREE_PERF);

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
    const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig = nullptr;
    QUIC_STATUS RetVal = 0;
    bool TestingKernelMode = false;
    bool KeyboardWait = false;
    const char* FileName = nullptr;
    bool PrivateTestLibrary = false;

    UniquePtr<char*[]> ArgValues = UniquePtr<char*[]>(new char*[argc]);

    if (ArgValues.get() == nullptr) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    int ArgCount = 0;

    QuicPlatformSystemLoad();
    if (QUIC_FAILED(QuicPlatformInitialize())) {
        printf("Platform failed to initialize\n");
        goto Exit;
    }

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
#ifdef _WIN32
            TestingKernelMode = true;
            if (strcmp("--kernelPriv", argv[i]) == 0) {
                PrivateTestLibrary = true;
            }
#else
            printf("Cannot run kernel mode tests on non windows platforms\n");
            RetVal = QUIC_STATUS_NOT_SUPPORTED;
            goto Exit;
#endif
        } else if (strcmp("--kbwait", argv[i]) == 0) {
            KeyboardWait = true;
        } else if (strncmp("--extraOutputFile", argv[i], 17) == 0) {
            FileName = argv[i] + 18;
        } else {
            ArgValues[ArgCount] = argv[i];
            ArgCount++;
        }
    }

    SelfSignedCredConfig =
        QuicPlatGetSelfSignedCert(
            TestingKernelMode ?
                QUIC_SELF_SIGN_CERT_MACHINE :
                QUIC_SELF_SIGN_CERT_USER);
    if (!SelfSignedCredConfig) {
        printf("Creating self signed certificate failed\n");
        RetVal = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    if (TestingKernelMode) {
#ifdef _WIN32
        printf("Entering kernel mode main\n");
        RetVal = QuicKernelMain(ArgCount, ArgValues.get(), KeyboardWait, SelfSignedCredConfig, PrivateTestLibrary, FileName);
#else
        QUIC_FRE_ASSERT(FALSE);
#endif
    } else {
        RetVal = QuicUserMain(ArgCount, ArgValues.get(), KeyboardWait, SelfSignedCredConfig, FileName);
    }

Exit:
    if (SelfSignedCredConfig) {
        QuicPlatFreeSelfSignedCert(SelfSignedCredConfig);
    }

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return RetVal;
}
