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

#define QUIC_DRIVER_NAME   "quicperf"

#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

QUIC_STATUS
QuicHandleRpsClient(
    _In_reads_(Length) uint8_t* ExtraData,
    _In_ uint32_t Length)
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

    struct hdr_histogram* histogram;

    uint32_t* Data = (uint32_t*)ExtraData;

    uint32_t Min = 0xFFFFFFFF;
    uint32_t Max = 0;
    for (size_t i = 0; i < MaxCount; i++) {
        uint32_t Value = Data[i];
        if (Value > Max) {
            Max = Value;
        }
        if (Value < Min) {
            Min = Value;
        }
    }

    if (Min == 0) {
        Min++;
    }
    if (Max == UINT32_MAX) {
        Max--;
    }

    hdr_init(
        Min - 1,
        Max + 1,
        3,
        &histogram);

    for (size_t i = 0; i < MaxCount; i++) {
        hdr_record_value(histogram, Data[i]);
    }

    hdr_percentiles_print(
        histogram,
        stdout,
        5,
        1.0,
        CLASSIC);

    Statistics LatencyStats;
    Percentiles PercentileStats;
    GetStatistics(Data, MaxCount, &LatencyStats, &PercentileStats);
    WriteOutput(
        "Result: %u RPS, Min: %d, Max: %d, Mean: %f, Variance: %f, StdDev: %f, StdErr: %f, 50th: %f, 90th: %f, 99th: %f, 99.9th: %f, 99.99th: %f\n",
        RPS,
        LatencyStats.Min,
        LatencyStats.Max,
        LatencyStats.Mean,
        LatencyStats.Variance,
        LatencyStats.StandardDeviation,
        LatencyStats.StandardError,
        PercentileStats.FiftiethPercentile,
        PercentileStats.NinetiethPercentile,
        PercentileStats.NintyNinthPercentile,
        PercentileStats.NintyNinePointNinthPercentile,
        PercentileStats.NintyNinePointNineNinethPercentile);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicUserMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool KeyboardWait,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig
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
        QuicMainFree();
        return Status;
    }

    PerfExtraDataMetadata Metadata;
    Status = QuicMainGetExtraDataMetadata(&Metadata);
    if (QUIC_FAILED(Status)) {
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
            QuicMainFree();
            return Status;
        }
        Status = QuicHandleRpsClient(Buffer.get(), Metadata.ExtraDataLength);
    }

    QuicMainFree();

    return Status;
}

#ifdef _WIN32

QUIC_STATUS
QuicKernelMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ bool /*KeyboardWait*/,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedParams
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

    if (!DriverClient.Initialize((QUIC_CERTIFICATE_HASH*)(SelfSignedParams + 1), QUIC_DRIVER_NAME)) {
        printf("Intializing Driver Client Failed.\n");
        DriverService.Uninitialize();
        QUIC_FREE(Data);
        return QUIC_STATUS_INVALID_STATE;
    }

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
                        QuicHandleRpsClient(Buffer.get(), Metadata.ExtraDataLength);
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

    QUIC_FREE(Data);
    QUIC_FREE(OutBuffer);
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
        RetVal = QuicKernelMain(argc, argv, KeyboardWait, SelfSignedCredConfig);
#else
        QUIC_FRE_ASSERT(FALSE);
#endif
    } else {
        RetVal = QuicUserMain(argc, argv, KeyboardWait, SelfSignedCredConfig);
    }

Exit:
    if (SelfSignedCredConfig) {
        QuicPlatFreeSelfSignedCert(SelfSignedCredConfig);
    }

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return RetVal;
}
