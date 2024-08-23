/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main execution runner.

--*/

#include "SecNetPerf.h"
#include "LatencyHelpers.h"
#include "histogram/hdr_histogram.h"

#ifdef _WIN32
#include <winioctl.h>
#include "PerfIoctls.h"
typedef struct {
    QUIC_CERTIFICATE_HASH ServerCertHash;
    QUIC_CERTIFICATE_HASH ClientCertHash;
} QUIC_RUN_CERTIFICATE_PARAMS;
#include "quic_driver_helpers.h"
#endif // _WIN32

void
QuicHandleExtraData(
    _In_reads_(Length) uint8_t* ExtraData,
    _In_ uint32_t Length,
    _In_opt_z_ const char* FileName
    )
{
    uint64_t RunTime;
    uint64_t CachedCompletedRequests;
    CXPLAT_FRE_ASSERT(Length >= sizeof(RunTime) + sizeof(CachedCompletedRequests));
    CxPlatCopyMemory(&RunTime, ExtraData, sizeof(RunTime));
    ExtraData += sizeof(RunTime);
    CxPlatCopyMemory(&CachedCompletedRequests, ExtraData, sizeof(CachedCompletedRequests));
    ExtraData += sizeof(CachedCompletedRequests);
    CXPLAT_FRE_ASSERT(CachedCompletedRequests <= UINT32_MAX);
    uint32_t RestOfBufferLength = Length - sizeof(RunTime) - sizeof(CachedCompletedRequests);
    RestOfBufferLength &= 0xFFFFFFFC; // Round down to nearest multiple of 4
    uint32_t MaxCount = CXPLAT_MIN((uint32_t)CachedCompletedRequests, RestOfBufferLength);

    uint32_t RPS = (uint32_t)((CachedCompletedRequests * 1000ull * 1000ull) / RunTime);
    if (RPS == 0) {
        printf("Error: No requests were completed\n");
        return;
    }

    Statistics LatencyStats;
    Percentiles PercentileStats;
    GetStatistics((uint32_t*)ExtraData, MaxCount, &LatencyStats, &PercentileStats);
    WriteOutput(
        "Result: %u RPS, Latency,us 0th: %d, 50th: %.0f, 90th: %.0f, 99th: %.0f, 99.9th: %.0f, 99.99th: %.0f, 99.999th: %.0f, 99.9999th: %.0f, Max: %d\n",
        RPS,
        LatencyStats.Min,
        PercentileStats.P50,
        PercentileStats.P90,
        PercentileStats.P99,
        PercentileStats.P99p9,
        PercentileStats.P99p99,
        PercentileStats.P99p999,
        PercentileStats.P99p9999,
        LatencyStats.Max);

    if (FileName != nullptr) {
#ifdef _WIN32
        FILE* FilePtr = nullptr;
        errno_t FileErr = fopen_s(&FilePtr, FileName, "w");
#else
        FILE* FilePtr = fopen(FileName, "w");
        int FileErr = (FilePtr == nullptr) ? 1 : 0;
#endif
        if (FileErr) {
            printf("Failed to open file '%s' for write, error: %d\n", FileName, FileErr);
            return;
        }
        struct hdr_histogram* histogram = nullptr;
        if (hdr_init(1, LatencyStats.Max, 3, &histogram)) {
            printf("Failed to create histogram\n");
        } else {
            for (size_t i = 0; i < MaxCount; i++) {
                hdr_record_value(histogram, ((uint32_t*)ExtraData)[i]);
            }
            hdr_percentiles_print(histogram, FilePtr, 5, 1.0, CLASSIC);
            hdr_close(histogram);
        }
        fclose(FilePtr);
    }
}

QUIC_STATUS
QuicUserMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_opt_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig,
    _In_opt_z_ const char* FileName
    ) {
    CxPlatEvent StopEvent {true};
    auto SimpleOutput = GetFlag(argc, argv, "trimout");
    auto AbortOnFailure = GetFlag(argc, argv, "abortOnFailure");
    QUIC_STATUS Status = QuicMainStart(argc, argv, &StopEvent.Handle, SelfSignedCredConfig);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    if (!SimpleOutput) {
        printf("Started!\n\n");
    }
    fflush(stdout);
    Status = QuicMainWaitForCompletion();
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    if (const uint32_t DataLength = QuicMainGetExtraDataLength(); DataLength) {
        auto Buffer = UniquePtr<uint8_t[]>(new (std::nothrow) uint8_t[DataLength]);
        CXPLAT_FRE_ASSERT(Buffer.get() != nullptr);
        QuicMainGetExtraData(Buffer.get(), DataLength);
        QuicHandleExtraData(Buffer.get(), DataLength, FileName);
    }

Exit:
    QuicMainFree();
    if (!SimpleOutput) {
        printf("App Main returning status %d\n", Status);
    }
    if (!QUIC_SUCCEEDED(Status) && AbortOnFailure) {
        CXPLAT_FRE_ASSERTMSG(FALSE, "AbortOnFailure: Non zero exit code detected. Abort to generate core dump.");
    }
    return Status;
}

#if defined(_WIN32) && !defined(QUIC_RESTRICTED_BUILD)

QUIC_STATUS
QuicKernelMain(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_opt_ const QUIC_CREDENTIAL_CONFIG* SelfSignedParams,
    _In_ bool PrivateTestLibrary,
    _In_z_ const char* DriverName,
    _In_opt_z_ const char* FileName
    )
{
    size_t TotalLength = sizeof(argc);
    for (int i = 0; i < argc; ++i) {
        TotalLength += strlen(argv[i]) + 1;
    }
    CXPLAT_FRE_ASSERT(TotalLength < UINT32_MAX);

    auto Data = UniquePtr<char[]>(new (std::nothrow) char[TotalLength]);
    CXPLAT_FRE_ASSERT(Data.get() != nullptr);

    char* DataCurrent = Data.get();
    CxPlatCopyMemory(DataCurrent, &argc, sizeof(argc));
    DataCurrent += sizeof(argc);

    for (int i = 0; i < argc; ++i) {
        const size_t ArgLen = strlen(argv[i]);
        CxPlatCopyMemory(DataCurrent, argv[i], ArgLen);
        DataCurrent += ArgLen;
        DataCurrent[0] = '\0';
        ++DataCurrent;
    }
    CXPLAT_FRE_ASSERT(DataCurrent == (Data.get() + TotalLength));

    constexpr uint32_t OutBufferSize = 1024 * 1000;
    auto OutBuffer = UniquePtr<char[]>(new (std::nothrow) char[OutBufferSize]); // 1 MB
    CXPLAT_FRE_ASSERT(OutBuffer.get() != nullptr);

    QuicDriverService MsQuicPrivDriverService;
    QuicDriverService DriverService;
    QuicDriverClient DriverClient;

    const char* DependentDriverNames;
    if (PrivateTestLibrary) {
        DependentDriverNames = "msquicpriv\0";
    } else {
        DependentDriverNames = "msquic\0";
    }

    if (PrivateTestLibrary) {
        if (!MsQuicPrivDriverService.Initialize("msquicpriv", "")) {
            printf("Failed to initialize msquicpriv driver service\n");
            return QUIC_STATUS_INVALID_STATE;
        }

        if (!MsQuicPrivDriverService.Start()) {
            printf("Starting msquicpriv Driver Service Failed\n");
            return QUIC_STATUS_INVALID_STATE;
        }
    }

    if (!DriverService.Initialize(DriverName, DependentDriverNames)) {
        printf("Failed to initialize driver service\n");
        return QUIC_STATUS_INVALID_STATE;
    }
    if (!DriverService.Start()) {
        printf("Starting Driver Service Failed\n");
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_RUN_CERTIFICATE_PARAMS CertParams = { 0 };
    if (SelfSignedParams) {
        CxPlatCopyMemory(
            &CertParams.ServerCertHash.ShaHash,
            (QUIC_CERTIFICATE_HASH*)(SelfSignedParams + 1),
            sizeof(QUIC_CERTIFICATE_HASH));
    }

    if (!DriverClient.Initialize(&CertParams, DriverName)) {
        printf("Intializing Driver Client Failed.\n");
        return QUIC_STATUS_INVALID_STATE;
    }

    uint32_t OutBufferWritten = 0;
    bool RunSuccess = false;
    if (!DriverClient.Run(IOCTL_QUIC_RUN_PERF, Data.get(), (uint32_t)TotalLength, 30000)) {
        printf("Failed To Run\n");

        RunSuccess =
            DriverClient.Read(
                IOCTL_QUIC_READ_DATA,
                OutBuffer.get(),
                OutBufferSize,
                &OutBufferWritten,
                10000);
        printf("OutBufferWritten %d\n", OutBufferWritten);
        if (RunSuccess) {
            printf("%s\n", OutBuffer.get());
        } else {
            printf("Failed to exit\n");
        }
        DriverClient.Run(IOCTL_CXPLAT_FREE_PERF);
        return QUIC_STATUS_INVALID_STATE;
    }
    printf("Started!\n\n");
    fflush(stdout);

    RunSuccess =
        DriverClient.Read(
            IOCTL_QUIC_READ_DATA,
            OutBuffer.get(),
            OutBufferSize,
            &OutBufferWritten,
            INFINITE);
    if (RunSuccess) {
        printf("%s\n", OutBuffer.get());

        uint32_t DataLength = 0;
        DriverClient.Read(
            IOCTL_QUIC_GET_EXTRA_DATA_LENGTH,
            (void*)&DataLength,
            sizeof(DataLength),
            &OutBufferWritten,
            10000);
        if (DataLength) {
            auto Buffer = UniquePtr<uint8_t[]>(new (std::nothrow) uint8_t[DataLength]);
            CXPLAT_FRE_ASSERT(Buffer.get() != nullptr);
            RunSuccess =
                DriverClient.Read(
                    IOCTL_QUIC_GET_EXTRA_DATA,
                    (void*)Buffer.get(),
                    DataLength,
                    &DataLength,
                    10000);
            if (RunSuccess) {
                QuicHandleExtraData(Buffer.get(), DataLength, FileName);
            }
        }
    } else {
        printf("Run end failed\n");
    }

    DriverClient.Run(IOCTL_CXPLAT_FREE_PERF);

    return RunSuccess ? QUIC_STATUS_SUCCESS : QUIC_STATUS_INTERNAL_ERROR;
}

#endif

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig = nullptr;
    uint8_t CipherSuite = 0;

    CxPlatSystemLoad();
    CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(CxPlatInitialize()));

    const char* DriverName = nullptr;
    bool PrivateTestLibrary = false;
     if (!TryGetValue(argc, argv, "driverName", &DriverName) &&
        TryGetValue(argc, argv, "driverNamePriv", &DriverName)) {
        PrivateTestLibrary = true;
    }

    const char* FileName = nullptr;
    TryGetValue(argc, argv, "extraOutputFile", &FileName);

    if (!TryGetTarget(argc, argv)) { // Only create certificate on server
        SelfSignedCredConfig =
            CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);
        if (!SelfSignedCredConfig) {
            printf("Creating self signed certificate failed\n");
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Exit;
        }
    }

    if (TryGetValue(argc, argv, "cipher", &CipherSuite)) {
        SelfSignedCredConfig->Flags |= QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
        SelfSignedCredConfig->AllowedCipherSuites = (QUIC_ALLOWED_CIPHER_SUITE_FLAGS)CipherSuite;
    }

    if (DriverName != nullptr) {
#if defined(_WIN32) && !defined(QUIC_RESTRICTED_BUILD)
        printf("Entering kernel mode main\n");
        Status = QuicKernelMain(argc, argv, SelfSignedCredConfig, PrivateTestLibrary, DriverName, FileName);
#else
        printf("Kernel mode main not supported on this platform\n");
        UNREFERENCED_PARAMETER(PrivateTestLibrary);
        Status = QUIC_STATUS_NOT_SUPPORTED;
#endif
    } else {
        Status = QuicUserMain(argc, argv, SelfSignedCredConfig, FileName);
    }

Exit:
    if (SelfSignedCredConfig) {
        CxPlatFreeSelfSignedCert(SelfSignedCredConfig);
    }

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return Status;
}
