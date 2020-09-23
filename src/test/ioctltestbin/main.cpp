/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1
#define QUIC_PRIVATE_INTERFACE

bool PrivateTestLibrary = false;

#include <quic_platform.h>
#include <MsQuicTests.h>
#include "quic_driver_helpers.h"
#include "msquic_ioctl.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

class QuicTestEnvironment : public ::testing::Environment {
public:
    QuicDriverService TestDriverService;
    QuicDriverService DriverService;
    const char* TestDriverName;
    void SetUp() override {
        QuicPlatformSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(QuicPlatformInitialize()));
        const char* DriverName;
        const char* DependentDriverNames;
        if (PrivateTestLibrary) {
            DriverName = "msquicpriv";
            TestDriverName = QUIC_DRIVER_NAME_PRIVATE;
            DependentDriverNames = "msquicpriv\0";
        } else {
            DriverName = "msquic";
            TestDriverName = QUIC_DRIVER_NAME;
            DependentDriverNames = "msquic\0";
        }
        ASSERT_TRUE(DriverService.Initialize(DriverName, ""));
        ASSERT_TRUE(TestDriverService.Initialize(TestDriverName, DependentDriverNames));

    }
    void TearDown() override {
        TestDriverService.Uninitialize();
        DriverService.Uninitialize();
        QuicPlatformUninitialize();
        QuicPlatformSystemUnload();
    }
};

static QuicTestEnvironment* QuicEnvironment;

static
DWORD
ManipulateLibrary(
        _In_ DWORD ControlCode
    ) {
    DWORD Status = ERROR_SUCCESS;
    DWORD ReadBytes;
    HANDLE DeviceHandle = INVALID_HANDLE_VALUE;

    const WCHAR* FileName;

    if (PrivateTestLibrary) {
        FileName = L"\\\\.\\\\msquictestprivIOCTL";
    } else {
        FileName = L"\\\\.\\\\msquictestIOCTL";
    }

    DeviceHandle =
        CreateFileW(
            FileName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (DeviceHandle == INVALID_HANDLE_VALUE) {
        Status = GetLastError();
        goto Exit;
    }

        if (!DeviceIoControl(
            DeviceHandle,
            ControlCode,
            NULL,
            0,
            NULL,
            0,
            &ReadBytes,
            NULL)) {
        Status = GetLastError();
        goto Exit;
    }
Exit:

    if (DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(DeviceHandle);
    }

    return Status;
}

static
DWORD
StartLibrary(
    ) {
    return ManipulateLibrary(IOCTL_QUIC_TEST_IOCTL_INTERFACE_INITIALIZE_LIBRARY);
}

static
DWORD
StopLibrary(
    ) {
    return ManipulateLibrary(IOCTL_QUIC_TEST_IOCTL_INTERFACE_UNINITIALIZE_LIBRARY);
}

TEST(IOCtlInterface, ServiceNotStartedCorrectBuffer) {
    QuicEnvironment->DriverService.DoStopSvc();
    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX;
    ASSERT_EQ(ERROR_FILE_NOT_FOUND, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
}

TEST(IOCtlInterface, ServiceNotStartedBufferTooSmall) {
    QuicEnvironment->DriverService.DoStopSvc();
    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX - 4];
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX - 4;
    ASSERT_EQ(ERROR_FILE_NOT_FOUND, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
}

TEST(IOCtlInterface, ServiceNotStartedBufferTooLarge) {
    QuicEnvironment->DriverService.DoStopSvc();
    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX + 4];
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX + 4;
    ASSERT_EQ(ERROR_FILE_NOT_FOUND, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
}

TEST(IOCtlInterface, LibraryNotInitializedCorrectBuffer) {
    QuicEnvironment->DriverService.Start();
    QuicEnvironment->TestDriverService.Start();

    ASSERT_EQ(ERROR_SUCCESS, StopLibrary());

    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
    for (uint32_t i = 0; i < QUIC_PERF_COUNTER_MAX; i++) {
        PerfCounters[i] = 0x42424242;
    }
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX;
    ASSERT_EQ(ERROR_SUCCESS, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
    ASSERT_EQ(QUIC_PERF_COUNTER_MAX, NumberOfCounters);
    for (uint32_t i = 0; i < NumberOfCounters; i++) {
        ASSERT_EQ(0, PerfCounters[i]);
    }
}

TEST(IOCtlInterface, LibraryNotInitializedBufferTooSmall) {
    QuicEnvironment->DriverService.Start();
    QuicEnvironment->TestDriverService.Start();

    ASSERT_EQ(ERROR_SUCCESS, StopLibrary());

    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX - 4];
    for (uint32_t i = 0; i < QUIC_PERF_COUNTER_MAX - 4; i++) {
        PerfCounters[i] = 0x42424242;
    }
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX - 4;
    ASSERT_EQ(ERROR_SUCCESS, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
    ASSERT_EQ(QUIC_PERF_COUNTER_MAX - 4, NumberOfCounters);
    for (uint32_t i = 0; i < NumberOfCounters; i++) {
        ASSERT_EQ(0, PerfCounters[i]);
    }
}

TEST(IOCtlInterface, LibraryNotInitializedBufferTooLarge) {
    QuicEnvironment->DriverService.Start();
    QuicEnvironment->TestDriverService.Start();

    ASSERT_EQ(ERROR_SUCCESS, StopLibrary());

    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX + 4];
    for (uint32_t i = 0; i < QUIC_PERF_COUNTER_MAX + 4; i++) {
        PerfCounters[i] = 0x42424242;
    }
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX + 4;
    ASSERT_EQ(ERROR_SUCCESS, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
    ASSERT_EQ(QUIC_PERF_COUNTER_MAX, NumberOfCounters);
    for (uint32_t i = 0; i < NumberOfCounters; i++) {
        ASSERT_EQ(0, PerfCounters[i]);
    }
    for (uint32_t i = NumberOfCounters; i < QUIC_PERF_COUNTER_MAX + 4; i++) {
        ASSERT_EQ(0x42424242, PerfCounters[i]);
    }
}

TEST(IOCtlInterface, LibraryInitializedCorrectBuffer) {
    QuicEnvironment->DriverService.Start();
    QuicEnvironment->TestDriverService.Start();

    ASSERT_EQ(ERROR_SUCCESS, StopLibrary());
    ASSERT_EQ(ERROR_SUCCESS, StartLibrary());

    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX;
    ASSERT_EQ(ERROR_SUCCESS, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
    ASSERT_EQ(QUIC_PERF_COUNTER_MAX, NumberOfCounters);
    // Nothing about the data can be assumed.
}

TEST(IOCtlInterface, LibraryInitializedBufferTooSmall) {
    QuicEnvironment->DriverService.Start();
    QuicEnvironment->TestDriverService.Start();

    ASSERT_EQ(ERROR_SUCCESS, StopLibrary());
    ASSERT_EQ(ERROR_SUCCESS, StartLibrary());

    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX - 4];
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX - 4;
    ASSERT_EQ(ERROR_SUCCESS, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
    ASSERT_EQ(QUIC_PERF_COUNTER_MAX - 4, NumberOfCounters);
    // Nothing about the data can be assumed.
}

TEST(IOCtlInterface, LibraryInitializedBufferTooLarge) {
    QuicEnvironment->DriverService.Start();
    QuicEnvironment->TestDriverService.Start();

    ASSERT_EQ(ERROR_SUCCESS, StopLibrary());
    ASSERT_EQ(ERROR_SUCCESS, StartLibrary());

    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX + 4];
    for (uint32_t i = 0; i < QUIC_PERF_COUNTER_MAX + 4; i++) {
        PerfCounters[i] = 0x42424242;
    }
    uint32_t NumberOfCounters = QUIC_PERF_COUNTER_MAX + 4;
    ASSERT_EQ(ERROR_SUCCESS, MsQuicReadPerformanceCounters(PerfCounters, &NumberOfCounters));
    ASSERT_EQ(QUIC_PERF_COUNTER_MAX, NumberOfCounters);
        for (uint32_t i = NumberOfCounters; i < QUIC_PERF_COUNTER_MAX + 4; i++) {
        ASSERT_EQ(0x42424242, PerfCounters[i]);
    }
}

int main(int argc, char** argv) {
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--privateLibrary", argv[i]) == 0) {
            PrivateTestLibrary = true;
        }
    }
    QuicEnvironment = new QuicTestEnvironment;
    ::testing::AddGlobalTestEnvironment(QuicEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
