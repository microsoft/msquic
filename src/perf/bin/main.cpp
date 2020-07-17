#ifdef QUIC_CLOG
#include "main.cpp.clog.h"
#endif

#define QUIC_TEST_APIS 1
#include "quic_driver_run.h"
#include "PerfHelpers.h"

#ifdef _WIN32
#include <winioctl.h>
#endif

//
// Name of the driver service for msquictest.sys.
//
#define QUIC_PERF_DRIVER_NAME   "quicperf"
#define QUIC_PERF_IOCTL_PATH    "\\\\.\\\\" QUIC_PERF_DRIVER_NAME

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

class QuicDriverService {
    SC_HANDLE ScmHandle{nullptr};
    SC_HANDLE ServiceHandle{nullptr};
public:
    QuicDriverService() = default;
    bool Initialize() {
        uint32_t Error;
        ScmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (ScmHandle == nullptr) {
            Error = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Error,
                "GetFullPathName failed");
            return false;
        }
    QueryService:
        ServiceHandle =
            OpenServiceA(
                ScmHandle,
                QUIC_PERF_DRIVER_NAME,
                SERVICE_ALL_ACCESS);
        if (ServiceHandle == nullptr) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                 GetLastError(),
                "OpenService failed");
            char DriverFilePath[MAX_PATH];
            Error =
                GetFullPathNameA(
                    "msquictest.sys",
                    sizeof(DriverFilePath),
                    DriverFilePath,
                    nullptr);
            if (Error == 0) {
                Error = GetLastError();
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "GetFullPathName failed");
                return false;
            }
            ServiceHandle =
                CreateServiceA(
                    ScmHandle,
                    QUIC_PERF_DRIVER_NAME,
                    QUIC_PERF_DRIVER_NAME,
                    SC_MANAGER_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    DriverFilePath,
                    nullptr,
                    nullptr,
                    "msquic\0",
                    nullptr,
                    nullptr);
            if (ServiceHandle == nullptr) {
                Error = GetLastError();
                if (Error == ERROR_SERVICE_EXISTS) {
                    goto QueryService;
                }
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "CreateService failed");
                return false;
            }
        }
        return true;
    }
    ~QuicDriverService() {
        if (ServiceHandle) {
            CloseServiceHandle(ServiceHandle);
        }
        if (ScmHandle) {
            CloseServiceHandle(ScmHandle);
        }
    }
    bool Start() {
        if (!StartServiceA(ServiceHandle, 0, nullptr)) {
            uint32_t Error = GetLastError();
            if (Error != ERROR_SERVICE_ALREADY_RUNNING) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "StartService failed");
                return false;
            }
        }
        return true;
    }
};

#define QUIC_CTL_CODE(request, method, access) \
    CTL_CODE(FILE_DEVICE_NETWORK, request, method, access)

#define IoGetFunctionCodeFromCtlCode( ControlCode ) (\
    ( ControlCode >> 2) & 0x00000FFF )

#define IOCTL_QUIC_SEC_CONFIG \
    QUIC_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_PERF \
    QUIC_CTL_CODE(2, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_READ_DATA \
    QUIC_CTL_CODE(3, METHOD_BUFFERED, FILE_READ_DATA)

class QuicDriverClient {
    HANDLE DeviceHandle{INVALID_HANDLE_VALUE};
public:
    QuicDriverClient() = default;
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams
        ) {
        uint32_t Error;
        DeviceHandle =
            CreateFileA(
                QUIC_PERF_IOCTL_PATH,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,                // no SECURITY_ATTRIBUTES structure
                OPEN_EXISTING,          // No special create flags
                FILE_FLAG_OVERLAPPED,   // Allow asynchronous requests
                nullptr);
        if (DeviceHandle == INVALID_HANDLE_VALUE) {
            Error = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Error,
                "CreateFile failed");
            return false;
        }
        if (!Run(IOCTL_QUIC_SEC_CONFIG, SecConfigParams->Thumbprint, sizeof(SecConfigParams->Thumbprint), 30000)) {
            CloseHandle(DeviceHandle);
            DeviceHandle = INVALID_HANDLE_VALUE;
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Run(IOCTL_QUIC_SEC_CONFIG) failed");
            return false;
        }
        return true;
    }
    ~QuicDriverClient() {
        if (DeviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(DeviceHandle);
        }
    }
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_reads_bytes_opt_(InBufferSize)
            void* InBuffer,
        _In_ uint32_t InBufferSize,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        uint32_t Error;
        OVERLAPPED Overlapped = { 0 };
        Overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (!Overlapped.hEvent) {
            Error = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Error,
                "CreateEvent failed");
            return false;
        }
        QuicTraceLogVerbose(
            TestSendIoctl,
            "[test] Sending IOCTL %u with %u bytes.",
            IoGetFunctionCodeFromCtlCode(IoControlCode),
            InBufferSize);
        if (!DeviceIoControl(
                DeviceHandle,
                IoControlCode,
                InBuffer, InBufferSize,
                nullptr, 0,
                nullptr,
                &Overlapped)) {
            Error = GetLastError();
            if (Error != ERROR_IO_PENDING) {
                CloseHandle(Overlapped.hEvent);
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "DeviceIoControl failed");
                return false;
            }
        }
        DWORD dwBytesReturned;
        if (!GetOverlappedResultEx(
                DeviceHandle,
                &Overlapped,
                &dwBytesReturned,
                TimeoutMs,
                FALSE)) {
            Error = GetLastError();
            if (Error == WAIT_TIMEOUT) {
                Error = ERROR_TIMEOUT;
                CancelIoEx(DeviceHandle, &Overlapped);
            }
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Error,
                "GetOverlappedResultEx failed");
        } else {
            Error = ERROR_SUCCESS;
        }
        CloseHandle(Overlapped.hEvent);
        return Error == ERROR_SUCCESS;
    }
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, nullptr, 0, TimeoutMs);
    }
    template<class T>
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_ const T& Data,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, (void*)&Data, sizeof(Data), TimeoutMs);
    }

    bool Read(
        _In_ uint32_t IoControlCode,
        _Out_writes_bytes_opt_(OutBufferSize)
            void* OutBuffer,
        _In_ DWORD OutBufferSize,
        _Out_ LPDWORD OutBufferWritten,
        _In_ DWORD TimeoutMs = 30000
        ) {
        uint32_t Error;
        OVERLAPPED Overlapped = { 0 };
        Overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (!Overlapped.hEvent) {
            Error = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Error,
                "CreateEvent failed");
            return false;
        }
        QuicTraceLogVerbose(
            TestSendIoctl,
            "[test] Sending IOCTL %u.",
            IoGetFunctionCodeFromCtlCode(IoControlCode));
        if (!DeviceIoControl(
                DeviceHandle,
                IoControlCode,
                nullptr, 0,
                OutBuffer, OutBufferSize,
                OutBufferWritten,
                &Overlapped)) {
            Error = GetLastError();
            if (Error != ERROR_IO_PENDING) {
                CloseHandle(Overlapped.hEvent);
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "DeviceIoControl failed");
                return false;
            }
        }
        DWORD dwBytesReturned;
        if (!GetOverlappedResultEx(
                DeviceHandle,
                &Overlapped,
                &dwBytesReturned,
                TimeoutMs,
                FALSE)) {
            Error = GetLastError();
            if (Error == WAIT_TIMEOUT) {
                Error = ERROR_TIMEOUT;
                CancelIoEx(DeviceHandle, &Overlapped);
            } else {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "GetOverlappedResultEx failed");
            }
        } else {
            Error = ERROR_SUCCESS;
        }
        CloseHandle(Overlapped.hEvent);
        return Error == ERROR_SUCCESS;
    }
};

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
    QUIC_SEC_CONFIG_PARAMS* SelfSignedParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    if (SelfSignedParams) {
        static_assert(sizeof(SelfSignedSecurityHash) == sizeof(SelfSignedParams->Thumbprint));
        QuicCopyMemory(SelfSignedSecurityHash, SelfSignedParams->Thumbprint, 20);
        IsSelfSignedValid = true;
    }

    bool TestingKernelMode = false;
    bool KeyboardWait = false;

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
            TestingKernelMode = true;
        } else if (strcmp("--kbwait", argv[i]) == 0) {
            KeyboardWait = true;
        }
    }

    int RetVal = 0;

    if (TestingKernelMode) {
#ifdef _WIN32
        RetVal = QuicKernelMain(argc, argv, KeyboardWait, SelfSignedParams);
#else
        printf("Cannot run kernel mode tests on non windows platforms\n");
        RetVal = QUIC_RUN_INVALID_MODE
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
