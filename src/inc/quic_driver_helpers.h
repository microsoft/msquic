/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains helpers for interacting with a kernel mode driver service.
--*/

#pragma once

#define QUIC_TEST_APIS 1
#include "quic_platform.h"
#include "quic_trace.h"

#ifdef _WIN32

//#define QUIC_DRIVER_FILE_NAME  QUIC_DRIVER_NAME ".sys"
//#define QUIC_IOCTL_PATH        "\\\\.\\\\" QUIC_DRIVER_NAME


class QuicDriverService {
    SC_HANDLE ScmHandle;
    SC_HANDLE ServiceHandle;
public:
    QuicDriverService() :
        ScmHandle(nullptr),
        ServiceHandle(nullptr) {
    }
    bool Initialize(
        _In_z_ const char* DriverName,
        _In_z_ const char* DependentFileNames
        ) {
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
                DriverName,
                SERVICE_ALL_ACCESS);
        if (ServiceHandle == nullptr) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                 GetLastError(),
                "OpenService failed");
            char DriverFilePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, DriverFilePath, MAX_PATH);
            char* PathEnd = strrchr(DriverFilePath, '\\');
            if (!PathEnd) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Failed to get currently executing module path");
                return false;
            }
            PathEnd++;
            size_t RemainingLength = sizeof(DriverFilePath) - (PathEnd - DriverFilePath);
            int PathResult =
                snprintf(
                    PathEnd,
                    RemainingLength,
                    "%s.sys",
                    DriverName);
            if (PathResult <= 0 || (size_t)PathResult > RemainingLength) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Failed to create driver on disk file path");
                return false;
            }
            if (GetFileAttributesA(DriverFilePath) == INVALID_FILE_ATTRIBUTES) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Failed to find driver on disk");
                return false;
            }
            ServiceHandle =
                CreateServiceA(
                    ScmHandle,
                    DriverName,
                    DriverName,
                    SC_MANAGER_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    DriverFilePath,
                    nullptr,
                    nullptr,
                    DependentFileNames,
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
    void Uninitialize() {
        if (ServiceHandle != nullptr) {
            CloseServiceHandle(ServiceHandle);
        }
        if (ScmHandle != nullptr) {
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

    VOID DoStopSvc()
    {
        SERVICE_STATUS_PROCESS ssp;
        DWORD dwStartTime = GetTickCount();
        DWORD dwBytesNeeded;
        DWORD dwTimeout = 30000; // 30-second time-out
        DWORD dwWaitTime;

        // Make sure the service is not already stopped.

        if ( !QueryServiceStatusEx(
                ServiceHandle,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp,
                sizeof(SERVICE_STATUS_PROCESS),
                &dwBytesNeeded ) )
        {
            printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
            return;
        }

        if ( ssp.dwCurrentState == SERVICE_STOPPED )
        {
            printf("Service is already stopped.\n");
            return;
        }

        // If a stop is pending, wait for it.

        while ( ssp.dwCurrentState == SERVICE_STOP_PENDING )
        {
            printf("Service stop pending...\n");

            // Do not wait longer than the wait hint. A good interval is
            // one-tenth of the wait hint but not less than 1 second
            // and not more than 10 seconds.

            dwWaitTime = ssp.dwWaitHint / 10;

            if( dwWaitTime < 1000 )
                dwWaitTime = 1000;
            else if ( dwWaitTime > 10000 )
                dwWaitTime = 10000;

            Sleep( dwWaitTime );

            if ( !QueryServiceStatusEx(
                    ServiceHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ssp,
                    sizeof(SERVICE_STATUS_PROCESS),
                    &dwBytesNeeded ) )
            {
                printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
                return;
            }

            if ( ssp.dwCurrentState == SERVICE_STOPPED )
            {
                printf("Service stopped successfully.\n");
                return;
            }

            if ( GetTickCount() - dwStartTime > dwTimeout )
            {
                printf("Service stop timed out.\n");
                return;
            }
        }

        // If the service is running, dependencies must be stopped first.

        StopDependentServices();

        // Send a stop code to the service.

        if ( !ControlService(
                ServiceHandle,
                SERVICE_CONTROL_STOP,
                (LPSERVICE_STATUS) &ssp ) )
        {
            printf( "ControlService failed (%d)\n", GetLastError() );
            return;
        }

        // Wait for the service to stop.

        while ( ssp.dwCurrentState != SERVICE_STOPPED )
        {
            Sleep( ssp.dwWaitHint );
            if ( !QueryServiceStatusEx(
                    ServiceHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ssp,
                    sizeof(SERVICE_STATUS_PROCESS),
                    &dwBytesNeeded ) )
            {
                printf( "QueryServiceStatusEx failed (%d)\n", GetLastError() );
                return;
            }

            if ( ssp.dwCurrentState == SERVICE_STOPPED )
                break;

            if ( GetTickCount() - dwStartTime > dwTimeout )
            {
                printf( "Wait timed out\n" );
                return;
            }
        }
        printf("Service stopped successfully\n");
    }

    BOOL StopDependentServices()
    {
        DWORD i;
        DWORD dwBytesNeeded;
        DWORD dwCount;

        LPENUM_SERVICE_STATUS   lpDependencies = NULL;
        ENUM_SERVICE_STATUS     ess;
        SC_HANDLE               hDepService;
        SERVICE_STATUS_PROCESS  ssp;

        DWORD dwStartTime = GetTickCount();
        DWORD dwTimeout = 30000; // 30-second time-out

        // Pass a zero-length buffer to get the required buffer size.
        if ( EnumDependentServices( ServiceHandle, SERVICE_ACTIVE,
            lpDependencies, 0, &dwBytesNeeded, &dwCount ) )
        {
            // If the Enum call succeeds, then there are no dependent
            // services, so do nothing.
            return TRUE;
        }
        else
        {
            if ( GetLastError() != ERROR_MORE_DATA )
                return FALSE; // Unexpected error

            // Allocate a buffer for the dependencies.
            lpDependencies = (LPENUM_SERVICE_STATUS) HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded );

            if ( !lpDependencies )
                return FALSE;

            __try {
                // Enumerate the dependencies.
                if ( !EnumDependentServices( ServiceHandle, SERVICE_ACTIVE,
                    lpDependencies, dwBytesNeeded, &dwBytesNeeded,
                    &dwCount ) )
                return FALSE;

                for ( i = 0; i < dwCount; i++ )
                {
                    ess = *(lpDependencies + i);
                    // Open the service.
                    hDepService = OpenService( ScmHandle,
                    ess.lpServiceName,
                    SERVICE_STOP | SERVICE_QUERY_STATUS );

                    if ( !hDepService )
                    return FALSE;

                    __try {
                        // Send a stop code.
                        if ( !ControlService( hDepService,
                                SERVICE_CONTROL_STOP,
                                (LPSERVICE_STATUS) &ssp ) )
                        return FALSE;

                        // Wait for the service to stop.
                        while ( ssp.dwCurrentState != SERVICE_STOPPED )
                        {
                            Sleep( ssp.dwWaitHint );
                            if ( !QueryServiceStatusEx(
                                    hDepService,
                                    SC_STATUS_PROCESS_INFO,
                                    (LPBYTE)&ssp,
                                    sizeof(SERVICE_STATUS_PROCESS),
                                    &dwBytesNeeded ) )
                            return FALSE;

                            if ( ssp.dwCurrentState == SERVICE_STOPPED )
                                break;

                            if ( GetTickCount() - dwStartTime > dwTimeout )
                                return FALSE;
                        }
                    }
                    __finally
                    {
                        // Always release the service handle.
                        CloseServiceHandle( hDepService );
                    }
                }
            }
            __finally
            {
                // Always free the enumeration buffer.
                HeapFree( GetProcessHeap(), 0, lpDependencies );
            }
        }
        return TRUE;
    }
};

class QuicDriverClient {
    HANDLE DeviceHandle;
public:
    QuicDriverClient() : DeviceHandle(INVALID_HANDLE_VALUE) { }
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams,
        _In_z_ const char* DriverName
        ) {
        uint32_t Error;
        char IoctlPath[MAX_PATH];
        int PathResult =
            snprintf(
                IoctlPath,
                sizeof(IoctlPath),
                "\\\\.\\\\%s",
                DriverName);
        if (PathResult < 0 || PathResult >= sizeof(IoctlPath)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERRROR, %s",
                "Creating Driver File Path failed");
            return false;
        }
        DeviceHandle =
            CreateFileA(
                IoctlPath,
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
    void Uninitialize() {
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
        if (Overlapped.hEvent == nullptr) {
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
            "[test] Sending Write IOCTL %u with %u bytes.",
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
                    "DeviceIoControl Write failed");
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
                "GetOverlappedResultEx Write failed");
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
        _In_ uint32_t OutBufferSize,
        _Out_opt_ uint32_t* OutBufferWritten,
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
            "[test] Sending Read IOCTL %u.",
            IoGetFunctionCodeFromCtlCode(IoControlCode));
        if (!DeviceIoControl(
                DeviceHandle,
                IoControlCode,
                nullptr, 0,
                OutBuffer, OutBufferSize,
                nullptr,
                &Overlapped)) {
            Error = GetLastError();
            if (Error != ERROR_IO_PENDING) {
                CloseHandle(Overlapped.hEvent);
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "DeviceIoControl Write failed");
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
                if (CancelIoEx(DeviceHandle, &Overlapped)) {
                    GetOverlappedResult(DeviceHandle, &Overlapped, &dwBytesReturned, true);
                }
            } else {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Error,
                    "GetOverlappedResultEx Read failed");
            }
        } else {
            Error = ERROR_SUCCESS;
            *OutBufferWritten = dwBytesReturned;
        }
        CloseHandle(Overlapped.hEvent);
        return Error == ERROR_SUCCESS;
    }
};

#else

class QuicDriverService {
public:
    bool Initialize(
        _In_z_ const char* DriverName,
        _In_z_ const char* DependentFileNames
        ) {
        UNREFERENCED_PARAMETER(DriverName);
        UNREFERENCED_PARAMETER(DependentFileNames);
        return false;
        }
    void Uninitialize() { }
    bool Start() { return false; }
};

class QuicDriverClient {
public:
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams,
        _In_z_ const char* DriverName
    ) {
        UNREFERENCED_PARAMETER(SecConfigParams);
        UNREFERENCED_PARAMETER(DriverName);
        return false;
    }
    void Uninitialize() { }
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_ void* InBuffer,
        _In_ uint32_t InBufferSize,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        UNREFERENCED_PARAMETER(IoControlCode);
        UNREFERENCED_PARAMETER(InBuffer);
        UNREFERENCED_PARAMETER(InBufferSize);
        UNREFERENCED_PARAMETER(TimeoutMs);
        return false;
    }
    bool
    Run(
        _In_ uint32_t IoControlCode,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, nullptr, 0, TimeoutMs);
    }
    template<class T>
    bool
    Run(
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
        _In_ uint32_t OutBufferSize,
        _Out_ uint32_t* OutBufferWritten,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        UNREFERENCED_PARAMETER(IoControlCode);
        UNREFERENCED_PARAMETER(OutBuffer);
        UNREFERENCED_PARAMETER(OutBufferSize);
        UNREFERENCED_PARAMETER(OutBufferWritten);
        UNREFERENCED_PARAMETER(TimeoutMs);
        return false;
    }
};

#endif
