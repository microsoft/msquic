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

    bool DoStopSvc()
    {
        SERVICE_STATUS_PROCESS ServiceStatus;
        DWORD StartTime = GetTickCount();
        DWORD BytesNeeded;
        DWORD Timeout = 30000; // 30-second time-out
        DWORD WaitTime;

        //
        // Make sure the service is not already stopped.
        //

       if (!QueryServiceStatusEx(
                ServiceHandle,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ServiceStatus,
                sizeof(SERVICE_STATUS_PROCESS),
                &BytesNeeded)) {
            return false;
        }

        if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
            return true;
        }

        //
        // If a stop is pending, wait for it.
        //

        while (ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING)
        {
            //
            // Do not wait longer than the wait hint. A good interval is
            // one-tenth of the wait hint but not less than 1 second
            // and not more than 10 seconds.
            //

            WaitTime = ServiceStatus.dwWaitHint / 10;

            if(WaitTime < 1000) {
                WaitTime = 1000;
            } else if (WaitTime > 10000) {
                WaitTime = 10000;
            }

            Sleep(WaitTime);

            if (!QueryServiceStatusEx(
                    ServiceHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ServiceStatus,
                    sizeof(SERVICE_STATUS_PROCESS),
                    &BytesNeeded)) {
                return false;
            }

            if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
                return true;
            }

            if (GetTickCount() - StartTime > Timeout) {
                return false;
            }
        }

        //
        // If the service is running, dependencies must be stopped first.
        //

        StopDependentServices();

        //
        // Send a stop code to the service.
        //

        if (!ControlService(
                ServiceHandle,
                SERVICE_CONTROL_STOP,
                (LPSERVICE_STATUS) &ServiceStatus)) {
            return false;
        }

        //
        // Wait for the service to stop.
        //

        while (ServiceStatus.dwCurrentState != SERVICE_STOPPED)
        {
            Sleep(ServiceStatus.dwWaitHint);
            if (!QueryServiceStatusEx(
                    ServiceHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ServiceStatus,
                    sizeof(SERVICE_STATUS_PROCESS),
                    &BytesNeeded)) {
                return false;
            }

            if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
                break;
            }

            if (GetTickCount() - StartTime > Timeout) {
                return false;
            }
        }
        return true;
    }

    bool StopDependentServices()
    {
        DWORD i;
        DWORD BytesNeeded;
        DWORD Count;
        bool Status = true;

        LPENUM_SERVICE_STATUS   Dependencies = NULL;
        ENUM_SERVICE_STATUS     EnumServices;
        SC_HANDLE               DepService;
        SERVICE_STATUS_PROCESS  ServiceStatus;

        DWORD StartTime = GetTickCount();
        DWORD Timeout = 30000; // 30-second time-out

        //
        // Pass a zero-length buffer to get the required buffer size.
        //
        if (EnumDependentServices(
                ServiceHandle,
                SERVICE_ACTIVE,
                Dependencies,
                0,
                &BytesNeeded,
                &Count)) {
            //
            // If the Enum call succeeds, then there are no dependent
            // services, so do nothing.
            //
            Status = true;
            goto Exit;
        } else {
            if (GetLastError() != ERROR_MORE_DATA) {
                //
                // Unexpected error
                //
                Status = false;
                goto Exit;
            }

            //
            // Allocate a buffer for the dependencies.
            //
            Dependencies =
                (LPENUM_SERVICE_STATUS)HeapAlloc(
                    GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    BytesNeeded);

            if (!Dependencies) {
                Status = false;
                goto Exit;
            }

            // Enumerate the dependencies.
            if (!EnumDependentServices(
                    ServiceHandle,
                    SERVICE_ACTIVE,
                    Dependencies,
                    BytesNeeded,
                    &BytesNeeded,
                    &Count)) {
                Status = false;
                goto Exit;
            }

            for (i = 0; i < Count; i++)
            {
                EnumServices = *(Dependencies + i);
                //
                // Open the service.
                //
                DepService =
                    OpenService(
                        ScmHandle,
                        EnumServices.lpServiceName,
                        SERVICE_STOP | SERVICE_QUERY_STATUS);

                if (!DepService) {
                    Status = false;
                    goto Exit;
                }

                // Send a stop code.
                if (!ControlService(
                        DepService,
                        SERVICE_CONTROL_STOP,
                        (LPSERVICE_STATUS) &ServiceStatus)) {
                    CloseServiceHandle(DepService);
                    Status = false;
                    goto Exit;
                }

                // Wait for the service to stop.
                while (ServiceStatus.dwCurrentState != SERVICE_STOPPED) {
                    Sleep(ServiceStatus.dwWaitHint);
                    if (!QueryServiceStatusEx(
                            DepService,
                            SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&ServiceStatus,
                            sizeof(SERVICE_STATUS_PROCESS),
                            &BytesNeeded)) {
                        CloseServiceHandle(DepService);
                        Status = false;
                        goto Exit;
                    }

                    if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
                        break;
                    }

                    if (GetTickCount() - StartTime > Timeout) {
                        CloseServiceHandle(DepService);
                        Status = false;
                        goto Exit;
                    }
                }
                CloseServiceHandle(DepService);
            }
        }
    Exit:
        if (Dependencies != nullptr) {
            HeapFree(GetProcessHeap(), 0, Dependencies);
        }
        return Status;
    }
};

class QuicDriverClient {
    HANDLE DeviceHandle;
public:
    QuicDriverClient() : DeviceHandle(INVALID_HANDLE_VALUE) { }
    bool Initialize(
        _In_ QUIC_CERTIFICATE_HASH* CertHash,
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
        if (!Run(IOCTL_QUIC_SET_CERT_HASH, CertHash, sizeof(*CertHash), 30000)) {
            CloseHandle(DeviceHandle);
            DeviceHandle = INVALID_HANDLE_VALUE;
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Run(IOCTL_QUIC_SET_CERT_HASH) failed");
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
        _In_ QUIC_CERTIFICATE_HASH* CertHash,
        _In_z_ const char* DriverName
    ) {
        UNREFERENCED_PARAMETER(CertHash);
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
