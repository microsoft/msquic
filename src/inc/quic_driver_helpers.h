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

#define QUIC_DRIVER_FILE_NAME  QUIC_DRIVER_NAME ".sys"
#define QUIC_IOCTL_PATH        "\\\\.\\\\" QUIC_DRIVER_NAME

class QuicDriverService {
    SC_HANDLE ScmHandle;
    SC_HANDLE ServiceHandle;
public:
    QuicDriverService() :
        ScmHandle(nullptr),
        ServiceHandle(nullptr) {
    }
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
                QUIC_DRIVER_NAME,
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
            if (!PathEnd ||
                sizeof(DriverFilePath) - (PathEnd - DriverFilePath) < sizeof(QUIC_DRIVER_FILE_NAME)) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Can't build " QUIC_DRIVER_FILE_NAME " full path");
                return false;
            }
            memcpy(PathEnd + 1, QUIC_DRIVER_FILE_NAME, sizeof(QUIC_DRIVER_FILE_NAME));
            if (GetFileAttributesA(DriverFilePath) == INVALID_FILE_ATTRIBUTES) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Failed to find " QUIC_DRIVER_FILE_NAME);
                return false;
            }
            ServiceHandle =
                CreateServiceA(
                    ScmHandle,
                    QUIC_DRIVER_NAME,
                    QUIC_DRIVER_NAME,
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
};

class QuicDriverClient {
    HANDLE DeviceHandle;
public:
    QuicDriverClient() : DeviceHandle(INVALID_HANDLE_VALUE) { }
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams
        ) {
        uint32_t Error;
        DeviceHandle =
            CreateFileA(
                QUIC_IOCTL_PATH,
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
    bool Initialize() { return false; }
    void Uninitialize() { }
    bool Start() { return false; }
};

class QuicDriverClient {
public:
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams
    ) {
        UNREFERENCED_PARAMETER(SecConfigParams);
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
