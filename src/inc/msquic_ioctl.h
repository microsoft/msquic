/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for the msquic ioctl interface

Environment:

    Windows User mode and Kernel mode

--*/

#pragma once

#ifndef _WIN32
#error "This Header is only supported in Windows"
#endif

#include "msquic.h"

#ifndef _KERNEL_MODE
#include "winioctl.h"
#endif

#ifdef QUIC_PRIVATE_INTERFACE
#define MSQUIC_DEVICE_NAME L"msquicpriv"
#else
#define MSQUIC_DEVICE_NAME L"msquic"
#endif


//
// MsQuic.sys IOCTL interface
//

#ifdef CTL_CODE

#define IOCTL_QUIC_PERFORMANCE_COUNTERS \
    CTL_CODE(FILE_DEVICE_NETWORK, 1, METHOD_BUFFERED, FILE_READ_DATA)

#endif // CTL_CODE

#ifndef _KERNEL_MODE

inline
QUIC_STATUS
MsQuicReadPerformanceCounters(
    _Out_writes_all_(NumberOfCounters) int64_t* Counters,
    _Inout_ uint32_t* NumberOfCounters
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    SC_HANDLE ScmHandle = NULL;
    SC_HANDLE ServiceHandle = NULL;
    SERVICE_STATUS_PROCESS ServiceStatus;
    DWORD ReadBytes;
    HANDLE DeviceHandle = INVALID_HANDLE_VALUE;

    ScmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (ScmHandle == NULL) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }

    ServiceHandle =
        OpenServiceW(
            ScmHandle,
            MSQUIC_DEVICE_NAME,
            SERVICE_QUERY_STATUS);
    if (ServiceHandle == NULL) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }

    if (!QueryServiceStatusEx(
        ServiceHandle,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ServiceStatus,
        sizeof(ServiceStatus),
        &ReadBytes)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }

    if (ServiceStatus.dwCurrentState != SERVICE_RUNNING) {
        Status = HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE);
        goto Exit;
    }

    DeviceHandle =
        CreateFileW(
            L"\\\\.\\\\" MSQUIC_DEVICE_NAME,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

    if (DeviceHandle == INVALID_HANDLE_VALUE) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }

    if (!DeviceIoControl(
        DeviceHandle,
        IOCTL_QUIC_PERFORMANCE_COUNTERS,
        NULL,
        0,
        (uint8_t*)Counters,
        (*NumberOfCounters) * 8,
        &ReadBytes,
        NULL)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }

    *NumberOfCounters = (uint32_t)(ReadBytes / 8);

Exit:

    if (DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(DeviceHandle);
    }

    if (ServiceHandle != NULL) {
        CloseServiceHandle(ServiceHandle);
    }

    if (ScmHandle != NULL) {
        CloseServiceHandle(ScmHandle);
    }

    return Status;
}

#endif // _KERNEL_MODE
