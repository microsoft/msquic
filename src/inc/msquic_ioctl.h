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
DWORD
MsQuicReadPerformanceCounters(
    _Out_writes_all_(NumberOfCounters) int64_t* Counters,
    _Inout_ uint32_t* NumberOfCounters
    )
{
    DWORD Status = ERROR_SUCCESS;
    DWORD ReadBytes;
    HANDLE DeviceHandle = INVALID_HANDLE_VALUE;

    const WCHAR* FileName;

#ifdef QUIC_PRIVATE_INTERFACE
    if (PrivateTestLibrary) {
        FileName = L"\\\\.\\\\msquicpriv";
    } else {
        FileName = L"\\\\.\\\\msquic";
    }
#else
    FileName = L"\\\\.\\\\msquic";
#endif

    DeviceHandle =
        CreateFileW(
            FileName,
            GENERIC_READ,
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
            IOCTL_QUIC_PERFORMANCE_COUNTERS,
            NULL,
            0,
            (uint8_t*)Counters,
            (*NumberOfCounters) * 8,
            &ReadBytes,
            NULL)) {
        Status = GetLastError();
        goto Exit;
    }

    *NumberOfCounters = (uint32_t)(ReadBytes / 8);
Exit:

    if (DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(DeviceHandle);
    }

    return Status;
}

#endif // _KERNEL_MODE
