/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Kernel Mode IOCTL definitions

--*/

#pragma once

#define QUIC_CTL_CODE(request, method, access) \
    CTL_CODE(FILE_DEVICE_NETWORK, request, method, access)

#define IoGetFunctionCodeFromCtlCode( ControlCode ) (\
    ( ControlCode >> 2) & 0x00000FFF )

#define IOCTL_QUIC_SET_CERT_HASH \
    QUIC_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_PERF \
    QUIC_CTL_CODE(2, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_READ_DATA \
    QUIC_CTL_CODE(3, METHOD_BUFFERED, FILE_READ_DATA)

#define QUIC_PERF_MAX_IOCTL_FUNC_CODE 3
