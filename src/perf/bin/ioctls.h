#pragma once

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
