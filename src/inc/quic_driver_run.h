#pragma once

#include "quic_platform.h"

#define QUIC_RUN_SUCCESS 0
#define QUIC_RUN_MISSING_TEST_TYPE -1
#define QUIC_RUN_FAILED_QUIC_OPEN -2
#define QUIC_RUN_FAILED_TEST_INITIALIZE -3
#define QUIC_RUN_MISSING_NECESSARY_ARGUMENTS -4
#define QUIC_RUN_UNKNOWN_TEST_TYPE -5
#define QUIC_RUN_INVALID_MODE -6
#define QUIC_RUN_STOP_FAILURE -7

extern
int
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT StopEvent
    );

extern
int
QuicMainStop(
    _In_ int Timeout
    );

#define QUIC_PERF_MAX_IOCTL_FUNC_CODE 0

