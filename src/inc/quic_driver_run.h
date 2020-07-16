#pragma once

#include "quic_platform.h"

#define QUIC_RUN_SUCCESS 0
#define QUIC_RUN_MISSING_TEST_TYPE -1
#define QUIC_RUN_FAILED_QUIC_OPEN -2
#define QUIC_RUN_FAILED_TEST_INITIALIZE -3
#define QUIC_RUN_MISSING_NECESSARY_ARGUMENTS -4
#define QUIC_RUN_UNKNOWN_TEST_TYPE -5
#define QUIC_RUN_INVALID_MODE -6

extern int
QuicMain(int Argc, char** Argv, QUIC_EVENT StopEvent, QUIC_EVENT ReadyEvent);
