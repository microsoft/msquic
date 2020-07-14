#pragma once

#include "quic_platform.h"

#ifdef _KERNEL_MODE
// TODO Setup ioctl
#else
extern int
QuicMain(int Argc, char **Argv, QUIC_EVENT StopEvent);
#endif
