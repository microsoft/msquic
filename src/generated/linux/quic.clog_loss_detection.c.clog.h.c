#include <clog.h>
#ifdef BUILDING_TRACEPOINT_PROVIDER
#define TRACEPOINT_CREATE_PROBES
#else
#define TRACEPOINT_DEFINE
#endif
#include "loss_detection.c.clog.h"
