#include <clog.h>
#ifdef BUILDING_TRACEPOINT_PROVIDER
#define TRACEPOINT_CREATE_PROBES
#else
#define TRACEPOINT_DEFINE
#endif
#include "cert_capi.c.clog.h"
