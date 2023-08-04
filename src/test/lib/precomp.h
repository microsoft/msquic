/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Test code defaults to disabling certificate validation.
//
#define QUIC_DEFAULT_CLIENT_CRED_FLAGS \
    (QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)

#ifndef _KERNEL_MODE
#include <vector>
#endif

#include "TestAbstractionLayer.h"

#include "msquic.h"
#include "msquicp.h"
#include "quic_versions.h"
#include "quic_trace.h"
#include "quic_var_int.h"
#include "../core/quicdef.h"

#ifdef _KERNEL_MODE
#ifdef PAGEDX
#undef PAGEDX
#endif
#ifdef INITCODE
#undef INITCODE
#endif
#ifndef WIN_ASSERT
#define WIN_ASSERT CXPLAT_FRE_ASSERT
#endif
#include "karray.h"

#ifndef GLOBAL_FOR_KERNEL
#define GLOBAL_FOR_KERNEL
bool UseQTIP = false;
uint64_t LARGE_SEND_SIZE = 100000000llu;
// currently x is only CXPLAT_DATAPATH_FEATURE_RAW
#define QuitTestIsFeatureSupported(x) false
#endif
#endif

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestConnection.h"
#include "TestListener.h"
#include "DrillDescriptor.h"
