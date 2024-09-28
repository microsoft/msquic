/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Test code defaults to disabling certificate validation.
//
#define QUIC_DEFAULT_CLIENT_CRED_FLAGS \
    (QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)

#pragma warning(disable:4746)  // volatile access of '<expression>' is subject to /volatile:<iso|ms> setting;
                               // consider using __iso_volatile_load/store intrinsic functions

#ifndef _KERNEL_MODE
#include <vector>
#endif

#include "TestAbstractionLayer.h"

#include "msquic.h"
#include "msquicp.h"
#include "quic_versions.h"
#include "quic_trace.h"
#include "msquichelper.h"
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
#endif

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestConnection.h"
#include "TestListener.h"
#include "DrillDescriptor.h"

#if defined(_ARM64_) || defined(_ARM64EC_)
#pragma optimize("", off)
#endif
