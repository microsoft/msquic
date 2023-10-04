/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#ifndef _PRECOMP_H_
#define _PRECOMP_H_

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
#endif

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestConnection.h"
#include "TestListener.h"
#include "DrillDescriptor.h"

#endif  //  _PRECOMP_H_