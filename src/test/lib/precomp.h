/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#ifndef _KERNEL_MODE
#include <vector>
#endif

#include "TestAbstractionLayer.h"

#include <msquic.h>
#include <msquicp.h>
#include <quic_versions.h>

#ifdef _KERNEL_MODE
#ifdef PAGEDX
#undef PAGEDX
#endif
#ifdef INITCODE
#undef INITCODE
#endif
#ifndef WIN_ASSERT
#define WIN_ASSERT QUIC_FRE_ASSERT
#endif
#include "karray.h"
#endif

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestConnection.h"
#include "TestListener.h"
#include "DrillDescriptor.h"
