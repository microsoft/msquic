/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#ifdef _KERNEL_MODE
#ifdef PAGEDX
#undef PAGEDX
#endif
#ifdef INITCODE
#undef INITCODE
#endif
#include <karray.h>
#else
#include <vector>
#endif

#include "TestAbstractionLayer.h"

#include <msquic.h>
#include <msquicp.h>
#include <quic_versions.h>

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestConnection.h"
#include "TestListener.h"
#include "DrillDescriptor.h"
