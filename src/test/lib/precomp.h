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
#define CXPLAT_STORAGE_ENABLE_WRITE_SUPPORT
#include "quic_storage.h"

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

//
// Basic listener accept callback that creates a TestConnection and signals
// readiness. For handshake-specific features (cert validation, TLS secrets,
// etc.), use the full ListenerAcceptConnection in HandshakeTest.cpp.
//
_Function_class_(NEW_CONNECTION_CALLBACK)
inline
bool
QUIC_API
ListenerAcceptConnectionBasic(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    )
{
    ServerAcceptContext* AcceptContext = (ServerAcceptContext*)Listener->Context;
    *AcceptContext->NewConnection = new(std::nothrow) TestConnection(ConnectionHandle);
    if (*AcceptContext->NewConnection == nullptr || !(*AcceptContext->NewConnection)->IsValid()) {
        TEST_FAILURE("Failed to accept new TestConnection.");
        delete *AcceptContext->NewConnection;
        *AcceptContext->NewConnection = nullptr;
        return false;
    }
    (*AcceptContext->NewConnection)->SetHasRandomLoss(Listener->GetHasRandomLoss());
    CxPlatEventSet(AcceptContext->NewConnectionReady);
    return true;
}

#if defined(_ARM64_) || defined(_ARM64EC_)
#pragma optimize("", off)
#endif
