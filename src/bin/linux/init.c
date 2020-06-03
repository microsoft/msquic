/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Library init routines

--*/

#define TRACEPOINT_CREATE_PROBES
#include "quic_platform.h"
#include "quic_trace.h"

void
MsQuicLibraryLoad(
    void
    );

void
MsQuicLibraryUnload(
    void
    );

static
void
Entry(
    void
    ) __attribute__((constructor));

static
void
Exit(
    void
    ) __attribute__((destructor));

static
void
Entry(
    void
    )
{
    QuicPlatformSystemLoad();
    MsQuicLibraryLoad();
}

static
void
Exit(
    void
    )
{
    MsQuicLibraryUnload();
    QuicPlatformSystemUnload();
}
