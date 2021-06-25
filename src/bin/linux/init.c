/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Library init routines

--*/

#include "quic_platform.h"

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
    MsQuicLibraryLoad();
}

static
void
Exit(
    void
    )
{
    MsQuicLibraryUnload();
}
