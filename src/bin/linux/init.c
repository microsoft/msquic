/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Library init routines

--*/

#include "quic_platform.h"

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
}

static
void
Exit(
    void
    )
{
}
