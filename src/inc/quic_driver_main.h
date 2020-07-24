/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Main common driver code.

--*/

#pragma once

#include "quic_platform.h"
#include "PerfHelpers.h"

extern
QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ QUIC_EVENT StopEvent,
    _In_ PerfSelfSignedConfiguration* SelfSignedConfig
    );

extern
QUIC_STATUS
QuicMainStop(
    _In_ int Timeout
    );
