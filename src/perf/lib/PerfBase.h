/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Base blass declaration. Defines the base class for all perf
    executions.

--*/

#pragma once

#include "msquic.h"
#include "quic_platform.h"

struct PerfBase {
    //
    // Virtual destructor so we can destruct the base class
    //
    virtual
    ~PerfBase() = default;

    //
    // Called to initialize the runner.
    //
    virtual
    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) = 0;

    //
    // Start the runner. The StopEvent can be triggered to stop early. Passed
    // here rather then Wait so we can synchronize off of it. This event must
    // be kept alive until Wait is called.
    //
    virtual
    QUIC_STATUS
    Start(
        _In_ QUIC_EVENT* StopEvent
        ) = 0;

    //
    // Wait for a run to finish, until timeout.
    // If 0 or less, wait forever
    //
    virtual
    QUIC_STATUS
    Wait(
        int Timeout
        ) = 0;
};
