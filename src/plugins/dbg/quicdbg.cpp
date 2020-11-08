/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension

--*/

#include "quicdbg.h"

ULONG g_ulDebug = DEBUG_LEVEL_QUIET;

//
// EXT_DECLARE_GLOBALS must be used to instantiate
// the framework's assumed globals.
//
EXT_DECLARE_GLOBALS();
