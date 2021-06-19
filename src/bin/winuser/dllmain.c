/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Dynamic Link Library Entry Point

--*/

#include "quic_platform.h"
#ifdef QUIC_CLOG
#include "quic_trace.h"
#endif

BOOL
__stdcall
DllMain(
    _In_ HINSTANCE Instance,
    _In_ DWORD Reason,
    _In_ LPVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(Reserved);

    switch (Reason) {

    case DLL_PROCESS_ATTACH:
#ifndef _MT // Don't disable thread library calls with static CRT!
        DisableThreadLibraryCalls(Instance);
#else
        UNREFERENCED_PARAMETER(Instance);
#endif
        break;
    }

    return TRUE;
}
