/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Dynamic Link Library Entry Point

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
//
// Don't disable thread library calls with static CRT!
//
#ifndef _MT
        DisableThreadLibraryCalls(Instance);
#else
        UNREFERENCED_PARAMETER(Instance);
#endif
        QuicPlatformSystemLoad();
        MsQuicLibraryLoad();
        break;

    case DLL_PROCESS_DETACH:
        MsQuicLibraryUnload();
        QuicPlatformSystemUnload();
        break;
    }

    return TRUE;
}
