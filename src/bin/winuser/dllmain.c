/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Dynamic Link Library Entry Point

--*/

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
        DisableThreadLibraryCalls(Instance);
        QuicPlatformSystemLoad();
        EventSetInformation(Microsoft_QuicHandle, EventProviderBinaryTrackInfo, NULL, 0);
        MsQuicLibraryLoad();
        break;

    case DLL_PROCESS_DETACH:
        MsQuicLibraryUnload();
        QuicPlatformSystemUnload();
        break;
    }

    return TRUE;
}
