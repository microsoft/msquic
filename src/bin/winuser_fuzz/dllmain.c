/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Dynamic Link Library Entry Point

--*/

#define QUIC_FUZZER 1
#include "msquic.h"
#include "msquic_fuzz.h"
#include "quic_platform.h"

QUIC_FUZZ_CONTEXT MsQuicFuzzerContext = {0};

extern void
CxPlatFuzzerReceiveInject(
    _In_ const QUIC_ADDR *SourceAddress,
    _In_ uint8_t *PacketData,
    _In_ uint16_t PacketLength
    );

void
MsQuicFuzzInit(
    _In_ void *CallbackContext,
    _In_ uint8_t RedirectDataPath
    )
{
    memset(&MsQuicFuzzerContext, '\0', sizeof(MsQuicFuzzerContext));

    MsQuicFuzzerContext.RedirectDataPath = RedirectDataPath;
    MsQuicFuzzerContext.CallbackContext = CallbackContext;
}

void
MsQuicFuzzRegisterSendCallback(
    _In_ QUIC_FUZZ_SEND_CALLBACK_FN SendCallback
    )
{
    MsQuicFuzzerContext.SendCallback = SendCallback;
}

void
MsQuicFuzzRegisterRecvCallback(
    _In_ QUIC_FUZZ_RECV_CALLBACK_FN Callback
    )
{
    MsQuicFuzzerContext.RecvCallback = Callback;
}

void
MsQuicFuzzRegisterInjectCallback(
    _In_ QUIC_FUZZ_INJECT_CALLBACK_FN Callback
    )
{
    MsQuicFuzzerContext.InjectCallback = Callback;
}

void
MsQuicFuzzRegisterEncryptCallback(
    _In_ QUIC_FUZZ_ENCRYPT_CALLBACK_FN Callback
    )
{
    MsQuicFuzzerContext.EncryptCallback = Callback;
}

void
MsQuicFuzzSimulateReceive(
    _In_ const QUIC_ADDR *SourceAddress,
    _In_ uint8_t *PacketData,
    _In_ uint16_t PacketLength
    )
{
    CxPlatFuzzerReceiveInject(SourceAddress, PacketData, PacketLength);
}

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
#ifndef _MT // Don't disable thread library calls with static CRT!
        DisableThreadLibraryCalls(Instance);
#else
        UNREFERENCED_PARAMETER(Instance);
#endif
        MsQuicLibraryLoad();
        break;

    case DLL_PROCESS_DETACH:
        MsQuicLibraryUnload();
        break;
    }

    return TRUE;
}
