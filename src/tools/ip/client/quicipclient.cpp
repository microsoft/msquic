/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A command-line wrapper for MsQuicGetPublicIP.

--*/

#define ENABLE_QUIC_PRINTF
#include "msquichelper.h"
#include "quicip.h"

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    if (GetFlag(argc, argv, "?") || GetFlag(argc, argv, "help")) {
        printf("Usage:\n");
        printf("  quicipclient.exe [-target:<...>] [-local:<...>] [-unsecure]\n");
        return 0;
    }

    const char* Target = "quic.westus.cloudapp.azure.com";
    const char* LocalAddressArg = "*";
    bool Unsecure = false;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR PublicAddress;

    TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "local", &LocalAddressArg);
    if (GetFlag(argc, argv, "unsecure")) {
        Unsecure = true;
    }

    if (!ConvertArgToAddress(LocalAddressArg, 0, &LocalAddress)) {
        printf("Failed to decode IP address.\n");
        return 0;
    }

    if (QUIC_SUCCEEDED(MsQuicGetPublicIP(Target, Unsecure, &LocalAddress, &PublicAddress))) {
        QUIC_ADDR_STR AddrStr = { 0 };
        QuicAddrToString(&LocalAddress, &AddrStr);
        printf(" Local IP: %s\n", AddrStr.Address);
        QuicAddrToString(&PublicAddress, &AddrStr);
        printf("Public IP: %s\n", AddrStr.Address);
    } else {
        printf("Failed!\n");
    }

    return 0;
}
