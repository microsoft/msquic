/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Load balances QUIC traffic from a public address to a set of private
    addresses.

--*/

#include <time.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>

#include <quic_datapath.h>
#include <msquichelper.h>

CXPLAT_DATAPATH_RECEIVE_CALLBACK LbReceive;
CXPLAT_DATAPATH_UNREACHABLE_CALLBACK LbUnreachable;
CXPLAT_UDP_DATAPATH_CALLBACKS LbUdpCallbacks { LbReceive, LbUnreachable };

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
LbReceive(
    _In_ CXPLAT_SOCKET*,
    _In_ void*,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatRecvDataReturn(RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
LbUnreachable(
    _In_ CXPLAT_SOCKET*,
    _In_ void*,
    _In_ const QUIC_ADDR*
    )
{
}

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    const char* PublicAddress;
    const char* PrivateAddresses;
    if (!TryGetValue(argc, argv, "pub", &PublicAddress) ||
        !TryGetValue(argc, argv, "priv", &PrivateAddresses)) {
        printf("Usage: quiclb -pub:<address> -priv:<address>,<address>\n");
        exit(1);
    }

    QUIC_ADDR PublicAddr;
    if (!QuicAddrFromString(PublicAddress, 0, &PublicAddr) ||
        !QuicAddrGetPort(&PublicAddr)) {
        printf("Failed to decode -pub address: %s.\n", PublicAddress);
        exit(1);
    }

    std::vector<QUIC_ADDR> PrivateAddrs;
    while (true) {
        char* End = (char*)strchr(PrivateAddresses, ',');
        if (End) {
            *End = 0;
        }

        QUIC_ADDR PrivateAddr;
        if (!QuicAddrFromString(PrivateAddresses, 0, &PrivateAddr) ||
            !QuicAddrGetPort(&PrivateAddr)) {
            printf("Failed to decode -priv address: %s.\n", PrivateAddresses);
            exit(1);
        }

        PrivateAddrs.push_back(PrivateAddr);

        if (!End) {
            break;
        }

        PrivateAddresses = End + 1;
    }

    CxPlatSystemLoad();
    CxPlatInitialize();

    CXPLAT_DATAPATH* Datapath = nullptr;
    if (QUIC_FAILED(
        CxPlatDataPathInitialize(
            0,
            &LbUdpCallbacks,
            NULL,
            &Datapath))) {
        printf("CxPlatDataPathInitialize failed.\n");
        exit(1);
    }

    CxPlatDataPathUninitialize(Datapath);

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return 0;
}
