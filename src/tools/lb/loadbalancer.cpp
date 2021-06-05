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
#include <quic_toeplitz.h>
#include <msquichelper.h>

CXPLAT_DATAPATH_RECEIVE_CALLBACK LbReceive;
CXPLAT_DATAPATH_UNREACHABLE_CALLBACK LbUnreachable;
CXPLAT_UDP_DATAPATH_CALLBACKS LbUdpCallbacks { LbReceive, LbUnreachable };

struct LbInterface;

CXPLAT_DATAPATH* Datapath;
CXPLAT_TOEPLITZ_HASH ToeplitzHash;

uint32_t Hash4Tuple(_In_ const QUIC_ADDR* Local, _In_ const QUIC_ADDR* Remote) {
    uint32_t Key, Offset;
    if (QuicAddrGetFamily(Local) == QUIC_ADDRESS_FAMILY_INET) {
        Key =
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Local) + QUIC_ADDR_V4_PORT_OFFSET,
                2, 0);
        Key ^=
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Local) + QUIC_ADDR_V4_IP_OFFSET,
                4, 2);
        Offset = 2 + 4;
    } else {
        Key =
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Local) + QUIC_ADDR_V6_PORT_OFFSET,
                2, 0);
        Key ^=
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Local) + QUIC_ADDR_V6_IP_OFFSET,
                16, 2);
        Offset = 2 + 16;
    }
    if (QuicAddrGetFamily(Remote) == QUIC_ADDRESS_FAMILY_INET) {
        Key ^=
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Remote) + QUIC_ADDR_V4_PORT_OFFSET,
                2, 0);
        Key ^=
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Remote) + QUIC_ADDR_V4_IP_OFFSET,
                4, 2);
        Offset = 2 + 4;
    } else {
        Key ^=
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Remote) + QUIC_ADDR_V6_PORT_OFFSET,
                2, 0);
        Key ^=
            CxPlatToeplitzHashCompute(
                &ToeplitzHash,
                ((uint8_t*)Remote) + QUIC_ADDR_V6_IP_OFFSET,
                16, 2);
        Offset = 2 + 16;
    }
    return Key;
}

LbInterface* PublicInterface;
std::vector<LbInterface*> PrivateInterfaces;

LbInterface* GetPrivateInterface(_In_ const QUIC_ADDR* Local, _In_ const QUIC_ADDR* Remote) {
    uint32_t Hash = Hash4Tuple(Local, Remote);
    return PrivateInterfaces[Hash % PrivateInterfaces.size()];
}

struct LbInterface {
    bool PublicEndpoint;
    CXPLAT_SOCKET* Socket {nullptr};

    LbInterface(_In_ const QUIC_ADDR* Address, _In_ bool PublicEndpoint)
        : PublicEndpoint(PublicEndpoint) {
        if (PublicEndpoint) {
            CxPlatSocketCreateUdp(Datapath, Address, NULL, this, 0, &Socket);
        } else {
            CxPlatSocketCreateUdp(Datapath, NULL, Address, this, 0, &Socket);
        }
        if (!Socket) {
            printf("CxPlatSocketCreateUdp failed.\n");
            exit(1);
        }
    }

    ~LbInterface() {
        CxPlatSocketDelete(Socket);
    }

    void Receive(_In_ CXPLAT_RECV_DATA* RecvDataChain) {
        if (PublicEndpoint) {
            auto PrivateInterface =
                GetPrivateInterface(
                    &RecvDataChain->Tuple->LocalAddress,
                    &RecvDataChain->Tuple->RemoteAddress);
            PrivateInterface->Send(RecvDataChain);
        } else {
            PublicInterface->Send(RecvDataChain);
        }
        CxPlatRecvDataReturn(RecvDataChain);
    }

    void Send(_In_ CXPLAT_RECV_DATA* RecvDataChain) {
        // TODO
    }

};

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
LbReceive(
    _In_ CXPLAT_SOCKET*,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    ((LbInterface*)(Context))->Receive(RecvDataChain);
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

    if (QUIC_FAILED(
        CxPlatDataPathInitialize(
            0,
            &LbUdpCallbacks,
            NULL,
            &Datapath))) {
        printf("CxPlatDataPathInitialize failed.\n");
        exit(1);
    }

    CxPlatRandom(CXPLAT_TOEPLITZ_KEY_SIZE, &ToeplitzHash.HashKey);
    CxPlatToeplitzHashInitialize(&ToeplitzHash);

    PublicInterface = new LbInterface(&PublicAddr, true);
    for (auto& PrivateAddr : PrivateAddrs) {
        PrivateInterfaces.push_back(new LbInterface(&PrivateAddr, false));
    }

    printf("Press Enter to exit.\n\n");
    getchar();

    CxPlatDataPathUninitialize(Datapath);

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return 0;
}
