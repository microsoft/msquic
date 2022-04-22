/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Load balances QUIC traffic from a public address to a set of private
    addresses. Requires the use of NAT'ing. Don't use in production.

--*/

#include <vector>
#include <unordered_map>
#include <mutex>

#include "quic_datapath.h"
#include "quic_toeplitz.h"
#include "msquichelper.h"

bool Verbose = false;
CXPLAT_DATAPATH* Datapath;
struct LbInterface* PublicInterface;
std::vector<QUIC_ADDR> PrivateAddrs;

struct LbInterface {
    bool IsPublic;
    CXPLAT_SOCKET* Socket {nullptr};
    QUIC_ADDR LocalAddress;

    LbInterface(_In_ const QUIC_ADDR* Address, bool IsPublic) : IsPublic(IsPublic) {
        CXPLAT_UDP_CONFIG UdpConfig = {0};
        UdpConfig.LocalAddress = nullptr;
        UdpConfig.RemoteAddress = nullptr;
        UdpConfig.Flags = 0;
        UdpConfig.InterfaceIndex = 0;
        UdpConfig.CallbackContext = this;
        if (IsPublic) {
            UdpConfig.LocalAddress = Address;
            CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket);
        } else {
            UdpConfig.RemoteAddress = Address;
            CxPlatSocketCreateUdp(Datapath, &UdpConfig, &Socket);
        }
        if (!Socket) {
            printf("CxPlatSocketCreateUdp failed.\n");
            exit(1);
        }
        CxPlatSocketGetLocalAddress(Socket, &LocalAddress);
    }

    virtual ~LbInterface() {
        CxPlatSocketDelete(Socket);
    }

    virtual void Receive(_In_ CXPLAT_RECV_DATA* RecvDataChain) = 0;

    void Send(_In_ CXPLAT_RECV_DATA* RecvDataChain, _In_opt_ const QUIC_ADDR* PeerAddress = nullptr) {
        QUIC_ADDR RemoteAddress;
        if (PeerAddress == nullptr) {
            CxPlatSocketGetRemoteAddress(Socket, &RemoteAddress);
            PeerAddress = &RemoteAddress;
        }
        CXPLAT_ROUTE Route;
        Route.LocalAddress = LocalAddress;
        Route.RemoteAddress = *PeerAddress;
        CXPLAT_SEND_DATA* Send = nullptr;
        while (RecvDataChain) {
            if (!Send) {
                Send = CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, MAX_UDP_PAYLOAD_LENGTH, &Route);
            }
            if (Send) {
                auto Buffer = CxPlatSendDataAllocBuffer(Send, MAX_UDP_PAYLOAD_LENGTH);
                if (!Buffer) {
                    (void)CxPlatSocketSend(Socket, &Route, Send, 0);
                    Send = CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, MAX_UDP_PAYLOAD_LENGTH, &Route);
                    if (Send) {
                        Buffer = CxPlatSendDataAllocBuffer(Send, MAX_UDP_PAYLOAD_LENGTH);
                    }
                }
                if (Buffer) {
                    Buffer->Length = RecvDataChain->BufferLength;
                    CxPlatCopyMemory(Buffer->Buffer, RecvDataChain->Buffer, RecvDataChain->BufferLength);
                }
            }
            RecvDataChain = RecvDataChain->Next;
        }
        if (Send) {
            (void)CxPlatSocketSend(Socket, &Route, Send, 0);
        }
    }
};

//
// Represents a NAT'ed socket from the load balancer back to a single private
// server address.
//
struct LbPrivateInterface : public LbInterface {
    const QUIC_ADDR PeerAddress {0};

    LbPrivateInterface(_In_ const QUIC_ADDR* PrivateAddress, _In_ const QUIC_ADDR* PeerAddress)
        : LbInterface(PrivateAddress, false), PeerAddress(*PeerAddress) {
        if (Verbose) {
            QUIC_ADDR_STR PeerStr, PrivateStr;
            QuicAddrToString(PeerAddress, &PeerStr);
            QuicAddrToString(PrivateAddress, &PrivateStr);
            printf("New private interface, %s => %s\n", PeerStr.Address, PrivateStr.Address);
        }
    }

    void Receive(_In_ CXPLAT_RECV_DATA* RecvDataChain) {
        PublicInterface->Send(RecvDataChain, &PeerAddress);
    }
};

//
// Represents the public listening socket that load balances (and NATs) UDP
// packets between public clients and back end (private) server addresses.
//
struct LbPublicInterface : public LbInterface {
    struct Hasher {
        CXPLAT_TOEPLITZ_HASH Toeplitz;
        Hasher() {
            CxPlatRandom(CXPLAT_TOEPLITZ_KEY_SIZE, &Toeplitz.HashKey);
            CxPlatToeplitzHashInitialize(&Toeplitz);
        }
        size_t operator() (const std::pair<QUIC_ADDR, QUIC_ADDR> key) const {
            uint32_t Key = 0, Offset;
            CxPlatToeplitzHashComputeAddr(&Toeplitz, &key.first, &Key, &Offset);
            CxPlatToeplitzHashComputeAddr(&Toeplitz, &key.second, &Key, &Offset);
            return Key;
        }
    };

    struct EqualFn {
        bool operator() (const std::pair<QUIC_ADDR, QUIC_ADDR>& t1, const std::pair<QUIC_ADDR, QUIC_ADDR>& t2) const {
            return QuicAddrCompare(&t1.second, &t2.second);
        }
    };

    std::unordered_map<std::pair<QUIC_ADDR, QUIC_ADDR>, LbPrivateInterface*, Hasher, EqualFn> PrivateInterfaces;
    std::mutex Lock;
    uint32_t NextInterface = 0;

    LbPublicInterface(_In_ const QUIC_ADDR* PublicAddress) : LbInterface(PublicAddress, true) { }

    ~LbPublicInterface() {
        // TODO - Iterate over private interfaces and delete
    }

    void Receive(_In_ CXPLAT_RECV_DATA* RecvDataChain) {
        auto PrivateInterface =
            GetPrivateInterface(
                &RecvDataChain->Route->LocalAddress,
                &RecvDataChain->Route->RemoteAddress);
        PrivateInterface->Send(RecvDataChain);
    }

    LbInterface* GetPrivateInterface(_In_ const QUIC_ADDR* Local, _In_ const QUIC_ADDR* Remote) {
        std::lock_guard<std::mutex> Scope(Lock);
        auto& Entry = PrivateInterfaces[std::pair{*Local, *Remote}];
        if (!Entry) {
            Entry = new LbPrivateInterface(&PrivateAddrs[NextInterface++ % PrivateAddrs.size()], Remote);
        }
        return Entry;
    }
};

void LbReceive(_In_ CXPLAT_SOCKET*, _In_ void* Context, _In_ CXPLAT_RECV_DATA* RecvDataChain) {
    ((LbInterface*)(Context))->Receive(RecvDataChain);
    CxPlatRecvDataReturn(RecvDataChain);
}

void NoOpUnreachable(_In_ CXPLAT_SOCKET*,_In_ void*, _In_ const QUIC_ADDR*) { }

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    const char* PublicAddress = "";
    const char* PrivateAddresses = "";
    if (!TryGetValue(argc, argv, "pub", &PublicAddress) ||
        !TryGetValue(argc, argv, "priv", &PrivateAddresses)) {
        printf("Usage: quiclb -pub:<address> -priv:<address>,<address>\n");
        exit(1);
    }
    Verbose = GetFlag(argc, argv, "v") || GetFlag(argc, argv, "verbose");

    QUIC_ADDR PublicAddr;
    if (!QuicAddrFromString(PublicAddress, 0, &PublicAddr) ||
        !QuicAddrGetPort(&PublicAddr)) {
        printf("Failed to decode -pub address: %s.\n", PublicAddress);
        exit(1);
    }

    while (true) {
        char* End = (char*)strchr(PrivateAddresses, ',');
        if (End) { *End = 0; }

        QUIC_ADDR PrivateAddr;
        if (!QuicAddrFromString(PrivateAddresses, 0, &PrivateAddr) ||
            !QuicAddrGetPort(&PrivateAddr)) {
            printf("Failed to decode -priv address: %s.\n", PrivateAddresses);
            exit(1);
        }
        PrivateAddrs.push_back(PrivateAddr);

        if (!End) { break; }
        PrivateAddresses = End + 1;
    }

    CxPlatSystemLoad();
    CxPlatInitialize();

    CXPLAT_UDP_DATAPATH_CALLBACKS LbUdpCallbacks { LbReceive, NoOpUnreachable };
    CxPlatDataPathInitialize(0, &LbUdpCallbacks, nullptr, nullptr, &Datapath);
    PublicInterface = new LbPublicInterface(&PublicAddr);

    printf("Press Enter to exit.\n\n");
    getchar();

    delete PublicInterface;
    CxPlatDataPathUninitialize(Datapath);
    CxPlatUninitialize();
    CxPlatSystemUnload();

    return 0;
}
