/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Load balances QUIC traffic from a public address to a set of private
    addresses. Requires the use of NAT'ing. Don't use in production.

--*/

#include <quic_datapath.h>
#include <quic_toeplitz.h>
#include <msquic.hpp>
#include <msquichelper.h>
#include <stdio.h>
#include <vector>

bool Verbose = false;
CXPLAT_DATAPATH* Datapath;
struct LbInterface* PublicInterface;
std::vector<QUIC_ADDR> PrivateAddrs;

struct LbInterface {
    bool IsPublic;
    CXPLAT_SOCKET* Socket {nullptr};
    QUIC_ADDR LocalAddress;
    CXPLAT_HASHTABLE_ENTRY HashEntry {0};

    LbInterface(_In_ const QUIC_ADDR* Address, bool IsPublic)
        : IsPublic(IsPublic) {
        if (IsPublic) {
            CxPlatSocketCreateUdp(Datapath, Address, nullptr, this, 0, &Socket);
        } else {
            CxPlatSocketCreateUdp(Datapath, nullptr, Address, this, 0, &Socket);
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
        CXPLAT_SEND_DATA* Send = nullptr;
        while (RecvDataChain) {
            if (!Send) {
                Send = CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, MAX_UDP_PAYLOAD_LENGTH);
            }
            if (Send) {
                auto Buffer = CxPlatSendDataAllocBuffer(Send, MAX_UDP_PAYLOAD_LENGTH);
                if (!Buffer) {
                    (void)CxPlatSocketSend(Socket, &LocalAddress, PeerAddress, Send, 0);
                    Send = CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, MAX_UDP_PAYLOAD_LENGTH);
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
            (void)CxPlatSocketSend(Socket, &LocalAddress, PeerAddress, Send, 0);
        }
    }
};

//
// Represents a NAT'ed socket from the load balancer back to a single private
// server address.
//
struct LbPrivateInterface : public LbInterface {
    const QUIC_ADDR PeerAddress {0};

    LbPrivateInterface(_In_ const QUIC_ADDR* PrivateAddress, _In_ const QUIC_ADDR* PeerAddress, _In_ uint32_t Hash)
        : LbInterface(PrivateAddress, false), PeerAddress(*PeerAddress) {
        HashEntry.Signature = Hash;
        if (Verbose) {
            QUIC_ADDR_STR PeerStr, PrivateStr;
            QuicAddrToString(PeerAddress, &PeerStr);
            QuicAddrToString(PrivateAddress, &PrivateStr);
            printf("New private interface, %s => %s\n", PeerStr.Address, PrivateStr.Address);
        }
    }

    bool Equals(const QUIC_ADDR* Address) {
        return QuicAddrCompare(&PeerAddress, Address);
    }

    static bool HashEquals(CXPLAT_HASHTABLE_ENTRY* Entry, void* Context) {
        return ((LbPrivateInterface*)CXPLAT_CONTAINING_RECORD(Entry, LbInterface, HashEntry))->Equals((QUIC_ADDR*)Context);
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

    CXPLAT_TOEPLITZ_HASH ToeplitzHash;
    HashTable PrivateInterfaces;
    CXPLAT_DISPATCH_LOCK Lock;

    LbPublicInterface(_In_ const QUIC_ADDR* PublicAddress)
        : LbInterface(PublicAddress, true) {
        CxPlatRandom(CXPLAT_TOEPLITZ_KEY_SIZE, &ToeplitzHash.HashKey);
        CxPlatToeplitzHashInitialize(&ToeplitzHash);
        CxPlatDispatchLockInitialize(&Lock);
    }

    ~LbPublicInterface() {
        // TODO - Iterate over private interfaces and delete
        CxPlatDispatchLockUninitialize(&Lock);
    }

    void Receive(_In_ CXPLAT_RECV_DATA* RecvDataChain) {
        auto PrivateInterface =
            GetPrivateInterface(
                &RecvDataChain->Tuple->LocalAddress,
                &RecvDataChain->Tuple->RemoteAddress);
        PrivateInterface->Send(RecvDataChain);
    }

    uint32_t Hash4Tuple(_In_ const QUIC_ADDR* Local, _In_ const QUIC_ADDR* Remote) {
        uint32_t Key = 0, Offset;
        CxPlatToeplitzHashComputeAddr(&ToeplitzHash, Local, &Key, &Offset);
        CxPlatToeplitzHashComputeAddr(&ToeplitzHash, Remote, &Key, &Offset);
        return Key;
    }

    LbInterface* GetPrivateInterface(_In_ const QUIC_ADDR* Local, _In_ const QUIC_ADDR* Remote) {
        uint32_t Hash = Hash4Tuple(Local, Remote);
        CxPlatDispatchLockAcquire(&Lock);
        auto Entry = PrivateInterfaces.LookupEx(Hash, LbPrivateInterface::HashEquals, (void*)Remote);
        if (Entry) {
            CxPlatDispatchLockRelease(&Lock);
            return CXPLAT_CONTAINING_RECORD(Entry, LbInterface, HashEntry);
        }
        auto NewInterface = new LbPrivateInterface(&PrivateAddrs[Hash % PrivateAddrs.size()], Remote, Hash);
        PrivateInterfaces.Insert(&NewInterface->HashEntry);
        CxPlatDispatchLockRelease(&Lock);
        return NewInterface;
    }
};

_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
LbReceive(
    _In_ CXPLAT_SOCKET*,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    ((LbInterface*)(Context))->Receive(RecvDataChain);
    CxPlatRecvDataReturn(RecvDataChain);
}

_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
NoOpUnreachable(
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
    CxPlatDataPathInitialize(0, &LbUdpCallbacks, nullptr, &Datapath);
    PublicInterface = new LbPublicInterface(&PublicAddr);

    printf("Press Enter to exit.\n\n");
    getchar();

    delete PublicInterface;
    CxPlatDataPathUninitialize(Datapath);
    CxPlatUninitialize();
    CxPlatSystemUnload();

    return 0;
}
