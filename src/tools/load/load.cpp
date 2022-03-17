/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <stdio.h>
#include "quic_datapath.h"
#include "msquic.hpp"

const MsQuicApi* MsQuic;
volatile long ConnectedCount;
volatile long ConnectionsActive;

void ResolveServerAddress(const char* ServerName, QUIC_ADDR& ServerAddress) {
    CxPlatSystemLoad();
    CxPlatInitialize();
    CXPLAT_DATAPATH* Datapath = nullptr;
    //QuicAddrSetFamily(&ServerAddress, AF_INET);
    if (QUIC_FAILED(CxPlatDataPathInitialize(0,nullptr,nullptr,nullptr,&Datapath)) ||
        QUIC_FAILED(CxPlatDataPathResolveAddress(Datapath,ServerName,&ServerAddress))) {
        printf("Failed to resolve IP address!\n");
        exit(1);
    }
    CxPlatDataPathUninitialize(Datapath);
    CxPlatUninitialize();
    CxPlatSystemUnload();
}

QUIC_STATUS ConnectionCallback(_In_ struct MsQuicConnection* , _In_opt_ void* , _Inout_ QUIC_CONNECTION_EVENT* Event) {
    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
        InterlockedIncrement(&ConnectedCount);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
        InterlockedDecrement(&ConnectionsActive);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, MsQuicStream::NoOpCallback);
    }
    return QUIC_STATUS_SUCCESS;
}

int QUIC_MAIN_EXPORT main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: quicload.exe <server_name> [conn_count] [keep_alive_ms] [poll_ms] [share_udp]\n");
        return 1;
    }

    const char* ServerName = argv[1];
    QuicAddr ServerAddress = {0};
    ResolveServerAddress(ServerName, ServerAddress.SockAddr);

    const uint32_t ConnectionCount = argc > 2 ? atoi(argv[2]) : 100;
    const uint32_t KeepAliveMs = argc > 3 ? atoi(argv[3]) : 60 * 1000;
    const uint32_t PollMs = argc > 4 ? atoi(argv[4]) : 10 * 1000;
    const bool ShareUdp = argc > 5 ? (atoi(argv[5]) ? true : false) : true;

    MsQuic = new(std::nothrow) MsQuicApi;
    {
        MsQuicRegistration Registration(true);
        MsQuicAlpn Alpns("h3", "h3-29");
        MsQuicSettings Settings;
        Settings.SetPeerUnidiStreamCount(3);
        Settings.SetKeepAlive(KeepAliveMs);
        Settings.SetIdleTimeoutMs(10 * 60 * 1000);
        MsQuicConfiguration Config(Registration, Alpns, Settings, MsQuicCredentialConfig());
        QUIC_ADDR_STR AddrStr;
        QuicAddrToString(&ServerAddress.SockAddr, &AddrStr);
        printf("Starting %u connections to %s [%s]\n\n", ConnectionCount, ServerName, AddrStr.Address);
        QuicAddr LocalAddress = {0};
        ConnectionsActive = ConnectionCount;
        uint64_t Start = CxPlatTimeMs64();
        for (uint32_t i = 0; i < ConnectionCount; ++i) {
            auto Connection = new(std::nothrow) MsQuicConnection(Registration, CleanUpAutoDelete, ConnectionCallback);
            Connection->SetRemoteAddr(ServerAddress);
            if (ShareUdp) {
                Connection->SetShareUdpBinding();
                if (i != 0) Connection->SetLocalAddr(LocalAddress);
            }
            Connection->Start(Config, ServerName, 443);
            if (ShareUdp && i == 0) Connection->GetLocalAddr(LocalAddress);
        }
        while (ConnectionsActive != 0) {
            printf("%4llu: %u connected, %u active\n", (long long unsigned)(CxPlatTimeMs64() - Start) / 1000, (uint32_t)ConnectedCount, (uint32_t)ConnectionsActive);
            CxPlatSleep(PollMs);
        }
    }

    delete MsQuic;
    return 0;
}
