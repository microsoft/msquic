/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <stdio.h>
#include "quic_datapath.h"
#include "msquic.hpp"

const MsQuicApi* MsQuic;
volatile long ConnectedCount;
const uint32_t ConnectionCount = 100;

void ResolveServerAddress(const char* ServerName, QUIC_ADDR& ServerAddress) {
    CxPlatSystemLoad();
    CxPlatInitialize();
    CXPLAT_DATAPATH* Datapath = nullptr;
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
    } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, MsQuicStream::NoOpCallback);
    }
    return QUIC_STATUS_SUCCESS;
}

int QUIC_MAIN_EXPORT main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: quicload.exe <server_name>\n");
        return 1;
    }

    const char* ServerName = argv[1];
    QuicAddr ServerAddress = {0};
    ResolveServerAddress(ServerName, ServerAddress.SockAddr);

    MsQuic = new(std::nothrow) MsQuicApi;
    {
        MsQuicRegistration Registration(true);
        MsQuicAlpn Alpns("h3", "h3-29");
        MsQuicSettings Settings;
        Settings.SetPeerUnidiStreamCount(3);
        MsQuicConfiguration Config(Registration, Alpns, Settings, MsQuicCredentialConfig());
        QUIC_ADDR_STR AddrStr;
        QuicAddrToString(&ServerAddress.SockAddr, &AddrStr);
        printf("Starting %u connections to %s [%s]\n", ConnectionCount, ServerName, AddrStr.Address);
        QuicAddr LocalAddress = {0};
        for (uint32_t i = 0; i < ConnectionCount; ++i) {
            auto Connection = new(std::nothrow) MsQuicConnection(Registration, CleanUpAutoDelete, ConnectionCallback);
            Connection->SetRemoteAddr(ServerAddress);
            Connection->SetShareUdpBinding();
            if (i != 0) Connection->SetLocalAddr(LocalAddress);
            Connection->Start(Config, ServerName, 443);
            if (i == 0) Connection->GetLocalAddr(LocalAddress);
        }
        CxPlatSleep(5000);
        printf("%d connections connected\n", ConnectedCount);
    }

    delete MsQuic;
    return 0;
}
