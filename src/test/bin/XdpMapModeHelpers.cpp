/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implementation of the XDP map mode rule configuration helpers. Keeping this
    out of the test list file (quic_gtest.cpp) makes the per-test XDP rule setup
    explicit at the start of each test rather than hidden inside a fixture.

--*/

#include "quic_platform.h"
#include "MsQuicTests.h"
#include "msquichelper.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"
#include "XdpMapModeHelpers.h"

#if defined(_WIN32) && defined(QUIC_API_ENABLE_PREVIEW_FEATURES)

#include <iphlpapi.h>
#define XDP_API_VERSION 3
#define XDP_INCLUDE_WINCOMMON
#include <xdp/wincommon.h>
#include <xdpapi.h>

extern const MsQuicApi* MsQuic;

XdpMapModeState XdpMapState = {};

namespace {

//
// CIBIR test constants matching the CIBIR id used by the map mode tests.
// Internal XDP rule format: just the id bytes, with offset computed as
// MsQuicLib.CidServerIdLength + 2. Default CidServerIdLength=0, so offset=2.
//
constexpr uint8_t CibirIdData[] = { 4, 3, 2, 1 };
constexpr uint8_t CibirIdDataLength = sizeof(CibirIdData);
constexpr uint8_t CibirCidOffset = 2; // CidServerIdLength(0) + 2

} // namespace

bool
DiscoverDuoNicInterfaces(
    _Out_writes_(XDP_MAP_MODE_MAX_INTERFACES) uint32_t* IfIndices,
    _Out_ uint32_t* Count
    )
{
    *Count = 0;
    ULONG Flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG BufSize = 0;
    GetAdaptersAddresses(AF_INET, Flags, NULL, NULL, &BufSize);
    if (BufSize == 0) return false;

    auto Adapters = (PIP_ADAPTER_ADDRESSES)malloc(BufSize);
    if (!Adapters) return false;

    if (GetAdaptersAddresses(AF_INET, Flags, NULL, Adapters, &BufSize) != NO_ERROR) {
        free(Adapters);
        return false;
    }

    for (auto Adapter = Adapters; Adapter && *Count < XDP_MAP_MODE_MAX_INTERFACES; Adapter = Adapter->Next) {
        if (Adapter->IfType != IF_TYPE_ETHERNET_CSMACD ||
            Adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        for (auto Unicast = Adapter->FirstUnicastAddress; Unicast; Unicast = Unicast->Next) {
            if (Unicast->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto* Sin = (SOCKADDR_IN*)Unicast->Address.lpSockaddr;
            ULONG Addr = ntohl(Sin->sin_addr.S_un.S_addr);
            // 192.168.1.11 or 192.168.1.12
            if (Addr == 0xC0A8010B || Addr == 0xC0A8010C) {
                IfIndices[*Count] = Adapter->IfIndex;
                (*Count)++;
                break;
            }
        }
    }
    free(Adapters);
    return *Count > 0;
}

void
XdpMapModeRuleScope::Setup(bool UseCibirParam, bool UseQtipParam)
{
    UseQtip = UseQtipParam;

    WSADATA WsaData;
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &WsaData), 0);
    WsaInitialized = true;

    //
    // Reserve ports (server + client) with OS sockets that stay open.
    // Always reserve both UDP and TCP to prevent port stealing.
    // Retry if the OS-assigned UDP port collides with an existing TCP
    // binding, since UDP and TCP port spaces are independent.
    //
    static const int MaxPortRetries = 1000;
    for (int i = 0; i < PortCount; i++) {
        bool PortReserved = false;
        for (int Retry = 0; Retry < MaxPortRetries; Retry++) {
            PortSocksUdp[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            ASSERT_NE(PortSocksUdp[i], INVALID_SOCKET)
                << "Failed to create UDP socket: WSAGetLastError=" << WSAGetLastError();
            struct sockaddr_in Addr = {};
            Addr.sin_family = AF_INET;
            ASSERT_EQ(bind(PortSocksUdp[i], (struct sockaddr*)&Addr, sizeof(Addr)), 0);
            int AddrLen = sizeof(Addr);
            ASSERT_EQ(getsockname(PortSocksUdp[i], (struct sockaddr*)&Addr, &AddrLen), 0);
            uint16_t Port = ntohs(Addr.sin_port);
            ASSERT_NE(Port, (uint16_t)0);

            //
            // Reserve the same port number on TCP. This prevents another
            // process from binding a TCP socket to this port, which is
            // required for QTIP (QUIC-over-TCP) tests.
            //
            PortSocksTcp[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            ASSERT_NE(PortSocksTcp[i], INVALID_SOCKET)
                << "Failed to create TCP socket: WSAGetLastError=" << WSAGetLastError();
            struct sockaddr_in TcpAddr = {};
            TcpAddr.sin_family = AF_INET;
            TcpAddr.sin_port = htons(Port);
            if (bind(PortSocksTcp[i], (struct sockaddr*)&TcpAddr, sizeof(TcpAddr)) == 0) {
                if (i == 0) ServerPort = Port; else ClientPort = Port;
                PortReserved = true;
                break;
            }
            //
            // TCP port collision. Close both sockets and retry with a
            // new OS-assigned port.
            //
            printf("XDP Map Mode: port %u TCP collision (attempt %d/%d), retrying\n",
                Port, Retry + 1, MaxPortRetries);
            closesocket(PortSocksTcp[i]);
            PortSocksTcp[i] = INVALID_SOCKET;
            closesocket(PortSocksUdp[i]);
            PortSocksUdp[i] = INVALID_SOCKET;
        }
        ASSERT_TRUE(PortReserved)
            << "Failed to reserve a UDP+TCP port pair after "
            << MaxPortRetries << " attempts";
    }

    printf("XDP Map Mode [%s]: ports Server=%u Client=%u CIBIR=%d QTIP=%d\n",
        ::testing::UnitTest::GetInstance()->current_test_info()->name(),
        ServerPort, ClientPort, UseCibirParam, UseQtipParam);

    //
    // If QTIP is needed, enable it globally before creating XDP programs.
    //
    if (UseQtip) {
        MsQuicSettings Settings;
        uint32_t SettingsSize = sizeof(Settings);
        MsQuic->GetParam(nullptr, QUIC_PARAM_GLOBAL_SETTINGS, &SettingsSize, &Settings);
        PreviousQtipSetting = Settings.QTIPEnabled;
        if (!PreviousQtipSetting) {
            Settings.SetQtipEnabled(true);
            ASSERT_TRUE(QUIC_SUCCEEDED(Settings.SetGlobal()));
        }
    }

    //
    // Build XDP rules based on CIBIR/QTIP mode.
    //
    // Server (listener/wildcard) rules:
    //   - No CIBIR: XDP_MATCH_UDP_DST (+ XDP_MATCH_TCP_DST if QTIP)
    //   - CIBIR: QUIC_FLOW_SRC_CID + QUIC_FLOW_DST_CID
    //            (+ TCP_QUIC_FLOW_SRC_CID + TCP_QUIC_FLOW_DST_CID + TCP_CONTROL_DST if QTIP)
    //
    // Client (non-wildcard) rules:
    //   - Always: XDP_MATCH_UDP_DST (no QTIP) or XDP_MATCH_TCP_DST (QTIP)
    //   - CIBIR does NOT change client XDP matching.
    //
    static const XDP_HOOK_ID RxHook = {
        XDP_HOOK_L2,
        XDP_HOOK_RX,
        XDP_HOOK_INSPECT,
    };

    for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
        for (uint32_t q = 0; q < XDP_MAP_MODE_MAX_QUEUES; q++) {
            XDP_RULE Rules[8] = {};
            uint8_t RulesSize = 0;

            //
            // Server port rules.
            //
            if (UseCibirParam) {
                Rules[RulesSize].Match = XDP_MATCH_QUIC_FLOW_SRC_CID;
                Rules[RulesSize].Pattern.QuicFlow.UdpPort = htons(ServerPort);
                Rules[RulesSize].Pattern.QuicFlow.CidLength = CibirIdDataLength;
                Rules[RulesSize].Pattern.QuicFlow.CidOffset = CibirCidOffset;
                memcpy(Rules[RulesSize].Pattern.QuicFlow.CidData, CibirIdData, CibirIdDataLength);
                Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                RulesSize++;

                Rules[RulesSize].Match = XDP_MATCH_QUIC_FLOW_DST_CID;
                Rules[RulesSize].Pattern.QuicFlow.UdpPort = htons(ServerPort);
                Rules[RulesSize].Pattern.QuicFlow.CidLength = CibirIdDataLength;
                Rules[RulesSize].Pattern.QuicFlow.CidOffset = CibirCidOffset;
                memcpy(Rules[RulesSize].Pattern.QuicFlow.CidData, CibirIdData, CibirIdDataLength);
                Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                RulesSize++;

                if (UseQtip) {
                    Rules[RulesSize].Match = XDP_MATCH_TCP_QUIC_FLOW_SRC_CID;
                    Rules[RulesSize].Pattern.QuicFlow.UdpPort = htons(ServerPort);
                    Rules[RulesSize].Pattern.QuicFlow.CidLength = CibirIdDataLength;
                    Rules[RulesSize].Pattern.QuicFlow.CidOffset = CibirCidOffset;
                    memcpy(Rules[RulesSize].Pattern.QuicFlow.CidData, CibirIdData, CibirIdDataLength);
                    Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                    Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                    Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                    RulesSize++;

                    Rules[RulesSize].Match = XDP_MATCH_TCP_QUIC_FLOW_DST_CID;
                    Rules[RulesSize].Pattern.QuicFlow.UdpPort = htons(ServerPort);
                    Rules[RulesSize].Pattern.QuicFlow.CidLength = CibirIdDataLength;
                    Rules[RulesSize].Pattern.QuicFlow.CidOffset = CibirCidOffset;
                    memcpy(Rules[RulesSize].Pattern.QuicFlow.CidData, CibirIdData, CibirIdDataLength);
                    Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                    Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                    Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                    RulesSize++;

                    Rules[RulesSize].Match = XDP_MATCH_TCP_CONTROL_DST;
                    Rules[RulesSize].Pattern.Port = htons(ServerPort);
                    Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                    Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                    Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                    RulesSize++;
                }
            } else {
                Rules[RulesSize].Match = XDP_MATCH_UDP_DST;
                Rules[RulesSize].Pattern.Port = htons(ServerPort);
                Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                RulesSize++;

                if (UseQtip) {
                    Rules[RulesSize].Match = XDP_MATCH_TCP_DST;
                    Rules[RulesSize].Pattern.Port = htons(ServerPort);
                    Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                    Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                    Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                    RulesSize++;
                }
            }

            //
            // Client port rules. CIBIR does not change client XDP matching.
            // QTIP clients use TCP-only; non-QTIP clients use UDP-only.
            //
            if (UseQtip) {
                Rules[RulesSize].Match = XDP_MATCH_TCP_DST;
                Rules[RulesSize].Pattern.Port = htons(ClientPort);
                Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                RulesSize++;
            } else {
                Rules[RulesSize].Match = XDP_MATCH_UDP_DST;
                Rules[RulesSize].Pattern.Port = htons(ClientPort);
                Rules[RulesSize].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[RulesSize].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
                Rules[RulesSize].Redirect.Target = XdpMapState.XskMaps[i];
                RulesSize++;
            }

            HRESULT Hr = XdpCreateProgram(
                XdpMapState.IfIndices[i],
                &RxHook,
                q,
                XDP_CREATE_PROGRAM_FLAG_NONE,
                Rules,
                RulesSize,
                &XdpPrograms[i][q]);
            if (FAILED(Hr)) {
                //
                // No more queues on this interface.
                //
                QueueCounts[i] = q;
                break;
            }
        }
        printf("XDP Map Mode: IfIndex=%u created %u per-queue programs\n",
            XdpMapState.IfIndices[i], QueueCounts[i]);
        ASSERT_GT(QueueCounts[i], (uint32_t)0)
            << "Failed to create any XDP programs for IfIndex="
            << XdpMapState.IfIndices[i];
    }
}

XdpMapModeRuleScope::~XdpMapModeRuleScope()
{
    for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
        for (uint32_t q = 0; q < QueueCounts[i]; q++) {
            if (XdpPrograms[i][q]) {
                CloseHandle(XdpPrograms[i][q]);
                XdpPrograms[i][q] = nullptr;
            }
        }
    }
    for (int i = 0; i < PortCount; i++) {
        if (PortSocksUdp[i] != INVALID_SOCKET) {
            closesocket(PortSocksUdp[i]);
            PortSocksUdp[i] = INVALID_SOCKET;
        }
        if (PortSocksTcp[i] != INVALID_SOCKET) {
            closesocket(PortSocksTcp[i]);
            PortSocksTcp[i] = INVALID_SOCKET;
        }
    }
    //
    // Restore QTIP global setting.
    //
    if (UseQtip && !PreviousQtipSetting) {
        MsQuicSettings Settings;
        Settings.SetQtipEnabled(false);
        Settings.SetGlobal();
    }
    if (WsaInitialized) {
        WSACleanup();
    }
}

#endif // _WIN32 && QUIC_API_ENABLE_PREVIEW_FEATURES
