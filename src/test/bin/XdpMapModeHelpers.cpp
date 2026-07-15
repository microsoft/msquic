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
#include "XdpMapModeHelpers.h"

#include <stdexcept>

#if defined(_WIN32) && defined(QUIC_API_ENABLE_PREVIEW_FEATURES)

#define XDP_API_VERSION 3
#define XDP_INCLUDE_WINCOMMON
#include <xdp/wincommon.h>
#include <xdpapi.h>
#include <iphlpapi.h>

extern const MsQuicApi* MsQuic;
extern bool UseDuoNic;
extern bool UseQTIP;

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

std::vector<uint32_t>
DiscoverDuoNicInterfaces()
{
    std::vector<uint32_t> Result;
    ULONG Flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG BufSize = 0;
    GetAdaptersAddresses(AF_INET, Flags, NULL, NULL, &BufSize);
    if (BufSize == 0) {
        return Result;
    }

    std::vector<uint8_t> Buffer(BufSize);
    auto* Adapters = (IP_ADAPTER_ADDRESSES*)Buffer.data();

    if (GetAdaptersAddresses(AF_INET, Flags, NULL, Adapters, &BufSize) != NO_ERROR) {
        return Result;
    }

    QUIC_ADDR DuoNicServer = {};
    QUIC_ADDR DuoNicClient = {};
    QuicAddrFromString("192.168.1.11", 0, &DuoNicServer);
    QuicAddrFromString("192.168.1.12", 0, &DuoNicClient);

    for (auto* Adapter = Adapters;
         Adapter != nullptr && Result.size() < XDP_MAP_MODE_MAX_INTERFACES;
         Adapter = Adapter->Next) {

        if (Adapter->IfType != IF_TYPE_ETHERNET_CSMACD ||
            Adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        for (auto* Unicast = Adapter->FirstUnicastAddress; Unicast != nullptr; Unicast = Unicast->Next) {
            if (Unicast->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            auto* Addr = (QUIC_ADDR*)Unicast->Address.lpSockaddr;
            if (QuicAddrCompareIp(Addr, &DuoNicServer) ||
                QuicAddrCompareIp(Addr, &DuoNicClient)) {
                Result.push_back(Adapter->IfIndex);
                break;
            }
        }
    }
    return Result;
}

XdpMapModeRuleScope::XdpMapModeRuleScope(bool UseCibirParam, bool UseQtipParam)
{
    UseQtip = UseQtipParam;

    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
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
            if (PortSocksUdp[i] == INVALID_SOCKET) {
                throw std::runtime_error("Failed to create UDP socket");
            }
            struct sockaddr_in Addr = {};
            Addr.sin_family = AF_INET;
            if (bind(PortSocksUdp[i], (struct sockaddr*)&Addr, sizeof(Addr)) != 0) {
                throw std::runtime_error("Failed to bind UDP socket");
            }
            int AddrLen = sizeof(Addr);
            if (getsockname(PortSocksUdp[i], (struct sockaddr*)&Addr, &AddrLen) != 0) {
                throw std::runtime_error("getsockname failed");
            }
            uint16_t Port = ntohs(Addr.sin_port);
            if (Port == 0) {
                throw std::runtime_error("OS assigned port 0");
            }

            //
            // Reserve the same port number on TCP. This prevents another
            // process from binding a TCP socket to this port, which is
            // required for QTIP (QUIC-over-TCP) tests.
            //
            PortSocksTcp[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (PortSocksTcp[i] == INVALID_SOCKET) {
                throw std::runtime_error("Failed to create TCP socket");
            }
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
            closesocket(PortSocksTcp[i]);
            PortSocksTcp[i] = INVALID_SOCKET;
            closesocket(PortSocksUdp[i]);
            PortSocksUdp[i] = INVALID_SOCKET;
        }
        if (!PortReserved) {
            throw std::runtime_error(
                "Failed to reserve a UDP+TCP port pair after max attempts");
        }
    }

    printf("XDP Map Mode: ports Server=%u Client=%u CIBIR=%d QTIP=%d\n",
        ServerPort, ClientPort, UseCibirParam, UseQtipParam);

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
        if (QueueCounts[i] == 0) {
            throw std::runtime_error(
                "Failed to create any XDP programs for interface");
        }
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
    if (WsaInitialized) {
        WSACleanup();
    }
}

//
// Helper: re-initialize the global MsQuic API object with optional XDP map
// mode configuration. Called by XdpMapModeTestScope's constructor and
// destructor to cycle the library.
//
static bool
ReinitMsQuic(bool WithMapMode)
{
    MsQuic = new(std::nothrow) MsQuicApi();
    if (!MsQuic || QUIC_FAILED(MsQuic->GetInitStatus())) {
        printf("XdpMapModeTestScope: MsQuicApi init failed\n");
        return false;
    }

    if (UseDuoNic) {
        MsQuicSettings Settings;
        Settings.SetXdpEnabled(true);
        if (QUIC_FAILED(Settings.SetGlobal())) {
            printf("XdpMapModeTestScope: SetXdpEnabled failed\n");
            return false;
        }
    }

    if (UseQTIP) {
        MsQuicSettings Settings;
        Settings.SetQtipEnabled(true);
        if (QUIC_FAILED(Settings.SetGlobal())) {
            printf("XdpMapModeTestScope: SetQtipEnabled failed\n");
            return false;
        }
    }

    if (WithMapMode) {
        QUIC_XDP_MAP_CONFIG MapConfigs[XDP_MAP_MODE_MAX_INTERFACES];
        for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
            MapConfigs[i].InterfaceIndex = XdpMapState.IfIndices[i];
            MapConfigs[i].MapHandle = (QUIC_XDP_MAP_HANDLE)XdpMapState.XskMaps[i];
        }

        if (QUIC_FAILED(MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG,
                XdpMapState.InterfaceCount * sizeof(QUIC_XDP_MAP_CONFIG),
                MapConfigs))) {
            printf("XdpMapModeTestScope: SetParam XDP_MAP_CONFIG failed\n");
            return false;
        }
    }

    BOOLEAN DscpOption = TRUE;
    if (QUIC_FAILED(MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_DATAPATH_DSCP_RECV_ENABLED,
            sizeof(BOOLEAN),
            &DscpOption))) {
        printf("XdpMapModeTestScope: SetParam DSCP_RECV_ENABLED failed\n");
        return false;
    }

    QuicTestInitialize();
    return true;
}

XdpMapModeTestScope::XdpMapModeTestScope()
{
    //
    // Map mode requires DuoNic.
    //
    if (!UseDuoNic) {
        Skip = true;
        SkipMessage = "XDP Map Mode requires DuoNic (--duoNic)";
        return;
    }

    //
    // Discover DuoNic interfaces.
    //
    auto IfIndices = DiscoverDuoNicInterfaces();
    if (IfIndices.empty()) {
        Skip = true;
        SkipMessage = "No DuoNic interfaces found";
        return;
    }

    //
    // Probe whether the XDP driver supports map mode by trying to create
    // a temporary XSKMAP. If it fails the driver is too old.
    //
    HANDLE ProbeMap = nullptr;
    HRESULT Hr = XdpMapCreate(&ProbeMap, XDP_MAP_TYPE_XSKMAP);
    if (FAILED(Hr)) {
        Skip = true;
        SkipMessage = "XDP driver does not support map mode (XdpMapCreate failed)";
        return;
    }
    CloseHandle(ProbeMap);

    //
    // Tear down the current MsQuic library instance so we can re-create
    // it with XDP map config set before lazy initialization.
    //
    QuicTestUninitialize();
    delete MsQuic;
    MsQuic = nullptr;

    //
    // Populate XdpMapState with discovered interfaces and create XSKMAPs.
    //
    XdpMapState.InterfaceCount = (uint32_t)IfIndices.size();
    memcpy(XdpMapState.IfIndices, IfIndices.data(),
        sizeof(uint32_t) * IfIndices.size());
    printf("XdpMapModeTestScope: discovered %u DuoNic interface(s)\n",
        XdpMapState.InterfaceCount);

    for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
        Hr = XdpMapCreate(&XdpMapState.XskMaps[i], XDP_MAP_TYPE_XSKMAP);
        if (FAILED(Hr)) {
            //
            // Clean up any already-created maps and restore normal mode.
            //
            for (uint32_t j = 0; j < i; j++) {
                CloseHandle(XdpMapState.XskMaps[j]);
                XdpMapState.XskMaps[j] = nullptr;
            }
            XdpMapState.InterfaceCount = 0;
            ReinitMsQuic(false);
            Skip = true;
            SkipMessage = "XdpMapCreate failed for interface XSKMAP";
            return;
        }
        printf("  IfIndex=%u, XskMap=%p\n",
            XdpMapState.IfIndices[i], XdpMapState.XskMaps[i]);
    }

    //
    // Re-create MsQuic with map mode configured.
    //
    if (!ReinitMsQuic(true)) {
        for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
            if (XdpMapState.XskMaps[i]) {
                CloseHandle(XdpMapState.XskMaps[i]);
                XdpMapState.XskMaps[i] = nullptr;
            }
        }
        XdpMapState.InterfaceCount = 0;
        ReinitMsQuic(false);
        Skip = true;
        SkipMessage = "Failed to re-initialize MsQuic with XDP map config";
        return;
    }

    MapModeActive = true;
}

XdpMapModeTestScope::~XdpMapModeTestScope()
{
    if (!MapModeActive) {
        return;
    }

    //
    // Tear down the map-mode MsQuic instance.
    //
    QuicTestUninitialize();
    delete MsQuic;
    MsQuic = nullptr;

    //
    // Close XSKMAPs.
    //
    for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
        if (XdpMapState.XskMaps[i]) {
            CloseHandle(XdpMapState.XskMaps[i]);
            XdpMapState.XskMaps[i] = nullptr;
        }
    }
    XdpMapState.InterfaceCount = 0;

    //
    // Restore the normal (non-map-mode) MsQuic instance.
    //
    ReinitMsQuic(false);
}

#endif // _WIN32 && QUIC_API_ENABLE_PREVIEW_FEATURES
