/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Helpers for configuring the XDP redirect rules used by the XDP map mode
    tests. The rule setup is intentionally kept out of the test list file and is
    invoked explicitly from the start of each test through an RAII scope, so the
    important per-test setup stays visible in the test body instead of being
    hidden in a fixture.

--*/

#pragma once

#if defined(_WIN32) && defined(QUIC_API_ENABLE_PREVIEW_FEATURES)

#include <vector>

#define XDP_MAP_MODE_MAX_INTERFACES 2
#define XDP_MAP_MODE_MAX_QUEUES 64

struct XdpMapModeState {
    uint32_t InterfaceCount;
    uint32_t IfIndices[XDP_MAP_MODE_MAX_INTERFACES];
    HANDLE XskMaps[XDP_MAP_MODE_MAX_INTERFACES];
};

extern XdpMapModeState XdpMapState;

//
// Discover DuoNic interface indices by enumerating Ethernet adapters with
// known DuoNic IPv4 addresses (192.168.1.11 and 192.168.1.12).
//
std::vector<uint32_t>
DiscoverDuoNicInterfaces();

//
// RAII helper that reserves the server/client ports and installs the per-queue
// XDP redirect programs for a single XDP map mode test. Construct it at the
// start of the test body; the constructor performs all setup (throws on
// failure) and the destructor tears everything back down.
//
class XdpMapModeRuleScope {
public:
    XdpMapModeRuleScope(bool UseCibir, bool UseQtip);
    ~XdpMapModeRuleScope();

    XdpMapModeRuleScope(const XdpMapModeRuleScope&) = delete;
    XdpMapModeRuleScope& operator=(const XdpMapModeRuleScope&) = delete;
    XdpMapModeRuleScope(XdpMapModeRuleScope&&) = delete;
    XdpMapModeRuleScope& operator=(XdpMapModeRuleScope&&) = delete;

    uint16_t GetServerPort() const { return ServerPort; }
    uint16_t GetClientPort() const { return ClientPort; }

private:
    static constexpr int PortCount = 2; // server + client
    SOCKET PortSocksUdp[PortCount] = {INVALID_SOCKET, INVALID_SOCKET};
    SOCKET PortSocksTcp[PortCount] = {INVALID_SOCKET, INVALID_SOCKET};
    uint16_t ServerPort = 0;
    uint16_t ClientPort = 0;
    HANDLE XdpPrograms[XDP_MAP_MODE_MAX_INTERFACES][XDP_MAP_MODE_MAX_QUEUES] = {};
    uint32_t QueueCounts[XDP_MAP_MODE_MAX_INTERFACES] = {};
    bool WsaInitialized = false;
    bool UseQtip = false;
};

//
// RAII scope that:
//  On Construction:
//  - probes whether we should skip this test by checking if 1) duonic is enabled AND 2) xdp map APIs work
//  - tears down the global datapath, creates map handles, and creates a new global datapath instance configured
//    with the map handles.
//  On Destruction:
//  - tears down the global datapath we created and configured earlier, and restores the global
//    back to its pre-test state.
//
class XdpMapModeTestScope {
public:
    XdpMapModeTestScope();
    ~XdpMapModeTestScope();

    XdpMapModeTestScope(const XdpMapModeTestScope&) = delete;
    XdpMapModeTestScope& operator=(const XdpMapModeTestScope&) = delete;
    XdpMapModeTestScope(XdpMapModeTestScope&&) = delete;
    XdpMapModeTestScope& operator=(XdpMapModeTestScope&&) = delete;

    bool ShouldSkip() const { return Skip; }
    const char* SkipReason() const { return SkipMessage; }

    bool HasFailed() const { return Failed; }
    const char* FailureReason() const { return FailureMessage; }

private:
    bool Skip = false;
    const char* SkipMessage = nullptr;
    bool Failed = false;
    const char* FailureMessage = nullptr;
};

#endif // _WIN32 && QUIC_API_ENABLE_PREVIEW_FEATURES
