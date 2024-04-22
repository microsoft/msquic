/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw_linux.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket_linux.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

//
// Socket Pool Logic
//

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        return FALSE;
    }
    CxPlatRwLockInitialize(&Pool->Lock);
    return TRUE;
}

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    CxPlatRwLockUninitialize(&Pool->Lock);
    CxPlatHashtableUninitialize(&Pool->Sockets);
}

struct BestMacthL3 {
    struct nl_addr *dst;
    struct rtnl_route *BestMatch;
    int BestPrefixLen;
} BestMacthL3;

void FindBestMatchL3(struct nl_object *obj, void *arg) {
    struct rtnl_route *route = (struct rtnl_route *) obj;
    struct BestMacthL3 *data = (struct BestMacthL3 *)arg;
    struct nl_addr *dst_addr = rtnl_route_get_dst(route);
    if (nl_addr_cmp_prefix(data->dst, dst_addr) == 0) {
        int prefixLen = nl_addr_get_prefixlen(dst_addr);
        if (prefixLen > data->BestPrefixLen) {
            data->BestPrefixLen = prefixLen;
            data->BestMatch = route;
        }
    }
}

QUIC_STATUS
ResolveBestL3Route(
    QUIC_ADDR* RemoteAddress,
    QUIC_ADDR* SourceAddress,
    QUIC_ADDR* GatewayAddress,
    int* oif
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    struct nl_sock *sock = NULL;
    struct nl_cache *cache = NULL;
    struct nl_addr *dst = NULL;

    sock = nl_socket_alloc();
    if (!sock) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    if (nl_connect(sock, NETLINK_ROUTE) < 0) {
        nl_socket_free(sock);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    // Allocate the route cache
    if (rtnl_route_alloc_cache(sock, RemoteAddress->Ip.sa_family, 0, &cache) < 0) {
        nl_close(sock);
        nl_socket_free(sock);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    // Create destination address from input
    dst = nl_addr_build(RemoteAddress->Ip.sa_family,
                        RemoteAddress->Ip.sa_family == AF_INET ? (void*)&RemoteAddress->Ipv4.sin_addr : (void*)&RemoteAddress->Ipv6.sin6_addr,
                        RemoteAddress->Ip.sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr));
    if (!dst) {
        nl_cache_free(cache);
        nl_close(sock);
        nl_socket_free(sock);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    // Find best matching route
    struct BestMacthL3 data = {
        .dst = dst,
        .BestMatch = NULL,
        .BestPrefixLen = -1
    };
    nl_cache_foreach(cache, FindBestMatchL3, &data);

    if (data.BestMatch == NULL) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    // Process the found route
    struct nl_addr* src_addr = rtnl_route_get_pref_src(data.BestMatch);
    struct nl_addr* gw_addr = NULL;
    struct rtnl_nexthop *nh = rtnl_route_nexthop_n(data.BestMatch, 0);
    if (nh != NULL) {
        gw_addr = rtnl_route_nh_get_gateway(nh);
        *oif = rtnl_route_nh_get_ifindex(nh);
        if (*oif == 0) {
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }
    }

    if (src_addr != NULL) {
        // Assume the address family is same as input address family
        if (RemoteAddress->Ip.sa_family == AF_INET) {
            memcpy(&(SourceAddress->Ipv4.sin_addr), nl_addr_get_binary_addr(src_addr), sizeof(struct in_addr));
        } else {
            memcpy(&(SourceAddress->Ipv6.sin6_addr), nl_addr_get_binary_addr(src_addr), sizeof(struct in6_addr));
        }
    }

    if (GatewayAddress) {
        if (gw_addr != NULL) {
            // Assume the address family is same as input address family
            if (RemoteAddress->Ip.sa_family == AF_INET) {
                memcpy(&(GatewayAddress->Ipv4.sin_addr), nl_addr_get_binary_addr(gw_addr), sizeof(struct in_addr));
                GatewayAddress->Ipv4.sin_family = AF_INET;
            } else {
                memcpy(&(GatewayAddress->Ipv6.sin6_addr), nl_addr_get_binary_addr(gw_addr), sizeof(struct in6_addr));
                GatewayAddress->Ipv6.sin6_family = AF_INET6;
            }
        } else {
            memcpy(GatewayAddress, RemoteAddress, sizeof(QUIC_ADDR));
        }
    }

Error:
    // Clean up
    nl_addr_put(dst);
    nl_cache_free(cache); // TODO: reuse cache
    nl_close(sock);
    nl_socket_free(sock);

    return Status;
}

struct BestMacthL2 {
    struct nl_addr* NlRemoteAddr;
    uint8_t* NextHopLinkLayerAddress;
} BestMacthL2;

void FindBestMacthL2(struct nl_object *obj, void *arg) {
    struct BestMacthL2* data = (struct BestMacthL2*)arg;
    struct rtnl_neigh* neigh = (struct rtnl_neigh*) obj;
    struct nl_addr* neigh_addr = rtnl_neigh_get_dst(neigh);

    if (nl_addr_cmp(neigh_addr, data->NlRemoteAddr) == 0) {
        struct nl_addr* lladdr = rtnl_neigh_get_lladdr(neigh);
        int* Address = nl_addr_get_binary_addr(lladdr);
        if (Address != NULL) {
            memcpy(data->NextHopLinkLayerAddress, Address, 6);
        }
    }
}

QUIC_STATUS
ResolveRemotePhysicalAddress(
    QUIC_ADDR* RemoteAddr,
    uint8_t NextHopLinkLayerAddress[6])
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    struct nl_sock *sock;
    struct nl_cache *cache;

    sock = nl_socket_alloc();
    if (sock == NULL) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    // Connect the socket
    if (nl_connect(sock, NETLINK_ROUTE)) {
        nl_socket_free(sock);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    // Allocate the cache
    if (rtnl_neigh_alloc_cache(sock, &cache)) {
        nl_socket_free(sock);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    // Loop over the cache entries
    struct nl_addr *NlRemoteAddr = NULL;
    if (RemoteAddr->Ip.sa_family == AF_INET) {
        NlRemoteAddr = nl_addr_build(AF_INET, &RemoteAddr->Ipv4.sin_addr, sizeof(struct in_addr));
    } else if (RemoteAddr->Ip.sa_family == AF_INET6) {
        NlRemoteAddr = nl_addr_build(AF_INET6, &RemoteAddr->Ipv6.sin6_addr, sizeof(struct in6_addr));
    } else {
        CXPLAT_FRE_ASSERT(FALSE);
    }
    struct BestMacthL2 data;
    data.NlRemoteAddr = NlRemoteAddr;
    data.NextHopLinkLayerAddress = NextHopLinkLayerAddress;
    nl_cache_foreach(cache, FindBestMacthL2, &data);

    // Free up memory
    nl_cache_free(cache); // TODO: reuse cache
    nl_socket_free(sock);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawResolveRoute(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    )
{
    UNREFERENCED_PARAMETER(Callback);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_DBG_ASSERT(!QuicAddrIsWildCard(&Route->RemoteAddress));

    Route->State = RouteResolving;

    QuicTraceEvent(
        DatapathGetRouteStart,
        "[data][%p] Querying route, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress));

    QUIC_ADDR NextHop = {0};
    int oif = -1;
    // get best next hop
    Status = ResolveBestL3Route(&Route->RemoteAddress, &Route->LocalAddress, &NextHop, &oif);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "ResolveBestL3Route");
        return Status;
    }

    // get local IP and mac
    CXPLAT_LIST_ENTRY* Entry = Socket->RawDatapath->Interfaces.Flink;
    for (; Entry != &Socket->RawDatapath->Interfaces; Entry = Entry->Flink) {
        CXPLAT_INTERFACE* Interface = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);
        if (Interface->IfIndex == (uint32_t)oif) {
            CXPLAT_DBG_ASSERT(sizeof(Interface->PhysicalAddress) == sizeof(Route->LocalLinkLayerAddress));
            CxPlatCopyMemory(&Route->LocalLinkLayerAddress, Interface->PhysicalAddress, sizeof(Route->LocalLinkLayerAddress));
            CxPlatDpRawAssignQueue(Interface, Route);
            break;
        }
    }

    // get remote mac
    Status = ResolveRemotePhysicalAddress(&NextHop, Route->NextHopLinkLayerAddress);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "ResolveRemotePhysicalAddress");
        return Status;
    }
    QuicTraceEvent(
        DatapathResoveShow,
        "[data][%p] Route resolution completed, local=%!ADDR!, remote=%!ADDR!, nexthop=%!ADDR!, iface=%d",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(NextHop), &NextHop),
        oif);

    CxPlatResolveRouteComplete(Context, Route, Route->NextHopLinkLayerAddress, PathId);

    return Status;
}

