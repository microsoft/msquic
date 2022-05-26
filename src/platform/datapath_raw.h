/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "quic_hashtable.h"

typedef struct CXPLAT_SOCKET_POOL {

    CXPLAT_RW_LOCK Lock;
    CXPLAT_HASHTABLE Sockets;

} CXPLAT_SOCKET_POOL;

typedef struct CXPLAT_DATAPATH CXPLAT_DATAPATH;

//
// A worker thread for draining queued route resolution operations.
//
typedef struct QUIC_CACHEALIGN CXPLAT_ROUTE_RESOLUTION_WORKER {
    //
    // TRUE if the worker is currently running.
    //
    BOOLEAN Enabled;

    //
    // An event to kick the thread.
    //
    CXPLAT_EVENT Ready;

    CXPLAT_THREAD Thread;
    CXPLAT_POOL OperationPool;

    //
    // Serializes access to the route resolution opreations.
    //
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_LIST_ENTRY Operations;
} CXPLAT_ROUTE_RESOLUTION_WORKER;

typedef struct CXPLAT_ROUTE_RESOLUTION_OPERATION {
    //
    // Link in the worker's operation queue.
    // N.B. Multi-threaded access, synchronized by worker's operation lock.
    //
    CXPLAT_LIST_ENTRY WorkerLink;
    MIB_IPNET_ROW2 IpnetRow;
    void* Context;
    uint8_t PathId;
    CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback;
} CXPLAT_ROUTE_RESOLUTION_OPERATION;

typedef struct CXPLAT_DATAPATH {

    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    CXPLAT_SOCKET_POOL SocketPool;

    CXPLAT_ROUTE_RESOLUTION_WORKER* RouteResolutionWorker;

    CXPLAT_LIST_ENTRY Interfaces;

    //
    // Rundown for waiting on binding cleanup.
    //
    CXPLAT_RUNDOWN_REF SocketsRundown;

} CXPLAT_DATAPATH;

#define ETH_MAC_ADDR_LEN 6

typedef struct CXPLAT_INTERFACE {
    CXPLAT_LIST_ENTRY Link;
    uint32_t IfIndex;
    UCHAR PhysicalAddress[ETH_MAC_ADDR_LEN];
    struct {
        struct {
            BOOLEAN NetworkLayerXsum : 1;
            BOOLEAN TransportLayerXsum : 1;
        } Transmit;
        struct {
            BOOLEAN NetworkLayerXsum : 1;
            BOOLEAN TransportLayerXsum : 1;
        } Receive;
    } OffloadStatus;
} CXPLAT_INTERFACE;

typedef struct CXPLAT_SEND_DATA {

    //
    // The type of ECN markings needed for send.
    //
    CXPLAT_ECN_TYPE ECN;

    QUIC_BUFFER Buffer;

} CXPLAT_SEND_DATA;

//
// Queries the raw datapath stack for the total size needed to allocate the
// datapath structure.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_opt_ const CXPLAT_DATAPATH_CONFIG* Config
    );

//
// Initializes the raw datapath stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_DATAPATH_CONFIG* Config
    );

//
// Cleans up the raw datapath stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    );

//
// Called on creation and deletion of a socket. It indicates to the raw datapath
// that it should update any filtering rules as necessary.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ BOOLEAN IsCreated
    );

//
// Assigns a raw datapath queue to a new route.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawAssignQueue(
    _In_ const CXPLAT_INTERFACE* Interface,
    _Inout_ CXPLAT_ROUTE* Route
    );

//
// Returns the raw interface for a given queue.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
const CXPLAT_INTERFACE*
CxPlatDpRawGetInterfaceFromQueue(
    _In_ const void* Queue
    );

typedef struct HEADER_BACKFILL {
    uint16_t TransportLayer;
    uint16_t NetworkLayer;
    uint16_t LinkLayer;
    uint16_t AllLayer; // Sum of the above three.
} HEADER_BACKFILL;

//
// Calculate how much space we should reserve for headers.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
HEADER_BACKFILL
CxPlatDpRawCalculateHeaderBackFill(
    _In_ QUIC_ADDRESS_FAMILY Family
    );

//
// Upcall from raw datapath to indicate a received chain of packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawParseEthernet(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    );

//
// Upcall from raw datapath to indicate a received chain of packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxEthernet(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _In_reads_(PacketCount)
        CXPLAT_RECV_DATA** Packets,
    _In_ uint16_t PacketCount
    );

//
// Frees a chain of previous received packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    );

//
// Allocates a new TX send object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize,
    _Inout_ CXPLAT_ROUTE* Route
    );

//
// Frees a previously allocated TX send object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Enqueues a TX send object to be sent out on the raw datapath device.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Raw Socket Interface
//

typedef struct CXPLAT_SOCKET {

    CXPLAT_HASHTABLE_ENTRY Entry;
    CXPLAT_RUNDOWN_REF Rundown;
    CXPLAT_DATAPATH* Datapath;
    SOCKET AuxSocket;
    void* CallbackContext;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;
    BOOLEAN Wildcard;           // Using a wildcard local address. Optimization
                                // to avoid always reading LocalAddress.
    BOOLEAN Connected;          // Bound to a remote address
    uint8_t CibirIdLength;      // CIBIR ID length. Value of 0 indicates CIBIR isn't used
    uint8_t CibirIdOffsetSrc;   // CIBIR ID offset in source CID
    uint8_t CibirIdOffsetDst;   // CIBIR ID offset in destination CID
    uint8_t CibirId[6];         // CIBIR ID data

} CXPLAT_SOCKET;

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    );

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    );

//
// Returns TRUE if the socket matches the given addresses. This code is used in
// conjunction with the hash table lookup, which already compares local UDP port
// so it assumes that matches already.
//
inline
BOOL
CxPlatSocketCompare(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    CXPLAT_DBG_ASSERT(QuicAddrGetPort(&Socket->LocalAddress) == QuicAddrGetPort(LocalAddress));
    if (Socket->Wildcard) {
        return TRUE; // The local port match is all that is needed.
    }

    //
    // Make sure the local IP matches and the full remote address matches.
    //
    CXPLAT_DBG_ASSERT(Socket->Connected);
    return
        QuicAddrCompareIp(&Socket->LocalAddress, LocalAddress) &&
        QuicAddrCompare(&Socket->RemoteAddress, RemoteAddress);
}

//
// Finds a socket to deliver received packets with the given addresses.
//
CXPLAT_SOCKET*
CxPlatGetSocket(
    _In_ const CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    );

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    );

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    );

//
// Network framing helpers. Used for Ethernet, IP (v4 & v6) and UDP.
//

typedef enum PACKET_TYPE {
    L3_TYPE_ICMPV4,
    L3_TYPE_ICMPV6,
    L4_TYPE_TCP,
    L4_TYPE_UDP,
} PACKET_TYPE;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatFramingWriteHeaders(
    _In_ const CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _Inout_ QUIC_BUFFER* Buffer,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ BOOLEAN SkipNetworkLayerXsum,
    _In_ BOOLEAN SkipTransportLayerXsum
    );
