/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "platform_internal.h"
#include "quic_hashtable.h"

typedef struct CXPLAT_SOCKET_POOL {

    CXPLAT_RW_LOCK Lock;
    CXPLAT_HASHTABLE Sockets;

} CXPLAT_SOCKET_POOL;


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

typedef struct CXPLAT_DATAPATH_RAW {
    const CXPLAT_DATAPATH *ParentDataPath;

    //
    // The Worker pool
    //
    CXPLAT_WORKER_POOL* WorkerPool;

    CXPLAT_SOCKET_POOL SocketPool;

    CXPLAT_ROUTE_RESOLUTION_WORKER* RouteResolutionWorker;

    CXPLAT_LIST_ENTRY Interfaces;

#if DEBUG
    BOOLEAN Uninitialized : 1;
    BOOLEAN Freed : 1;
#endif
    BOOLEAN ReserveAuxTcpSock; // Whether or not we create an auxiliary TCP socket.

} CXPLAT_DATAPATH_RAW;

#define ETH_MAC_ADDR_LEN 6

typedef struct CXPLAT_INTERFACE {
    CXPLAT_LIST_ENTRY Link;
    uint32_t IfIndex;
    uint32_t ActualIfIndex;
    uint8_t PhysicalAddress[ETH_MAC_ADDR_LEN];
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
    CXPLAT_SEND_DATA_COMMON;

    QUIC_BUFFER Buffer;

} CXPLAT_SEND_DATA;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRouteWorkerUninitialize(
    _In_ CXPLAT_ROUTE_RESOLUTION_WORKER* Worker
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathRouteWorkerInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* DataPath
    );

//
// Initializes the raw datapath stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    );

//
// Cleans up the raw datapath stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    );

//
// Called when the datapath is ready to be freed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitializeComplete(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    );

//
// Updates the datapath polling idle timeout.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    );

//
// Called on creation and deletion of a socket. It indicates to the raw datapath
// that it should update any filtering rules as necessary.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET_RAW* Socket,
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
    _In_ const CXPLAT_QUEUE* Queue
    );

//
// Returns whether the L3 (i.e., network) layer transmit checksum offload is
// enabled on the queue.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDpRawIsL3TxXsumOffloadedOnQueue(
    _In_ const CXPLAT_QUEUE* Queue
    );

//
// Returns whether the L3 (i.e., transport) layer transmit checksum offload is
// enabled on the queue.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDpRawIsL4TxXsumOffloadedOnQueue(
    _In_ const CXPLAT_QUEUE* Queue
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
    _In_ CXPLAT_ROUTE* Route
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
    _In_ const CXPLAT_DATAPATH_RAW* Datapath,
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
    _Inout_ CXPLAT_SEND_CONFIG* Config
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
// Sets the TX send object to have the specified L3 checksum offload settings.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxSetL3ChecksumOffload(
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Sets the TX send object to have the specified L4 checksum offload settings.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxSetL4ChecksumOffload(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN IsIpv6,
    _In_ BOOLEAN IsTcp,
    _In_ uint8_t L4HeaderLength
    );

//
// Raw Socket Interface
//

typedef struct CXPLAT_SOCKET_RAW {

    CXPLAT_HASHTABLE_ENTRY Entry;
    CXPLAT_RUNDOWN_REF RawRundown;
    CXPLAT_DATAPATH_RAW* RawDatapath;
    SOCKET AuxSocket;
    BOOLEAN Wildcard;                // Using a wildcard local address. Optimization
                                     // to avoid always reading LocalAddress.
    uint8_t CibirIdLength;           // CIBIR ID length. Value of 0 indicates CIBIR isn't used
    uint8_t CibirIdOffsetSrc;        // CIBIR ID offset in source CID
    uint8_t CibirIdOffsetDst;        // CIBIR ID offset in destination CID
    uint8_t CibirId[6];              // CIBIR ID data

    CXPLAT_SEND_DATA* PausedTcpSend; // Paused TCP send data *before* framing
    CXPLAT_SEND_DATA* CachedRstSend; // Cached TCP RST send data *after* framing

    CXPLAT_SOCKET;
} CXPLAT_SOCKET_RAW;

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
QUIC_INLINE
BOOLEAN
CxPlatSocketCompare(
    _In_ CXPLAT_SOCKET_RAW* Socket,
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
CXPLAT_SOCKET_RAW*
CxPlatGetSocket(
    _In_ const CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    );

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    );

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    );

//
// Network framing helpers. Used for Ethernet, IP (v4 & v6) and UDP.
//

typedef enum PACKET_TYPE {
    L3_TYPE_ICMPV4,
    L3_TYPE_ICMPV6,
    L4_TYPE_UDP,
    L4_TYPE_TCP,
    L4_TYPE_TCP_SYN,
    L4_TYPE_TCP_SYNACK,
    L4_TYPE_TCP_FIN,
} PACKET_TYPE;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketAckSyn(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ CXPLAT_RECV_DATA* Packet
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketSyn(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketAckFin(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ CXPLAT_RECV_DATA* Packet
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatFramingWriteHeaders(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _Inout_ CXPLAT_SEND_DATA* SendData,
    _Inout_ QUIC_BUFFER* Buffer,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint8_t DSCP,
    _In_ BOOLEAN SkipNetworkLayerXsum,
    _In_ BOOLEAN SkipTransportLayerXsum,
    _In_ uint32_t TcpSeqNum,
    _In_ uint32_t TcpAckNum,
    _In_ uint8_t TcpFlags
    );


//
// Ethernet / IP Framing Logic
//

#pragma pack(push)
#pragma pack(1)

typedef struct IPV6_EXTENSION {
    uint8_t NextHeader;
    uint8_t Length;
    uint16_t Reserved0;
    uint32_t Reserved1;
    uint8_t Data[0];
} IPV6_EXTENSION;

typedef struct UDP_HEADER {
    uint16_t SourcePort;
    uint16_t DestinationPort;
    uint16_t Length;
    uint16_t Checksum;
    uint8_t Data[0];
} UDP_HEADER;

typedef struct TCP_HEADER {
    uint16_t SourcePort;
    uint16_t DestinationPort;
    uint32_t SequenceNumber;
    uint32_t AckNumber;
    uint8_t X2           : 4;
    uint8_t HeaderLength : 4;
    uint8_t Flags;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t UrgentPointer;
} TCP_HEADER;

#pragma pack(pop)

//
// Constants for headers in wire format.
//

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define IPV4_VERSION 4
#define IPV4_VERSION_BYTE (IPV4_VERSION << 4)

#define IP_DEFAULT_HOP_LIMIT 128

#ifndef _KERNEL_MODE
typedef struct ETHERNET_HEADER {
    uint8_t Destination[6];
    uint8_t Source[6];
    uint16_t Type;
    uint8_t Data[0];
} ETHERNET_HEADER;

typedef struct IPV4_HEADER {
    uint8_t VersionAndHeaderLength;
    union {
        uint8_t TypeOfServiceAndEcnField;
        struct {
            uint8_t EcnField : 2;
            uint8_t TypeOfService : 6;
        };
    };
    uint16_t TotalLength;
    uint16_t Identification;
    uint16_t FlagsAndFragmentOffset;
    uint8_t TimeToLive;
    uint8_t Protocol;
    uint16_t HeaderChecksum;
    uint8_t Source[4];
    uint8_t Destination[4];
    uint8_t Data[0];
} IPV4_HEADER;

typedef struct IPV6_HEADER {
    uint32_t VersionClassEcnFlow;
    uint16_t PayloadLength;
    uint8_t NextHeader;
    uint8_t HopLimit;
    uint8_t Source[16];
    uint8_t Destination[16];
    uint8_t Data[0];
} IPV6_HEADER;

#define IPV6_VERSION 6
#define IPV4_DEFAULT_VERHLEN ((IPV4_VERSION_BYTE) | (sizeof(IPV4_HEADER) / sizeof(uint32_t)))

#define ETHERNET_TYPE_IPV4 0x0008
#define ETHERNET_TYPE_IPV6 0xdd86

#endif
