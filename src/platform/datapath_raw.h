/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "quic_hashtable.h"

typedef struct CXPLAT_SOCKET_POOL {

    CXPLAT_RW_LOCK Lock;
    CXPLAT_HASHTABLE Sockets;
    uint16_t NextLocalPort;

} CXPLAT_SOCKET_POOL;

typedef struct CXPLAT_DATAPATH {

    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    CXPLAT_SOCKET_POOL SocketPool;

    // Hacks - Eventually shouldn't be necessary
    uint8_t ServerMac[6];
    uint8_t ClientMac[6];
    QUIC_ADDR ServerIP;
    QUIC_ADDR ClientIP;

    // RSS stuff
    uint16_t Cpu;
    uint8_t NumaNode;
    uint8_t CpuTableSize;
    uint16_t CpuTable[64];

} CXPLAT_DATAPATH;

typedef struct CXPLAT_SEND_DATA {

    QUIC_BUFFER Buffer;

} CXPLAT_SEND_DATA;

//
// Queries the raw datapath stack for the total size needed to allocate the
// datapath structure.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDapathSize(
    void
    );

//
// Initializes the raw datapath stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength
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
// Upcall from raw datapath to generate the CPU table used for RSS.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawGenerateCpuTable(
    _Inout_ CXPLAT_DATAPATH* Datapath
    );

//
// Upcall from raw datapath to allow for parsing of a received Ethernet packet.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
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
    _In_ CXPLAT_DATAPATH* Datapath,
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
    _In_ uint16_t MaxPacketSize
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
    void* CallbackContext;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;
    BOOLEAN Connected;  // Bound to a remote address

} CXPLAT_SOCKET;

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    );

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    );

uint16_t // Host byte order
CxPlatSockPoolGetNextLocalPort(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    );

//
// Finds a socket to deliver received packets with the given addresses.
//
CXPLAT_SOCKET*
CxPlatGetSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    );

BOOLEAN
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    );

void
CxPlatTryRemoveSocket(
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
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _Inout_ QUIC_BUFFER* Buffer
    );
