/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "quic_hashtable.h"

typedef struct CXPLAT_DATAPATH {

    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    CXPLAT_RW_LOCK SocketsLock;
    CXPLAT_HASHTABLE Sockets;

    uint16_t NextLocalPort;

    // Hacks - Eventually shouldn't be necessary
    uint8_t ServerMac[6];
    uint8_t ClientMac[6];
    QUIC_ADDR ServerIP;
    QUIC_ADDR ClientIP;

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
