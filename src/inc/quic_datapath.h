/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for the data path used by the core QUIC
    library.

--*/

#pragma once

#include "quic_platform.h"

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:4214)  // nonstandard extension used: bit field types other than int

//
// The minimum IPv4 header size.
//
#define CXPLAT_MIN_IPV4_HEADER_SIZE 20

//
// The minimum IPv6 header size.
//
#define CXPLAT_MIN_IPV6_HEADER_SIZE 40

//
// The number of bytes in a UDP header.
//
#define CXPLAT_UDP_HEADER_SIZE 8

//
// The number of bytes in a TCP header.
//
#define CXPLAT_TCP_HEADER_SIZE 20

//
// The minimum and maximum ephemeral ports according to RFC 6335.
//
#define QUIC_ADDR_EPHEMERAL_PORT_MIN 49152
#define QUIC_ADDR_EPHEMERAL_PORT_MAX 65535

//
// Different types of Explicit Congestion Notifications
//
typedef enum CXPLAT_ECN_TYPE {

    CXPLAT_ECN_NON_ECT = 0x0, // Non ECN-Capable Transport, Non-ECT
    CXPLAT_ECN_ECT_1   = 0x1, // ECN Capable Transport, ECT(1)
    CXPLAT_ECN_ECT_0   = 0x2, // ECN Capable Transport, ECT(0)
    CXPLAT_ECN_CE      = 0x3  // Congestion Encountered, CE

} CXPLAT_ECN_TYPE;

//
// Different DiffServ Code Points
//
typedef enum CXPLAT_DSCP_TYPE {

    CXPLAT_DSCP_CS0 = 0,
    CXPLAT_DSCP_LE  = 1,
    CXPLAT_DSCP_CS1 = 8,
    CXPLAT_DSCP_CS2 = 16,
    CXPLAT_DSCP_CS3 = 24,
    CXPLAT_DSCP_CS4 = 32,
    CXPLAT_DSCP_CS5 = 40,
    CXPLAT_DSCP_EF  = 46,

} CXPLAT_DSCP_TYPE;

//
// Helper to get the ECN type from the Type of Service field of received data.
//
#define CXPLAT_ECN_FROM_TOS(ToS) (CXPLAT_ECN_TYPE)((ToS) & 0x3)

//
// Helper to get the DSCP value from the Type of Service field of received data.
//
#define CXPLAT_DSCP_FROM_TOS(ToS) (uint8_t)((ToS) >> 2)

//
// Define the maximum type of service value allowed.
// Note: this is without the ECN bits included
//
#define CXPLAT_MAX_DSCP 63

//
// The maximum IP MTU this implementation supports for QUIC.
//
#define CXPLAT_MAX_MTU 1500

//
// The buffer size that must be allocated to fit the maximum UDP payload we
// support.
//
#define MAX_UDP_PAYLOAD_LENGTH (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE)

//
// Helper function for calculating the length of a UDP packet, for a given
// MTU, on a dual-mode socket. It uses IPv4 header size since that is the
// least limiting as far as making sure enough space is allocated. An IPv6
// UDP payload can still fit in a buffer allocated for IPv4, but not the
// reverse.
//
QUIC_INLINE
uint16_t
MaxUdpPayloadSizeFromMTU(
    _In_ uint16_t Mtu
    )
{
    return  Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
}

//
// Helper function for calculating the length of UDP payload, given the address
// family and MTU.
//
QUIC_INLINE
uint16_t
MaxUdpPayloadSizeForFamily(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ uint16_t Mtu
    )
{
    return Family == QUIC_ADDRESS_FAMILY_INET ?
        Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE :
        Mtu - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
}

//
// Helper function for calculating the MTU, given the length of UDP payload and
// the address family.
//
QUIC_INLINE
uint16_t
PacketSizeFromUdpPayloadSize(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ uint16_t UdpPayloadSize
    )
{
    uint32_t PayloadSize = Family == QUIC_ADDRESS_FAMILY_INET ?
        UdpPayloadSize + CXPLAT_MIN_IPV4_HEADER_SIZE + CXPLAT_UDP_HEADER_SIZE :
        UdpPayloadSize + CXPLAT_MIN_IPV6_HEADER_SIZE + CXPLAT_UDP_HEADER_SIZE;
    if (PayloadSize > UINT16_MAX) {
        PayloadSize = UINT16_MAX;
    }
    return (uint16_t)PayloadSize;
}

//
// The top level datapath handle type.
//
typedef struct CXPLAT_DATAPATH CXPLAT_DATAPATH;
typedef struct CXPLAT_DATAPATH_RAW CXPLAT_DATAPATH_RAW;

//
// Represents a UDP or TCP abstraction.
//
typedef struct CXPLAT_SOCKET CXPLAT_SOCKET;

//
// Structure that maintains the 'per send' context.
//
typedef struct CXPLAT_SEND_DATA CXPLAT_SEND_DATA;

//
// Contains a pointer and length.
//
typedef struct QUIC_BUFFER QUIC_BUFFER;

typedef enum CXPLAT_ROUTE_STATE {
    RouteUnresolved,
    RouteResolving,
    RouteSuspected,
    RouteResolved,
} CXPLAT_ROUTE_STATE;

typedef struct CXPLAT_RAW_TCP_STATE {
    BOOLEAN Syncd;
    //
    // All numbers are in host order.
    //
    uint32_t AckNumber;
    uint32_t SequenceNumber;
} CXPLAT_RAW_TCP_STATE;

//
// An opaque queue type. Each queue is associated with a single RSS queue on a
// single interface.
//
typedef struct CXPLAT_QUEUE CXPLAT_QUEUE;

//
// Structure to represent a network route.
//
typedef struct CXPLAT_ROUTE {

    CXPLAT_QUEUE* Queue;

    QUIC_ADDR RemoteAddress;
    QUIC_ADDR LocalAddress;

    uint8_t LocalLinkLayerAddress[6];
    uint8_t NextHopLinkLayerAddress[6];

    uint16_t DatapathType: 15; // CXPLAT_DATAPATH_TYPE
    uint8_t UseQTIP: 1;        // TRUE if the route is using QTIP

    //
    // QuicCopyRouteInfo copies memory up to this point (not including State).
    //

    CXPLAT_ROUTE_STATE State;
    CXPLAT_RAW_TCP_STATE TcpState;

} CXPLAT_ROUTE;

//
// Structure to represent received UDP datagrams or TCP data.
//
typedef struct CXPLAT_RECV_DATA {

    //
    // The next receive data in the chain.
    //
    struct CXPLAT_RECV_DATA* Next;

    //
    // Contains the network route.
    //
    CXPLAT_ROUTE* Route;

    //
    // The data buffer containing the received bytes.
    //
    _Field_size_(BufferLength)
    uint8_t* Buffer;

    //
    // Length of the valid data in Buffer.
    //
    uint16_t BufferLength;

    //
    // The partition ID of the received data.
    //
    uint16_t PartitionIndex;

    //
    // The Type of Service (ToS) field of the IPv4 header or Traffic Class field
    // of the IPv6 header.
    //
    uint8_t TypeOfService;

    //
    // TTL Hoplimit field of the IP header of the received packet on handshake.
    //
    uint8_t HopLimitTTL;

    //
    // Flags.
    //
    uint16_t Allocated : 1;          // Used for debugging. Set to FALSE on free.
    uint16_t QueuedOnConnection : 1; // Used for debugging.
    uint16_t DatapathType : 2;       // CXPLAT_DATAPATH_TYPE
    uint16_t Reserved : 4;           // PACKET_TYPE (at least 3 bits)
    uint16_t ReservedEx : 8;         // Header length

    //
    // Variable length data (of size `ClientRecvContextLength` passed into
    // CxPlatDataPathInitialize) directly follows.
    //

} CXPLAT_RECV_DATA;

//
// QUIC Encryption Offload (QEO) interfaces
//

typedef enum CXPLAT_QEO_OPERATION {
    CXPLAT_QEO_OPERATION_ADD,     // Add (or modify) a QUIC connection offload
    CXPLAT_QEO_OPERATION_REMOVE,  // Remove a QUIC connection offload
} CXPLAT_QEO_OPERATION;

typedef enum CXPLAT_QEO_DIRECTION {
    CXPLAT_QEO_DIRECTION_TRANSMIT, // An offload for the transmit path
    CXPLAT_QEO_DIRECTION_RECEIVE,  // An offload for the receive path
} CXPLAT_QEO_DIRECTION;

typedef enum CXPLAT_QEO_DECRYPT_FAILURE_ACTION {
    CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,     // Drop the packet on decryption failure
    CXPLAT_QEO_DECRYPT_FAILURE_ACTION_CONTINUE, // Continue and pass the packet up on decryption failure
} CXPLAT_QEO_DECRYPT_FAILURE_ACTION;

typedef enum CXPLAT_QEO_CIPHER_TYPE {
    CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_128_GCM,
    CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
    CXPLAT_QEO_CIPHER_TYPE_AEAD_CHACHA20_POLY1305,
    CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_128_CCM,
} CXPLAT_QEO_CIPHER_TYPE;

typedef struct CXPLAT_QEO_CONNECTION {
    uint32_t Operation            : 1;  // CXPLAT_QEO_OPERATION
    uint32_t Direction            : 1;  // CXPLAT_QEO_DIRECTION
    uint32_t DecryptFailureAction : 1;  // CXPLAT_QEO_DECRYPT_FAILURE_ACTION
    uint32_t KeyPhase             : 1;
    uint32_t RESERVED             : 12; // Must be set to 0. Don't read.
    uint32_t CipherType           : 16; // CXPLAT_QEO_CIPHER_TYPE
    uint64_t NextPacketNumber;
    QUIC_ADDR Address;
    uint8_t ConnectionIdLength;
    uint8_t ConnectionId[20]; // QUIC v1 and v2 max CID size
    uint8_t PayloadKey[32];   // Length determined by CipherType
    uint8_t HeaderKey[32];    // Length determined by CipherType
    uint8_t PayloadIv[12];
} CXPLAT_QEO_CONNECTION;

//
// Function pointer type for datapath TCP accept callbacks.
// Any QUIC_FAILED status will reject the connection.
// Do not call CxPlatSocketDelete from this callback, it will
// crash.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
QUIC_STATUS
(CXPLAT_DATAPATH_ACCEPT_CALLBACK)(
    _In_ CXPLAT_SOCKET* ListenerSocket,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    );

typedef CXPLAT_DATAPATH_ACCEPT_CALLBACK *CXPLAT_DATAPATH_ACCEPT_CALLBACK_HANDLER;

//
// Function pointer type for datapath TCP connect/disconnect callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_CONNECT_CALLBACK)
void
(CXPLAT_DATAPATH_CONNECT_CALLBACK)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ BOOLEAN Connected
    );

typedef CXPLAT_DATAPATH_CONNECT_CALLBACK *CXPLAT_DATAPATH_CONNECT_CALLBACK_HANDLER;

//
// Function pointer type for datapath TCP send completion callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK)
void
(CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_ uint32_t ByteCount
    );

typedef CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK *CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK_HANDLER;

//
// Function pointer type for datapath receive callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
(CXPLAT_DATAPATH_RECEIVE_CALLBACK)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    );

typedef CXPLAT_DATAPATH_RECEIVE_CALLBACK *CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER;

//
// Function pointer type for datapath port unreachable callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ const QUIC_ADDR* RemoteAddress
    );

typedef CXPLAT_DATAPATH_UNREACHABLE_CALLBACK *CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER;

//
// UDP Callback function pointers used by the datapath.
//
typedef struct CXPLAT_UDP_DATAPATH_CALLBACKS {

    CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER Receive;
    CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER Unreachable;

} CXPLAT_UDP_DATAPATH_CALLBACKS;

//
// TCP Callback function pointers used by the datapath.
//
typedef struct CXPLAT_TCP_DATAPATH_CALLBACKS {

    CXPLAT_DATAPATH_ACCEPT_CALLBACK_HANDLER Accept;
    CXPLAT_DATAPATH_CONNECT_CALLBACK_HANDLER Connect;
    CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER Receive;
    CXPLAT_DATAPATH_SEND_COMPLETE_CALLBACK_HANDLER SendComplete;

} CXPLAT_TCP_DATAPATH_CALLBACKS;

typedef enum CXPLAT_DATAPATH_FEATURES {
    CXPLAT_DATAPATH_FEATURE_NONE               = 0x00000000,
    CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING  = 0x00000001,
    CXPLAT_DATAPATH_FEATURE_RECV_COALESCING    = 0x00000002,
    CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION  = 0x00000004,
    CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING = 0x00000008,
    CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS  = 0x00000010,
    CXPLAT_DATAPATH_FEATURE_TCP                = 0x00000020,
    CXPLAT_DATAPATH_FEATURE_RAW                = 0x00000040,
    CXPLAT_DATAPATH_FEATURE_TTL                = 0x00000080,
    CXPLAT_DATAPATH_FEATURE_SEND_DSCP          = 0x00000100,
    CXPLAT_DATAPATH_FEATURE_RIO                = 0x00000200,
    CXPLAT_DATAPATH_FEATURE_RECV_DSCP          = 0x00000400,
} CXPLAT_DATAPATH_FEATURES;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_DATAPATH_FEATURES)

typedef enum CXPLAT_SOCKET_FLAGS {
    CXPLAT_SOCKET_FLAG_NONE     = 0x00000000,
    CXPLAT_SOCKET_FLAG_PCP      = 0x00000001, // Socket is used for internal PCP support
    CXPLAT_SOCKET_FLAG_SHARE    = 0x00000002, // Forces sharing of the address and port
    CXPLAT_SOCKET_SERVER_OWNED  = 0x00000004, // Indicates socket is a listener socket
    CXPLAT_SOCKET_FLAG_XDP      = 0x00000008, // Socket will use XDP
    CXPLAT_SOCKET_FLAG_QTIP     = 0x00000010, // Socket will use QTIP
    CXPLAT_SOCKET_FLAG_RIO      = 0x00000020, // Socket will use RIO
} CXPLAT_SOCKET_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_SOCKET_FLAGS)

//
// Function pointer type for send complete callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE)
void
(CXPLAT_DATAPATH_SEND_COMPLETE)(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* ClientContext,
    _In_ QUIC_STATUS CompletionStatus,
    _In_ uint32_t NumBytesSent
    );

typedef CXPLAT_DATAPATH_SEND_COMPLETE *CXPLAT_DATAPATH_SEND_COMPLETE_HANDLER;

//
// Opens a new handle to the QUIC datapath.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Out_ CXPLAT_DATAPATH** NewDatapath
    );

//
// Closes a QUIC datapath handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    );

//
// Updates the polling idle timeout of a datapath.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    );

//
// Queries the currently supported features of the datapath for the given type
// of socket.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_FEATURES
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_FLAGS SocketFlags
    );

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Resolves a hostname to an IP address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    );

//
// Values from RFC 2863
//
typedef enum CXPLAT_OPERATION_STATUS {
    CXPLAT_OPERATION_STATUS_UP = 1,
    CXPLAT_OPERATION_STATUS_DOWN,
    CXPLAT_OPERATION_STATUS_TESTING,
    CXPLAT_OPERATION_STATUS_UNKNOWN,
    CXPLAT_OPERATION_STATUS_DORMANT,
    CXPLAT_OPERATION_STATUS_NOT_PRESENT,
    CXPLAT_OPERATION_STATUS_LOWER_LAYER_DOWN
} CXPLAT_OPERATION_STATUS;

#define CXPLAT_IF_TYPE_SOFTWARE_LOOPBACK    24

typedef struct CXPLAT_ADAPTER_ADDRESS {
    QUIC_ADDR Address;
    uint32_t InterfaceIndex;
    uint16_t InterfaceType;
    CXPLAT_OPERATION_STATUS OperationStatus;
} CXPLAT_ADAPTER_ADDRESS;

//
// Gets info on the list of local IP addresses.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    );

//
// Gets the list of Gateway server addresses.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    );

//
// The following APIs are specific to a single UDP or TCP socket abstraction.
//
typedef struct CXPLAT_UDP_CONFIG {
    const QUIC_ADDR* LocalAddress;      // optional
    const QUIC_ADDR* RemoteAddress;     // optional
    CXPLAT_SOCKET_FLAGS Flags;
    uint32_t InterfaceIndex;            // 0 means any/all
    uint16_t PartitionIndex;            // Client-only
    void* CallbackContext;              // optional
#ifdef QUIC_COMPARTMENT_ID
    QUIC_COMPARTMENT_ID CompartmentId;  // optional
#endif
#ifdef QUIC_OWNING_PROCESS
    QUIC_PROCESS OwningProcess;         // Kernel client-only
#endif

    // used for RAW datapath
    uint8_t CibirIdLength;              // CIBIR ID length. Value of 0 indicates CIBIR isn't used
    uint8_t CibirIdOffsetSrc;           // CIBIR ID offset in source CID
    uint8_t CibirIdOffsetDst;           // CIBIR ID offset in destination CID
    uint8_t CibirId[6];                 // CIBIR ID data
} CXPLAT_UDP_CONFIG;

//
// Creates a UDP socket for the given (optional) local address and/or (optional)
// remote address. This function immediately registers for receive upcalls from
// the layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** Socket
    );

//
// Creates a TCP socket for the given (optional) local address and (required)
// remote address. This function immediately registers for upcalls from the
// layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    );

//
// Creates a TCP listener socket for the given (optional) local address. This
// function immediately registers for accept upcalls from the layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    );

//
// Deletes a socket. This function blocks on all outstanding upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    );

//
// Plumbs new or removes existing QUIC encryption offload information.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketUpdateQeo(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    );

//
// Queries the locally bound interface's MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ROUTE* Route
    );

//
// Queries the locally bound IP address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

//
// Queries the connected remote IP address. Only valid if the socket was
// initially created with a remote address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

//
// Queries a raw socket availability.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSocketRawSocketAvailable(
    _In_ CXPLAT_SOCKET* Socket
    );

//
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    );

typedef enum CXPLAT_SEND_FLAGS {
    CXPLAT_SEND_FLAGS_NONE = 0,
    CXPLAT_SEND_FLAGS_MAX_THROUGHPUT = 1,
} CXPLAT_SEND_FLAGS;

typedef struct CXPLAT_SEND_CONFIG {
    CXPLAT_ROUTE* Route;
    uint16_t MaxPacketSize;
    uint8_t ECN; // CXPLAT_ECN_TYPE
    uint8_t Flags; // CXPLAT_SEND_FLAGS
    uint8_t DSCP; // CXPLAT_DSCP_TYPE
} CXPLAT_SEND_CONFIG;

//
// Allocates a new send context to be used to call QuicSocketSend. It
// can be freed with QuicSendDataFree too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    );

//
// Frees a send context returned from a previous call to QuicSendDataAlloc.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Allocates a new data buffer for sending.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    );

//
// Frees a data buffer returned from a previous call to QuicSendDataAllocBuffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    );

//
// Returns whether the send context buffer limit has been reached.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Sends the data over the socket.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    );

typedef struct CXPLAT_TCP_STATISTICS { // Mostly copied from TCP_INFO_v1 for now
    uint32_t Mss;
    uint64_t ConnectionTimeMs;
    BOOLEAN TimestampsEnabled;
    uint32_t RttUs;
    uint32_t MinRttUs;
    uint32_t BytesInFlight;
    uint32_t Cwnd;
    uint32_t SndWnd;
    uint32_t RcvWnd;
    uint32_t RcvBuf;
    uint64_t BytesOut;
    uint64_t BytesIn;
    uint32_t BytesReordered;
    uint32_t BytesRetrans;
    uint32_t FastRetrans;
    uint32_t DupAcksIn;
    uint32_t TimeoutEpisodes;
    uint8_t SynRetrans;
    uint32_t SndLimTransRwin;
    uint32_t SndLimTimeRwin;
    uint64_t SndLimBytesRwin;
    uint32_t SndLimTransCwnd;
    uint32_t SndLimTimeCwnd;
    uint64_t SndLimBytesCwnd;
    uint32_t SndLimTransSnd;
    uint32_t SndLimTimeSnd;
    uint64_t SndLimBytesSnd;
} CXPLAT_TCP_STATISTICS;

//
// Queries socket statistics.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketGetTcpStatistics(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ CXPLAT_TCP_STATISTICS* Statistics
    );

//
// Function pointer type for datapath route resolution callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_ROUTE_RESOLUTION_CALLBACK)
void
(CXPLAT_ROUTE_RESOLUTION_CALLBACK)(
    _Inout_ void* Context,
    _When_(Succeeded == FALSE, _Reserved_)
    _When_(Succeeded == TRUE, _In_reads_bytes_(6))
        const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    );

typedef CXPLAT_ROUTE_RESOLUTION_CALLBACK *CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER;
typedef struct QUIC_CONNECTION QUIC_CONNECTION;

//
// Copies L2 address into route object and sets route state to resolved.
//
void
CxPlatResolveRouteComplete(
    _In_ void* Context,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    );

//
// Tries to resolve route and neighbor for the given destination address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatResolveRoute(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    );

//
// Get the RSS Configuration of the interface.
//
typedef enum CXPLAT_RSS_HASH_TYPE {
    CXPLAT_RSS_HASH_TYPE_IPV4        = 0x001,
    CXPLAT_RSS_HASH_TYPE_TCP_IPV4    = 0x002,
    CXPLAT_RSS_HASH_TYPE_UDP_IPV4    = 0x004,
    CXPLAT_RSS_HASH_TYPE_IPV6        = 0x008,
    CXPLAT_RSS_HASH_TYPE_TCP_IPV6    = 0x010,
    CXPLAT_RSS_HASH_TYPE_UDP_IPV6    = 0x020,
    CXPLAT_RSS_HASH_TYPE_IPV6_EX     = 0x040,
    CXPLAT_RSS_HASH_TYPE_TCP_IPV6_EX = 0x080,
    CXPLAT_RSS_HASH_TYPE_UDP_IPV6_EX = 0x100
} CXPLAT_RSS_HASH_TYPE;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_RSS_HASH_TYPE)

typedef struct CXPLAT_RSS_CONFIG {
    CXPLAT_RSS_HASH_TYPE HashTypes;
    uint32_t RssSecretKeyLength;
    uint32_t RssIndirectionTableCount;
    _Field_size_bytes_(RssSecretKeyLength)
    uint8_t* RssSecretKey;
    _Field_size_(RssIndirectionTableCount)
    uint32_t* RssIndirectionTable;      // Converted to processor indices from platform-specific representation.
} CXPLAT_RSS_CONFIG;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathRssConfigGet(
    _In_ uint32_t InterfaceIndex,
    _Outptr_ _At_(*RssConfig, __drv_allocatesMem(Mem))
        CXPLAT_RSS_CONFIG** RssConfig
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRssConfigFree(
    _In_ CXPLAT_RSS_CONFIG* RssConfig
    );

#if defined(__cplusplus)
}
#endif
