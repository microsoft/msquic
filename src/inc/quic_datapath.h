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
// Different types of Explicit Congestion Notifications
//
typedef enum CXPLAT_ECN_TYPE {

    CXPLAT_ECN_NON_ECT = 0x0, // Non ECN-Capable Transport, Non-ECT
    CXPLAT_ECN_ECT_1   = 0x1, // ECN Capable Transport, ECT(1)
    CXPLAT_ECN_ECT_0   = 0x2, // ECN Capable Transport, ECT(0)
    CXPLAT_ECN_CE      = 0x3  // Congestion Encountered, CE

} CXPLAT_ECN_TYPE;

//
// Helper to get the ECN type from the Type of Service field of recieved data.
//
#define CXPLAT_ECN_FROM_TOS(ToS) (CXPLAT_ECN_TYPE)((ToS) & 0x3)

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
inline
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
inline
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
inline
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

//
// Represents a UDP or TCP abstraction.
//
typedef struct CXPLAT_SOCKET CXPLAT_SOCKET;

//
// Can be defined to whatever the client needs.
//
typedef struct CXPLAT_RECV_PACKET CXPLAT_RECV_PACKET;

//
// Structure that maintains the 'per send' context.
//
typedef struct CXPLAT_SEND_DATA CXPLAT_SEND_DATA;

//
// Contains a pointer and length.
//
typedef struct QUIC_BUFFER QUIC_BUFFER;

//
// Structure to represent data buffers received.
//
typedef struct CXPLAT_TUPLE {

    QUIC_ADDR RemoteAddress;
    QUIC_ADDR LocalAddress;

} CXPLAT_TUPLE;

//
// Structure to represent received UDP datagrams or TCP data.
//
typedef struct CXPLAT_RECV_DATA {

    //
    // The next receive data in the chain.
    //
    struct CXPLAT_RECV_DATA* Next;

    //
    // Contains the 4 tuple.
    //
    CXPLAT_TUPLE* Tuple;

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
    // Flags.
    //
    uint8_t Allocated : 1;          // Used for debugging. Set to FALSE on free.
    uint8_t QueuedOnConnection : 1; // Used for debugging.

} CXPLAT_RECV_DATA;

//
// Gets the corresponding receive data from its context pointer.
//
CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const RecvPacket
    );

//
// Gets the corresponding client context from its receive data pointer.
//
CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const RecvData
    );

//
// Function pointer type for datapath TCP accept callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_ACCEPT_CALLBACK)
void
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
    _Out_ CXPLAT_DATAPATH** NewDatapath
    );

//
// Closes a QUIC datapath handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* datapath
    );

#define CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING     0x0001
#define CXPLAT_DATAPATH_FEATURE_RECV_COALESCING       0x0002
#define CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION     0x0004

//
// Queries the currently supported features of the datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    );

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
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
// The following APIs are specific to a single UDP or TCP socket abstraction.
//

//
// Creates a UDP socket for the given (optional) local address and/or (optional)
// remote address. This function immediately registers for receive upcalls from
// the layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _In_ uint32_t InternalFlags,
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
// Deletes a socket. This function blocks on all outstandind upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    );

//
// Queries the locally bound interface's MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
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
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    );

//
// Allocates a new send context to be used to call QuicSocketSend. It
// can be freed with QuicSendDataFree too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
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
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t PartitionId
    );

//
// Sets a parameter on the socket.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketSetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t* Buffer
    );

//
// Sets a parameter on the socket.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketGetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t* Buffer
    );

#if defined(__cplusplus)
}
#endif
