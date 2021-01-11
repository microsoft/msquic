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
#define QUIC_MIN_IPV4_HEADER_SIZE 20

//
// The minimum IPv6 header size.
//
#define QUIC_MIN_IPV6_HEADER_SIZE 40

//
// The number of bytes in a UDP header.
//
#define QUIC_UDP_HEADER_SIZE 8

//
// Different types of Explicit Congestion Notifications
//
typedef enum QUIC_ECN_TYPE {

    QUIC_ECN_NON_ECT = 0x0, // Non ECN-Capable Transport, Non-ECT
    QUIC_ECN_ECT_1   = 0x1, // ECN Capable Transport, ECT(1)
    QUIC_ECN_ECT_0   = 0x2, // ECN Capable Transport, ECT(0)
    QUIC_ECN_CE      = 0x3  // Congestion Encountered, CE

} QUIC_ECN_TYPE;

//
// Helper to get the ECN type from the Type of Service field of recieved data.
//
#define QUIC_ECN_FROM_TOS(ToS) (QUIC_ECN_TYPE)((ToS) & 0x3)

//
// The maximum IP MTU this implementation supports for QUIC.
//
#define QUIC_MAX_MTU 1500

//
// The buffer size that must be allocated to fit the maximum UDP payload we
// support.
//
#define MAX_UDP_PAYLOAD_LENGTH (QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE)

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
    return  Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
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
        Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE :
        Mtu - QUIC_MIN_IPV6_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
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
    return Family == QUIC_ADDRESS_FAMILY_INET ?
        UdpPayloadSize + QUIC_MIN_IPV4_HEADER_SIZE + QUIC_UDP_HEADER_SIZE :
        UdpPayloadSize + QUIC_MIN_IPV6_HEADER_SIZE + QUIC_UDP_HEADER_SIZE;
}

//
// The top level datapath handle type.
//
typedef struct QUIC_DATAPATH QUIC_DATAPATH;

//
// Represents a UDP or TCP abstraction.
//
typedef struct QUIC_SOCKET QUIC_SOCKET;

//
// Can be defined to whatever the client needs.
//
typedef struct QUIC_RECV_PACKET QUIC_RECV_PACKET;

//
// Structure that maintains the 'per send' context.
//
typedef struct QUIC_SEND_DATA QUIC_SEND_DATA;

//
// Contains a pointer and length.
//
typedef struct QUIC_BUFFER QUIC_BUFFER;

//
// Structure to represent data buffers received.
//
typedef struct QUIC_TUPLE {

    QUIC_ADDR RemoteAddress;
    QUIC_ADDR LocalAddress;

} QUIC_TUPLE;

//
// Structure to represent received UDP datagrams or TCP data.
//
typedef struct QUIC_RECV_DATA {

    //
    // The next receive data in the chain.
    //
    struct QUIC_RECV_DATA* Next;

    //
    // Contains the 4 tuple.
    //
    QUIC_TUPLE* Tuple;

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

} QUIC_RECV_DATA;

//
// Gets the corresponding receive data from its context pointer.
//
QUIC_RECV_DATA*
QuicDataPathRecvPacketToRecvData(
    _In_ const QUIC_RECV_PACKET* const RecvPacket
    );

//
// Gets the corresponding client context from its receive data pointer.
//
QUIC_RECV_PACKET*
QuicDataPathRecvDataToRecvPacket(
    _In_ const QUIC_RECV_DATA* const RecvData
    );

//
// Function pointer type for datapath TCP accept callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_ACCEPT_CALLBACK)
void
(QUIC_DATAPATH_ACCEPT_CALLBACK)(
    _In_ QUIC_SOCKET* ListenerSocket,
    _In_ void* ListenerContext,
    _In_ QUIC_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    );

typedef QUIC_DATAPATH_ACCEPT_CALLBACK *QUIC_DATAPATH_ACCEPT_CALLBACK_HANDLER;

//
// Function pointer type for datapath TCP connect/disconnect callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_CONNECT_CALLBACK)
void
(QUIC_DATAPATH_CONNECT_CALLBACK)(
    _In_ QUIC_SOCKET* Socket,
    _In_ void* Context,
    _In_ BOOLEAN Connected
    );

typedef QUIC_DATAPATH_CONNECT_CALLBACK *QUIC_DATAPATH_CONNECT_CALLBACK_HANDLER;

//
// Function pointer type for datapath receive callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
void
(QUIC_DATAPATH_RECEIVE_CALLBACK)(
    _In_ QUIC_SOCKET* Socket,
    _In_ void* Context,
    _In_ QUIC_RECV_DATA* RecvDataChain
    );

typedef QUIC_DATAPATH_RECEIVE_CALLBACK *QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER;

//
// Function pointer type for datapath port unreachable callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_UNREACHABLE_CALLBACK)
void
(QUIC_DATAPATH_UNREACHABLE_CALLBACK)(
    _In_ QUIC_SOCKET* Socket,
    _In_ void* Context,
    _In_ const QUIC_ADDR* RemoteAddress
    );

typedef QUIC_DATAPATH_UNREACHABLE_CALLBACK *QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER;

//
// UDP Callback function pointers used by the datapath.
//
typedef struct QUIC_UDP_DATAPATH_CALLBACKS {

    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER Receive;
    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER Unreachable;

} QUIC_UDP_DATAPATH_CALLBACKS;

//
// TCP Callback function pointers used by the datapath.
//
typedef struct QUIC_TCP_DATAPATH_CALLBACKS {

    QUIC_DATAPATH_ACCEPT_CALLBACK_HANDLER Accept;
    QUIC_DATAPATH_CONNECT_CALLBACK_HANDLER Connect;
    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER Receive;

} QUIC_TCP_DATAPATH_CALLBACKS;

//
// Function pointer type for send complete callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_SEND_COMPLETE)
void
(QUIC_DATAPATH_SEND_COMPLETE)(
    _In_ QUIC_SOCKET* Socket,
    _In_ void* ClientContext,
    _In_ QUIC_STATUS CompletionStatus,
    _In_ uint32_t NumBytesSent
    );

typedef QUIC_DATAPATH_SEND_COMPLETE *QUIC_DATAPATH_SEND_COMPLETE_HANDLER;

//
// Opens a new handle to the QUIC datapath.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const QUIC_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const QUIC_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ QUIC_DATAPATH** NewDatapath
    );

//
// Closes a QUIC datapath handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* datapath
    );

#define QUIC_DATAPATH_FEATURE_RECV_SIDE_SCALING     0x0001
#define QUIC_DATAPATH_FEATURE_RECV_COALESCING       0x0002
#define QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION     0x0004

//
// Queries the currently supported features of the datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    );

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    );

//
// Resolves a hostname to an IP address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
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
QuicSocketCreateUdp(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_SOCKET** Socket
    );

//
// Creates a TCP socket for the given (optional) local address and (required)
// remote address. This function immediately registers for upcalls from the
// layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketCreateTcp(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_SOCKET** Socket
    );

//
// Creates a TCP listener socket for the given (optional) local address. This
// function immediately registers for accept upcalls from the layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketCreateTcpListener(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_SOCKET** Socket
    );

//
// Deletes a socket. This function blocks on all outstandind upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSocketDelete(
    _In_ QUIC_SOCKET* Socket
    );

//
// Queries the locally bound interface's MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicSocketGetLocalMtu(
    _In_ QUIC_SOCKET* Socket
    );

//
// Queries the locally bound IP address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSocketGetLocalAddress(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

//
// Queries the connected remote IP address. Only valid if the socket was
// initially created with a remote address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSocketGetRemoteAddress(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    );

//
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvDataReturn(
    _In_opt_ QUIC_RECV_DATA* RecvDataChain
    );

//
// Allocates a new send context to be used to call QuicSocketSend. It
// can be freed with QuicSendDataFree too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SEND_DATA*
QuicSendDataAlloc(
    _In_ QUIC_SOCKET* Socket,
    _In_ QUIC_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    );

//
// Frees a send context returned from a previous call to QuicSendDataAlloc.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendDataFree(
    _In_ QUIC_SEND_DATA* SendData
    );

//
// Allocates a new data buffer for sending.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
QuicSendDataAllocBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    );

//
// Frees a data buffer returned from a previous call to QuicSendDataAllocBuffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendDataFreeBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    );

//
// Returns whether the send context buffer limit has been reached.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendDataIsFull(
    _In_ QUIC_SEND_DATA* SendData
    );

//
// Sends the data over the socket.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSocketSend(
    _In_ QUIC_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_SEND_DATA* SendData
    );

//
// Sets a parameter on the socket.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketSetParam(
    _In_ QUIC_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t* Buffer
    );

//
// Sets a parameter on the socket.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketGetParam(
    _In_ QUIC_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t* Buffer
    );

#if defined(__cplusplus)
}
#endif
