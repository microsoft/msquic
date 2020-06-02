/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Darwin

--*/

#include "platform_internal.h"
#include "quic_platform_dispatch.h"

//
// Gets the corresponding recv datagram from its context pointer.
//
QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const Packet
    ) {
    return NULL;
}

//
// Gets the corresponding client context from its recv datagram pointer.
//
QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const Datagram
    ) {
    return NULL;
}

//
// Opens a new handle to the QUIC Datapath library.
//
QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDatapath
    ) {
    return QUIC_STATUS_SUCCESS;
}

//
// Closes a QUIC Datapath library handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* Datapath
    )
{ }

//
// Queries the currently supported features of the datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return 0;
}

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return FALSE;
}

//
// Resolves a hostname to an IP address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    ) {
    return QUIC_STATUS_SUCCESS;
}

//
// Creates a datapath binding handle for the given local address and/or remote
// address. This function immediately registers for receive upcalls from the
// UDP layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** Binding
    ) {
    return QUIC_STATUS_SUCCESS;
}

//
// Deletes a UDP binding. This function blocks on all outstandind upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDelete(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{ }

//
// Queries the locally bound interface's MTU. Returns QUIC_MIN_MTU if not
// already bound.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicDataPathBindingGetLocalMtu(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    return 0;
}

//
// Queries the locally bound IP address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetLocalAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{ }

//
// Queries the connected remote IP address. Only valid if the binding was
// initially created with a remote address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetRemoteAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{ }

//
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{ }

//
// Allocates a new send context to be used to call QuicDataPathBindingSendTo. It
// can be freed with QuicDataPathBindingFreeSendContext too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    )
{ 
    return NULL;
}

//
// Frees a send context returned from a previous call to
// QuicDataPathBindingAllocSendContext.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{ }

//
// Allocates a new UDP datagram buffer for sending.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    )
{
    return NULL;
}

//
// Frees a datagram buffer returned from a previous call to
// QuicDataPathBindingAllocSendDatagram.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* SendDatagram
    )
{ }

//
// Returns whether the send context buffer limit has been reached.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    return FALSE;
}

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    return QUIC_STATUS_SUCCESS;
}

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    return QUIC_STATUS_SUCCESS;
}

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
    return QUIC_STATUS_SUCCESS;
}

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingGetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
    return QUIC_STATUS_SUCCESS;
}

