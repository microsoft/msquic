/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Port Control Protocol (PCP) Implementation

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "pcp.c.clog.h"
#endif

const uint16_t QUIC_PCP_PORT = 5351;

const uint16_t PCP_MAX_UDP_PAYLOAD = 1100;

const uint8_t PCP_VERSION = 2;

const uint8_t PCP_RESULT_SUCCESS = 0;
//const uint8_t PCP_RESULT_UNSUPP_VERSION = 1;
//const uint8_t PCP_RESULT_NOT_AUTHORIZED = 2;
//const uint8_t PCP_RESULT_MALFORMED_REQUEST = 3;
//const uint8_t PCP_RESULT_UNSUPP_OPCODE = 4;
//const uint8_t PCP_RESULT_UNSUPP_OPTION = 5;
//const uint8_t PCP_RESULT_MALFORMED_OPTION = 6;
//const uint8_t PCP_RESULT_NETWORK_FAILURE = 7;
//const uint8_t PCP_RESULT_NO_RESOURCES = 8;
//const uint8_t PCP_RESULT_UNSUPP_PROTOCOL = 9;
//const uint8_t PCP_RESULT_USER_EX_QUOTA = 10;
//const uint8_t PCP_RESULT_CANNOT_PROVIDE_EXTERNAL = 11;
//const uint8_t PCP_RESULT_ADDRESS_MISMATCH = 12;
//const uint8_t PCP_RESULT_EXCESSIVE_REMOTE_PEERS = 13;

//const uint8_t PCP_OPCODE_ANNOUNCE = 0;
const uint8_t PCP_OPCODE_MAP = 1;
const uint8_t PCP_OPCODE_PEER = 2;

#pragma pack(push)
#pragma pack(1)

typedef struct PCP_REQUEST {

    uint8_t Version;
    uint8_t Opcode : 7;
    uint8_t Request : 1;
    uint16_t Reserved;
    uint32_t RequestLifetime;
    uint8_t ClientIpAddress[16];
    union {
        uint8_t OpcodePayload[0];
        struct {
            uint8_t MappingNonce[12];
            uint8_t Protocol;
            uint8_t Reserved[3];
            uint16_t InternalPort;
            uint16_t SuggestedExternalPort;
            uint8_t SuggestedExternalIpAddress[16];
        } MAP;
        struct {
            uint8_t MappingNonce[12];
            uint8_t Protocol;
            uint8_t Reserved[3];
            uint16_t InternalPort;
            uint16_t SuggestedExternalPort;
            uint8_t SuggestedExternalIpAddress[16];
            uint16_t RemotePeerPort;
            uint16_t Reserved2;
            uint8_t RemotePeerIpAddress[16];
        } PEER;
    };

} PCP_REQUEST;

typedef struct PCP_RESPONSE {

    uint8_t Version;
    uint8_t Opcode : 7;
    uint8_t Request : 1;
    uint8_t Reserved1;
    uint8_t ResultCode;
    uint32_t Lifetime;
    uint32_t EpochTime;
    uint8_t Reserved2[12];
    union {
        uint8_t OpcodePayload[0];
        struct {
            uint8_t MappingNonce[12];
            uint8_t Protocol;
            uint8_t Reserved[3];
            uint16_t InternalPort;
            uint16_t AssignedExternalPort;
            uint8_t AssignedExternalIpAddress[16];
        } MAP;
        struct {
            uint8_t MappingNonce[12];
            uint8_t Protocol;
            uint8_t Reserved[3];
            uint16_t InternalPort;
            uint16_t AssignedExternalPort;
            uint8_t AssignedExternalIpAddress[16];
            uint16_t RemotePeerPort;
            uint16_t Reserved2;
            uint8_t RemotePeerIpAddress[16];
        } PEER;
    };

} PCP_RESPONSE;

#pragma pack(pop)

#define SIZEOF_THROUGH_FIELD(type, field) \
    (FIELD_OFFSET(type, field) + sizeof(((type *)0)->field))

const uint16_t PCP_MAP_REQUEST_SIZE = SIZEOF_THROUGH_FIELD(PCP_REQUEST, MAP.SuggestedExternalIpAddress);
const uint16_t PCP_PEER_REQUEST_SIZE = SIZEOF_THROUGH_FIELD(PCP_REQUEST, PEER.RemotePeerIpAddress);

const uint16_t PCP_MAP_RESPONSE_SIZE = SIZEOF_THROUGH_FIELD(PCP_RESPONSE, MAP.AssignedExternalIpAddress);
const uint16_t PCP_PEER_RESPONSE_SIZE = SIZEOF_THROUGH_FIELD(PCP_RESPONSE, PEER.RemotePeerIpAddress);

//
// Main structure for PCP
//
typedef struct QUIC_PCP {

    void* ClientContext;
    QUIC_PCP_CALLBACK_HANDLER ClientCallback;

    uint32_t GatewayCount;

    _Field_size_(GatewayCount)
    QUIC_DATAPATH_BINDING* GatewayBindings[0];

} QUIC_PCP;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPcpInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ void* Context,
    _In_ QUIC_PCP_CALLBACK_HANDLER Handler,
    _Out_ QUIC_PCP** NewPcpContext
    )
{
    QUIC_PCP* PcpContext = NULL;
    uint32_t PcpContextSize;
    QUIC_ADDR* GatewayAddresses = NULL;
    uint32_t GatewayAddressesCount;

    QUIC_STATUS Status =
        QuicDataPathGetGatewayAddresses(
            Datapath,
            &GatewayAddresses,
            &GatewayAddressesCount);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    QUIC_DBG_ASSERT(GatewayAddresses != NULL);
    QUIC_DBG_ASSERT(GatewayAddressesCount != 0);

    PcpContextSize = sizeof(QUIC_PCP) + (GatewayAddressesCount * sizeof(QUIC_DATAPATH_BINDING*));
    PcpContext = (QUIC_PCP*)QUIC_ALLOC_PAGED(PcpContextSize);
    if (PcpContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PCP",
            PcpContextSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(PcpContext, PcpContextSize);
    PcpContext->ClientContext = Context;
    PcpContext->ClientCallback = Handler;
    PcpContext->GatewayCount = GatewayAddressesCount;

    for (uint32_t i = 0; i < GatewayAddressesCount; ++i) {
        QuicAddrSetPort(&GatewayAddresses[i], QUIC_PCP_PORT);
        Status =
            QuicDataPathBindingCreate(
                Datapath,
                NULL,
                &GatewayAddresses[i],
                PcpContext,
                QUIC_DATAPATH_BINDING_FLAG_PCP,
                &PcpContext->GatewayBindings[i]);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    *NewPcpContext = PcpContext;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        if (PcpContext != NULL) {
            QuicPcpUninitialize(PcpContext);
        }
    }

    if (GatewayAddresses != NULL) {
        QUIC_FREE(GatewayAddresses);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPcpUninitialize(
    _In_ QUIC_PCP* PcpContext
    )
{
    QUIC_DBG_ASSERT(PcpContext != NULL);

    for (uint32_t i = 0; i < PcpContext->GatewayCount; ++i) {
        if (PcpContext->GatewayBindings[i] != NULL) {
            QuicDataPathBindingDelete(PcpContext->GatewayBindings[i]);
        }
    }

    QUIC_FREE(PcpContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPcpProcessDatagram(
    _In_ QUIC_PCP* PcpContext,
    _In_ QUIC_RECV_DATAGRAM* Datagram
    )
{
    PCP_RESPONSE* Response = (PCP_RESPONSE*)Datagram->Buffer;

    if (Datagram->BufferLength < PCP_MAP_RESPONSE_SIZE) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PCP: Invalid length");
        return;
    }

    if (Response->Version != PCP_VERSION) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PCP: Invalid version");
        return;
    }

    if (Response->Request != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PCP: Unexpected request");
        return;
    }

    QUIC_PCP_EVENT Event;
    QuicCopyMemory(Event.FAILURE.Nonce, Response->MAP.MappingNonce, QUIC_PCP_NONCE_LENGTH);
    QUIC_ADDR InternalAddress;
    QuicCopyMemory(&InternalAddress, &Datagram->Tuple->LocalAddress, sizeof(QUIC_ADDR));
    InternalAddress.Ipv6.sin6_port = Response->MAP.InternalPort;
    QUIC_ADDR ExternalAddress = {0};
    QUIC_ADDR RemotePeerAddress = {0};

    if (Response->ResultCode != PCP_RESULT_SUCCESS) {
        Event.Type = QUIC_PCP_EVENT_FAILURE;
        Event.FAILURE.ErrorCode = Response->ResultCode;

    } else if (Response->Opcode == PCP_OPCODE_MAP) {

        QuicAddrSetFamily(&ExternalAddress, QUIC_ADDRESS_FAMILY_INET6);
        QuicCopyMemory(
            &ExternalAddress.Ipv6.sin6_addr,
            Response->MAP.AssignedExternalIpAddress,
            sizeof(Response->MAP.AssignedExternalIpAddress));
        ExternalAddress.Ipv6.sin6_port = Response->MAP.AssignedExternalPort;
        QuicConvertFromMappedV6(&ExternalAddress, &ExternalAddress);

        Event.Type = QUIC_PCP_EVENT_MAP;
        Event.MAP.LifetimeSeconds = QuicByteSwapUint32(Response->Lifetime);
        Event.MAP.InternalAddress = &InternalAddress;
        Event.MAP.ExternalAddress = &ExternalAddress;

    } else if (Response->Opcode == PCP_OPCODE_PEER) {

        if (Datagram->BufferLength < PCP_PEER_RESPONSE_SIZE) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "PCP: Invalid length");
            return;
        }

        QuicAddrSetFamily(&ExternalAddress, QUIC_ADDRESS_FAMILY_INET6);
        QuicCopyMemory(
            &ExternalAddress.Ipv6.sin6_addr,
            Response->PEER.AssignedExternalIpAddress,
            sizeof(Response->PEER.AssignedExternalIpAddress));
        ExternalAddress.Ipv6.sin6_port = Response->MAP.AssignedExternalPort;
        QuicConvertFromMappedV6(&ExternalAddress, &ExternalAddress);

        QuicAddrSetFamily(&RemotePeerAddress, QUIC_ADDRESS_FAMILY_INET6);
        QuicCopyMemory(
            &RemotePeerAddress.Ipv6.sin6_addr,
            Response->PEER.RemotePeerIpAddress,
            sizeof(Response->PEER.RemotePeerIpAddress));
        RemotePeerAddress.Ipv6.sin6_port = Response->PEER.RemotePeerPort;
        QuicConvertFromMappedV6(&RemotePeerAddress, &RemotePeerAddress);

        Event.Type = QUIC_PCP_EVENT_PEER;
        Event.PEER.LifetimeSeconds = QuicByteSwapUint32(Response->Lifetime);
        Event.PEER.InternalAddress = &InternalAddress;
        Event.PEER.ExternalAddress = &ExternalAddress;
        Event.PEER.RemotePeerAddress = &RemotePeerAddress;

    } else {

        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PCP: Unexpected opcode");
        return;
    }

    PcpContext->ClientCallback(
        PcpContext,
        PcpContext->ClientContext,
        &Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
void
QuicPcpRecvCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ QUIC_RECV_DATAGRAM* RecvBufferChain
    )
{
    UNREFERENCED_PARAMETER(Binding);
    QUIC_DBG_ASSERT(Context);
    QUIC_PCP* PcpContext = Context;

    for (QUIC_RECV_DATAGRAM* Datagram = RecvBufferChain;
         Datagram != NULL;
         Datagram = Datagram->Next) {
        QuicPcpProcessDatagram(PcpContext, RecvBufferChain);
    }

    QuicDataPathBindingReturnRecvDatagrams(RecvBufferChain);
}

BOOL
QuicDatapathBindingMatchesLocalAddr(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR* LocalAddr
    )
{
    QUIC_ADDR BindingLocalAddress;
    QuicDataPathBindingGetLocalAddress(Binding, &BindingLocalAddress);
    return
        QuicAddrGetFamily(LocalAddr) == QuicAddrGetFamily(&BindingLocalAddress) &&
        QuicAddrCompareIp(LocalAddr, &BindingLocalAddress);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPcpSendMapRequestInternal(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_reads_(QUIC_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete Nonce must match.
    )
{
    QUIC_ADDR LocalAddress, RemoteAddress;
    QuicDataPathBindingGetLocalAddress(Binding, &LocalAddress);
    QuicDataPathBindingGetRemoteAddress(Binding, &RemoteAddress);

    QUIC_ADDR LocalMappedAddress;
    QuicConvertToMappedV6(&LocalAddress, &LocalMappedAddress);

    QUIC_DATAPATH_SEND_CONTEXT* SendContext =
        QuicDataPathBindingAllocSendContext(
            Binding, QUIC_ECN_NON_ECT, PCP_MAP_REQUEST_SIZE);
    if (SendContext == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QUIC_BUFFER* SendBuffer =
        QuicDataPathBindingAllocSendDatagram(SendContext, PCP_MAP_REQUEST_SIZE);
    if (SendBuffer == NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    PCP_REQUEST* Request = (PCP_REQUEST*)SendBuffer->Buffer;

    Request->Version = PCP_VERSION;
    Request->Request = 0;
    Request->Opcode = PCP_OPCODE_MAP;
    Request->Reserved = 0;
    Request->RequestLifetime = QuicByteSwapUint32(Lifetime);
    QuicCopyMemory(
        Request->ClientIpAddress,
        &LocalMappedAddress.Ipv6.sin6_addr,
        sizeof(Request->ClientIpAddress));
    QuicCopyMemory(Request->MAP.MappingNonce, Nonce, QUIC_PCP_NONCE_LENGTH);
    Request->MAP.Protocol = 17; // UDP
    QuicZeroMemory(Request->MAP.Reserved, sizeof(Request->MAP.Reserved));
    Request->MAP.InternalPort = QuicByteSwapUint16(InternalPort);
    Request->MAP.SuggestedExternalPort = 0;
    QuicZeroMemory(
        Request->MAP.SuggestedExternalIpAddress,
        sizeof(Request->MAP.SuggestedExternalIpAddress));

    QUIC_STATUS Status =
        QuicDataPathBindingSend(
            Binding,
            &LocalAddress,
            &RemoteAddress,
            SendContext);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPcpSendMapRequest(
    _In_ QUIC_PCP* PcpContext,
    _In_reads_(QUIC_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete Nonce must match.
    )
{
    QUIC_DBG_ASSERT(PcpContext != NULL);

    QUIC_STATUS Status;
    for (uint32_t i = 0; i < PcpContext->GatewayCount; ++i) {
        if (LocalAddress == NULL ||
            QuicDatapathBindingMatchesLocalAddr(
                PcpContext->GatewayBindings[i], LocalAddress)) {
            Status =
                QuicPcpSendMapRequestInternal(
                    PcpContext->GatewayBindings[i],
                    Nonce,
                    InternalPort,
                    Lifetime);
            if (QUIC_FAILED(Status)) {
                return Status;
            }
        }
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPcpSendPeerRequestInternal(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_reads_(QUIC_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_ const QUIC_ADDR* RemotePeerAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete. Nonce must match.
    )
{
    QUIC_ADDR LocalAddress, RemoteAddress;
    QuicDataPathBindingGetLocalAddress(Binding, &LocalAddress);
    QuicDataPathBindingGetRemoteAddress(Binding, &RemoteAddress);

    QUIC_ADDR LocalMappedAddress;
    QuicConvertToMappedV6(&LocalAddress, &LocalMappedAddress);

    QUIC_ADDR RemotePeerMappedAddress;
    QuicConvertToMappedV6(RemotePeerAddress, &RemotePeerMappedAddress);

    QUIC_DATAPATH_SEND_CONTEXT* SendContext =
        QuicDataPathBindingAllocSendContext(
            Binding, QUIC_ECN_NON_ECT, PCP_PEER_REQUEST_SIZE);
    if (SendContext == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QUIC_BUFFER* SendBuffer =
        QuicDataPathBindingAllocSendDatagram(SendContext, PCP_PEER_REQUEST_SIZE);
    if (SendBuffer == NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    PCP_REQUEST* Request = (PCP_REQUEST*)SendBuffer->Buffer;

    Request->Version = PCP_VERSION;
    Request->Request = 0;
    Request->Opcode = PCP_OPCODE_PEER;
    Request->Reserved = 0;
    Request->RequestLifetime = QuicByteSwapUint32(Lifetime);
    QuicCopyMemory(
        Request->ClientIpAddress,
        &LocalMappedAddress.Ipv6.sin6_addr,
        sizeof(Request->ClientIpAddress));
    QuicCopyMemory(Request->MAP.MappingNonce, Nonce, QUIC_PCP_NONCE_LENGTH);
    Request->PEER.Protocol = 17; // UDP
    QuicZeroMemory(Request->PEER.Reserved, sizeof(Request->PEER.Reserved));
    Request->PEER.InternalPort = QuicByteSwapUint16(InternalPort);
    Request->PEER.SuggestedExternalPort = 0;
    QuicZeroMemory(
        Request->PEER.SuggestedExternalIpAddress,
        sizeof(Request->PEER.SuggestedExternalIpAddress));
    QuicCopyMemory(
        Request->PEER.RemotePeerIpAddress,
        &RemotePeerMappedAddress.Ipv6.sin6_addr,
        sizeof(Request->PEER.RemotePeerIpAddress));
    Request->PEER.RemotePeerPort = RemotePeerMappedAddress.Ipv6.sin6_port;

    QUIC_STATUS Status =
        QuicDataPathBindingSend(
            Binding,
            &LocalAddress,
            &RemoteAddress,
            SendContext);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPcpSendPeerRequest(
    _In_ QUIC_PCP* PcpContext,
    _In_reads_(QUIC_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemotePeerAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete. Nonce must match.
    )
{
    QUIC_DBG_ASSERT(PcpContext != NULL);

    QUIC_STATUS Status;
    for (uint32_t i = 0; i < PcpContext->GatewayCount; ++i) {
        if (LocalAddress == NULL ||
            QuicDatapathBindingMatchesLocalAddr(
                PcpContext->GatewayBindings[i], LocalAddress)) {
            Status =
                QuicPcpSendPeerRequestInternal(
                    PcpContext->GatewayBindings[i],
                    Nonce,
                    RemotePeerAddress,
                    InternalPort,
                    Lifetime);
            if (QUIC_FAILED(Status)) {
                return Status;
            }
        }
    }

    return QUIC_STATUS_SUCCESS;
}
