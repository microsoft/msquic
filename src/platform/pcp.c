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

const uint16_t CXPLAT_PCP_PORT = 5351;

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
typedef struct CXPLAT_PCP {

    void* ClientContext;
    CXPLAT_PCP_CALLBACK_HANDLER ClientCallback;

    uint32_t GatewayCount;

    _Field_size_(GatewayCount)
    CXPLAT_SOCKET* GatewaySockets[0];

} CXPLAT_PCP;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatPcpInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ void* Context,
    _In_ CXPLAT_PCP_CALLBACK_HANDLER Handler,
    _Out_ CXPLAT_PCP** NewPcpContext
    )
{
    CXPLAT_PCP* PcpContext = NULL;
    uint32_t PcpContextSize;
    QUIC_ADDR* GatewayAddresses = NULL;
    uint32_t GatewayAddressesCount;

    QUIC_STATUS Status =
        CxPlatDataPathGetGatewayAddresses(
            Datapath,
            &GatewayAddresses,
            &GatewayAddressesCount);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    CXPLAT_DBG_ASSERT(GatewayAddresses != NULL);
    CXPLAT_DBG_ASSERT(GatewayAddressesCount != 0);

    PcpContextSize = sizeof(CXPLAT_PCP) + (GatewayAddressesCount * sizeof(CXPLAT_SOCKET*));
    PcpContext = (CXPLAT_PCP*)CXPLAT_ALLOC_NONPAGED(PcpContextSize, QUIC_POOL_PCP);
    if (PcpContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_PCP",
            PcpContextSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(PcpContext, PcpContextSize);
    PcpContext->ClientContext = Context;
    PcpContext->ClientCallback = Handler;
    PcpContext->GatewayCount = GatewayAddressesCount;

    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = NULL;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_PCP;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = PcpContext;

    for (uint32_t i = 0; i < GatewayAddressesCount; ++i) {
        QuicAddrSetPort(&GatewayAddresses[i], CXPLAT_PCP_PORT);
        UdpConfig.RemoteAddress = &GatewayAddresses[i];
        Status =
            CxPlatSocketCreateUdp(
                Datapath,
                &UdpConfig,
                &PcpContext->GatewaySockets[i]);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    *NewPcpContext = PcpContext;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        if (PcpContext != NULL) {
            CxPlatPcpUninitialize(PcpContext);
        }
    }

    if (GatewayAddresses != NULL) {
        CXPLAT_FREE(GatewayAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPcpUninitialize(
    _In_ CXPLAT_PCP* PcpContext
    )
{
    CXPLAT_DBG_ASSERT(PcpContext != NULL);

    for (uint32_t i = 0; i < PcpContext->GatewayCount; ++i) {
        if (PcpContext->GatewaySockets[i] != NULL) {
            CxPlatSocketDelete(PcpContext->GatewaySockets[i]);
        }
    }

    CXPLAT_FREE(PcpContext, QUIC_POOL_PCP);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatPcpProcessDatagram(
    _In_ CXPLAT_PCP* PcpContext,
    _In_ CXPLAT_RECV_DATA* Datagram
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

    CXPLAT_PCP_EVENT Event = {0};
    CxPlatCopyMemory(Event.FAILURE.Nonce, Response->MAP.MappingNonce, CXPLAT_PCP_NONCE_LENGTH);
    QUIC_ADDR InternalAddress;
    CxPlatCopyMemory(&InternalAddress, &Datagram->Route->LocalAddress, sizeof(QUIC_ADDR));
    InternalAddress.Ipv6.sin6_port = Response->MAP.InternalPort;
    QUIC_ADDR ExternalAddress = {0};
    QUIC_ADDR RemotePeerAddress = {0};

    if (Response->ResultCode != PCP_RESULT_SUCCESS) {
        Event.Type = CXPLAT_PCP_EVENT_FAILURE;
        Event.FAILURE.ErrorCode = Response->ResultCode;

    } else if (Response->Opcode == PCP_OPCODE_MAP) {
        QuicAddrSetFamily(&ExternalAddress, QUIC_ADDRESS_FAMILY_INET6);
        CxPlatCopyMemory(
            &ExternalAddress.Ipv6.sin6_addr,
            Response->MAP.AssignedExternalIpAddress,
            sizeof(Response->MAP.AssignedExternalIpAddress));
        ExternalAddress.Ipv6.sin6_port = Response->MAP.AssignedExternalPort;
        CxPlatConvertFromMappedV6(&ExternalAddress, &ExternalAddress);

        Event.Type = CXPLAT_PCP_EVENT_MAP;
        Event.MAP.LifetimeSeconds = CxPlatByteSwapUint32(Response->Lifetime);
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
        CxPlatCopyMemory(
            &ExternalAddress.Ipv6.sin6_addr,
            Response->PEER.AssignedExternalIpAddress,
            sizeof(Response->PEER.AssignedExternalIpAddress));
        ExternalAddress.Ipv6.sin6_port = Response->MAP.AssignedExternalPort;
        CxPlatConvertFromMappedV6(&ExternalAddress, &ExternalAddress);

        QuicAddrSetFamily(&RemotePeerAddress, QUIC_ADDRESS_FAMILY_INET6);
        CxPlatCopyMemory(
            &RemotePeerAddress.Ipv6.sin6_addr,
            Response->PEER.RemotePeerIpAddress,
            sizeof(Response->PEER.RemotePeerIpAddress));
        RemotePeerAddress.Ipv6.sin6_port = Response->PEER.RemotePeerPort;
        CxPlatConvertFromMappedV6(&RemotePeerAddress, &RemotePeerAddress);

        Event.Type = CXPLAT_PCP_EVENT_PEER;
        Event.PEER.LifetimeSeconds = CxPlatByteSwapUint32(Response->Lifetime);
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
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
CxPlatPcpRecvCallback(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvBufferChain
    )
{
    UNREFERENCED_PARAMETER(Socket);
    CXPLAT_DBG_ASSERT(Context);
    CXPLAT_PCP* PcpContext = Context;

    for (CXPLAT_RECV_DATA* Datagram = RecvBufferChain;
         Datagram != NULL;
         Datagram = Datagram->Next) {
        CxPlatPcpProcessDatagram(PcpContext, RecvBufferChain);
    }

    CxPlatRecvDataReturn(RecvBufferChain);
}

BOOLEAN
CxPlatSocketMatchesLocalAddr(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddr
    )
{
    QUIC_ADDR SocketLocalAddress;
    CxPlatSocketGetLocalAddress(Socket, &SocketLocalAddress);
    return
        QuicAddrGetFamily(LocalAddr) == QuicAddrGetFamily(&SocketLocalAddress) &&
        QuicAddrCompareIp(LocalAddr, &SocketLocalAddress);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatPcpSendMapRequestInternal(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(CXPLAT_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete Nonce must match.
    )
{
    CXPLAT_ROUTE Route;
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    CxPlatSocketGetRemoteAddress(Socket, &Route.RemoteAddress);

    QUIC_ADDR LocalMappedAddress;
    CxPlatConvertToMappedV6(&Route.LocalAddress, &LocalMappedAddress);

    CXPLAT_SEND_DATA* SendData =
        CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, PCP_MAP_REQUEST_SIZE, &Route);
    if (SendData == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QUIC_BUFFER* SendBuffer =
        CxPlatSendDataAllocBuffer(SendData, PCP_MAP_REQUEST_SIZE);
    if (SendBuffer == NULL) {
        CxPlatSendDataFree(SendData);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    PCP_REQUEST* Request = (PCP_REQUEST*)SendBuffer->Buffer;

    Request->Version = PCP_VERSION;
    Request->Request = 0;
    Request->Opcode = PCP_OPCODE_MAP;
    Request->Reserved = 0;
    Request->RequestLifetime = CxPlatByteSwapUint32(Lifetime);
    CxPlatCopyMemory(
        Request->ClientIpAddress,
        &LocalMappedAddress.Ipv6.sin6_addr,
        sizeof(Request->ClientIpAddress));
    CxPlatCopyMemory(Request->MAP.MappingNonce, Nonce, CXPLAT_PCP_NONCE_LENGTH);
    Request->MAP.Protocol = 17; // UDP
    CxPlatZeroMemory(Request->MAP.Reserved, sizeof(Request->MAP.Reserved));
    Request->MAP.InternalPort = CxPlatByteSwapUint16(InternalPort);
    Request->MAP.SuggestedExternalPort = 0;
    CxPlatZeroMemory(
        Request->MAP.SuggestedExternalIpAddress,
        sizeof(Request->MAP.SuggestedExternalIpAddress));

    QUIC_STATUS Status =
        CxPlatSocketSend(
            Socket,
            &Route,
            SendData,
            (uint16_t)CxPlatProcCurrentNumber());
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatPcpSendMapRequest(
    _In_ CXPLAT_PCP* PcpContext,
    _In_reads_(CXPLAT_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete Nonce must match.
    )
{
    CXPLAT_DBG_ASSERT(PcpContext != NULL);

    QUIC_STATUS Status;
    for (uint32_t i = 0; i < PcpContext->GatewayCount; ++i) {
        if (LocalAddress == NULL ||
            CxPlatSocketMatchesLocalAddr(
                PcpContext->GatewaySockets[i], LocalAddress)) {
            Status =
                CxPlatPcpSendMapRequestInternal(
                    PcpContext->GatewaySockets[i],
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
CxPlatPcpSendPeerRequestInternal(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(CXPLAT_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_ const QUIC_ADDR* RemotePeerAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete. Nonce must match.
    )
{
    CXPLAT_ROUTE Route;
    CxPlatSocketGetLocalAddress(Socket, &Route.LocalAddress);
    CxPlatSocketGetRemoteAddress(Socket, &Route.RemoteAddress);

    QUIC_ADDR LocalMappedAddress;
    CxPlatConvertToMappedV6(&Route.LocalAddress, &LocalMappedAddress);

    QUIC_ADDR RemotePeerMappedAddress;
    CxPlatConvertToMappedV6(RemotePeerAddress, &RemotePeerMappedAddress);

    CXPLAT_SEND_DATA* SendData =
        CxPlatSendDataAlloc(Socket, CXPLAT_ECN_NON_ECT, PCP_PEER_REQUEST_SIZE, &Route);
    if (SendData == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QUIC_BUFFER* SendBuffer =
        CxPlatSendDataAllocBuffer(SendData, PCP_PEER_REQUEST_SIZE);
    if (SendBuffer == NULL) {
        CxPlatSendDataFree(SendData);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    PCP_REQUEST* Request = (PCP_REQUEST*)SendBuffer->Buffer;

    Request->Version = PCP_VERSION;
    Request->Request = 0;
    Request->Opcode = PCP_OPCODE_PEER;
    Request->Reserved = 0;
    Request->RequestLifetime = CxPlatByteSwapUint32(Lifetime);
    CxPlatCopyMemory(
        Request->ClientIpAddress,
        &LocalMappedAddress.Ipv6.sin6_addr,
        sizeof(Request->ClientIpAddress));
    CxPlatCopyMemory(Request->MAP.MappingNonce, Nonce, CXPLAT_PCP_NONCE_LENGTH);
    Request->PEER.Protocol = 17; // UDP
    CxPlatZeroMemory(Request->PEER.Reserved, sizeof(Request->PEER.Reserved));
    Request->PEER.InternalPort = CxPlatByteSwapUint16(InternalPort);
    Request->PEER.SuggestedExternalPort = 0;
    CxPlatZeroMemory(
        Request->PEER.SuggestedExternalIpAddress,
        sizeof(Request->PEER.SuggestedExternalIpAddress));
    CxPlatCopyMemory(
        Request->PEER.RemotePeerIpAddress,
        &RemotePeerMappedAddress.Ipv6.sin6_addr,
        sizeof(Request->PEER.RemotePeerIpAddress));
    Request->PEER.RemotePeerPort = RemotePeerMappedAddress.Ipv6.sin6_port;

    QUIC_STATUS Status =
        CxPlatSocketSend(
            Socket,
            &Route,
            SendData,
            (uint16_t)CxPlatProcCurrentNumber());
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatPcpSendPeerRequest(
    _In_ CXPLAT_PCP* PcpContext,
    _In_reads_(CXPLAT_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemotePeerAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete. Nonce must match.
    )
{
    CXPLAT_DBG_ASSERT(PcpContext != NULL);

    QUIC_STATUS Status;
    for (uint32_t i = 0; i < PcpContext->GatewayCount; ++i) {
        if (LocalAddress == NULL ||
            CxPlatSocketMatchesLocalAddr(
                PcpContext->GatewaySockets[i], LocalAddress)) {
            Status =
                CxPlatPcpSendPeerRequestInternal(
                    PcpContext->GatewaySockets[i],
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
