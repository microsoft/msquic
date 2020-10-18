/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <msquichelper.h>
#include <quic_datapath.h>

static QUIC_DATAPATH* Datapath;
static QUIC_ADDR* GatewayAddresses;
static uint32_t GatewayAddressesCount;
static uint8_t PcpNonce[12];

const uint16_t QUIC_PCP_PORT = 5351;

const uint16_t PCP_MAX_UDP_PAYLOAD = 1100;

const uint8_t PCP_VERSION = 2;

const uint8_t PCP_RESULT_SUCCESS = 0;
const uint8_t PCP_RESULT_UNSUPP_VERSION = 1;
const uint8_t PCP_RESULT_NOT_AUTHORIZED = 2;
const uint8_t PCP_RESULT_MALFORMED_REQUEST = 3;
const uint8_t PCP_RESULT_UNSUPP_OPCODE = 4;
const uint8_t PCP_RESULT_UNSUPP_OPTION = 5;
const uint8_t PCP_RESULT_MALFORMED_OPTION = 6;
const uint8_t PCP_RESULT_NETWORK_FAILURE = 7;
const uint8_t PCP_RESULT_NO_RESOURCES = 8;
const uint8_t PCP_RESULT_UNSUPP_PROTOCOL = 9;
const uint8_t PCP_RESULT_USER_EX_QUOTA = 10;
const uint8_t PCP_RESULT_CANNOT_PROVIDE_EXTERNAL = 11;
const uint8_t PCP_RESULT_ADDRESS_MISMATCH = 12;
const uint8_t PCP_RESULT_EXCESSIVE_REMOTE_PEERS = 13;

const uint8_t PCP_OPCODE_ANNOUNCE = 0;
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

QUIC_STATIC_ASSERT(PCP_MAP_REQUEST_SIZE <= PCP_MAX_UDP_PAYLOAD, "MAP Request must fit in max");
QUIC_STATIC_ASSERT(PCP_PEER_REQUEST_SIZE <= PCP_MAX_UDP_PAYLOAD, "PEER Request must fit in max");

void PrintUsage()
{
    printf("quicpcp is used communicating with a PCP server.\n\n");

    printf("Usage:\n");
    printf("  quicattack.exe [-server:address]\n\n");
}

void
ProcessRecvDatagram(
    _In_ QUIC_RECV_DATAGRAM* Datagram
    )
{
    PCP_RESPONSE* Response = (PCP_RESPONSE*)Datagram->Buffer;
    if (Response->Version != PCP_VERSION) {
        printf("Invalid version: %hhu\n", Response->Version);
        return;
    }

    if (Response->Request != 1) {
        printf("Received unexpected request\n");
        return;
    }

    if (Response->Opcode == PCP_OPCODE_MAP) {

        if (Response->ResultCode != PCP_RESULT_SUCCESS) {
            printf("Received MAP failure result, %hhu\n", Response->ResultCode);
            return;
        }

        if (memcmp(PcpNonce, Response->MAP.MappingNonce, sizeof(PcpNonce))) {
            printf("Received invalid nonce\n");
            return;
        }

        QUIC_ADDR ExternalAddr = {0};
        QuicAddrSetFamily(&ExternalAddr, QUIC_ADDRESS_FAMILY_INET6);
        QuicCopyMemory(
            &ExternalAddr.Ipv6.sin6_addr,
            Response->MAP.AssignedExternalIpAddress,
            sizeof(Response->MAP.AssignedExternalIpAddress));
        ExternalAddr.Ipv6.sin6_port = Response->MAP.AssignedExternalPort;
        QuicConvertFromMappedV6(&ExternalAddr, &ExternalAddr);

        QUIC_ADDR_STR AddrStr;
        QuicAddrToString(&ExternalAddr, &AddrStr);
        printf("Response: %s maps to :%hu for %u seconds\n",
            AddrStr.Address,
            QuicByteSwapUint16(Response->MAP.InternalPort),
            QuicByteSwapUint32(Response->Lifetime));

    } else if (Response->Opcode == PCP_OPCODE_PEER) {

        if (Response->ResultCode != PCP_RESULT_SUCCESS) {
            printf("Received PEER failure result, %hhu\n", Response->ResultCode);
            return;
        }

        if (memcmp(PcpNonce, Response->MAP.MappingNonce, sizeof(PcpNonce))) {
            printf("Received invalid nonce\n");
            return;
        }

        QUIC_ADDR ExternalAddr = {0};
        QuicAddrSetFamily(&ExternalAddr, QUIC_ADDRESS_FAMILY_INET6);
        QuicCopyMemory(
            &ExternalAddr.Ipv6.sin6_addr,
            Response->PEER.AssignedExternalIpAddress,
            sizeof(Response->PEER.AssignedExternalIpAddress));
        ExternalAddr.Ipv6.sin6_port = Response->MAP.AssignedExternalPort;
        QuicConvertFromMappedV6(&ExternalAddr, &ExternalAddr);

        QUIC_ADDR RemotePeerAddr = {0};
        QuicAddrSetFamily(&RemotePeerAddr, QUIC_ADDRESS_FAMILY_INET6);
        QuicCopyMemory(
            &RemotePeerAddr.Ipv6.sin6_addr,
            Response->PEER.RemotePeerIpAddress,
            sizeof(Response->PEER.RemotePeerIpAddress));
        RemotePeerAddr.Ipv6.sin6_port = Response->PEER.RemotePeerPort;
        QuicConvertFromMappedV6(&RemotePeerAddr, &RemotePeerAddr);

        QUIC_ADDR_STR ExternalAddrStr, RemotePeerAddrStr;
        QuicAddrToString(&ExternalAddr, &ExternalAddrStr);
        QuicAddrToString(&RemotePeerAddr, &RemotePeerAddrStr);
        printf("Response: %s (to peer %s) maps to :%hu for %u seconds\n",
            ExternalAddrStr.Address,
            RemotePeerAddrStr.Address,
            QuicByteSwapUint16(Response->PEER.InternalPort),
            QuicByteSwapUint32(Response->Lifetime));

    } else {

        printf("Received unexpected opcode, %hhu\n", Response->Opcode);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
void
UdpRecvCallback(
    _In_ QUIC_DATAPATH_BINDING* /* Binding */,
    _In_ void* /* Context */,
    _In_ QUIC_RECV_DATAGRAM* RecvBufferChain
    )
{
    ProcessRecvDatagram(RecvBufferChain);
    QuicDataPathBindingReturnRecvDatagrams(RecvBufferChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_UNREACHABLE_CALLBACK)
void
UdpUnreachCallback(
    _In_ QUIC_DATAPATH_BINDING* /* Binding */,
    _In_ void* /* Context */,
    _In_ const QUIC_ADDR* /* RemoteAddress */
    )
{
}

bool
SendPcpMapRequest(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t InternalPort,             // Host byte order
    _In_ uint32_t Lifetime                  // Host byte order
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
    if (SendContext == nullptr) {
        printf("QuicDataPathBindingAllocSendContext failed\n");
        return false;
    }

    QUIC_BUFFER* SendBuffer =
        QuicDataPathBindingAllocSendDatagram(SendContext, PCP_MAP_REQUEST_SIZE);
    if (SendBuffer == nullptr) {
        printf("QuicDataPathBindingAllocSendDatagram failed\n");
        QuicDataPathBindingFreeSendContext(SendContext);
        return false;
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
    QuicCopyMemory(Request->MAP.MappingNonce, PcpNonce, sizeof(PcpNonce));
    Request->MAP.Protocol = 17; // UDP
    QuicZeroMemory(Request->MAP.Reserved, sizeof(Request->MAP.Reserved));
    Request->MAP.InternalPort = QuicByteSwapUint16(InternalPort);
    Request->MAP.SuggestedExternalPort = 0;
    QuicZeroMemory(
        Request->MAP.SuggestedExternalIpAddress,
        sizeof(Request->MAP.SuggestedExternalIpAddress));

    if (Request->RequestLifetime) {
        printf("Request: Map :%hu for %u seconds\n",
            QuicByteSwapUint16(Request->MAP.InternalPort),
            QuicByteSwapUint32(Request->RequestLifetime));
    } else {
        printf("Request: Delete Map :%hu\n",
            QuicByteSwapUint16(Request->MAP.InternalPort));
    }

    QUIC_STATUS Status =
        QuicDataPathBindingSend(
            Binding,
            &LocalAddress,
            &RemoteAddress,
            SendContext);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathBindingSend failed, 0x%x\n", Status);
        return false;
    }

    return true;
}

bool
SendPcpPeerRequest(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR* RemotePeerAddress,
    _In_ uint16_t InternalPort,             // Host byte order
    _In_ uint32_t Lifetime                  // Host byte order
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
    if (SendContext == nullptr) {
        printf("QuicDataPathBindingAllocSendContext failed\n");
        return false;
    }

    QUIC_BUFFER* SendBuffer =
        QuicDataPathBindingAllocSendDatagram(SendContext, PCP_PEER_REQUEST_SIZE);
    if (SendBuffer == nullptr) {
        printf("QuicDataPathBindingAllocSendDatagram failed\n");
        QuicDataPathBindingFreeSendContext(SendContext);
        return false;
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
    QuicCopyMemory(Request->PEER.MappingNonce, PcpNonce, sizeof(PcpNonce));
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

    if (Request->RequestLifetime) {
        printf("Request: Peer :%hu for %u seconds\n",
            QuicByteSwapUint16(Request->MAP.InternalPort),
            QuicByteSwapUint32(Request->RequestLifetime));
    } else {
        printf("Request: Delete Peer :%hu\n",
            QuicByteSwapUint16(Request->MAP.InternalPort));
    }

    QUIC_STATUS Status =
        QuicDataPathBindingSend(
            Binding,
            &LocalAddress,
            &RemoteAddress,
            SendContext);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathBindingSend failed, 0x%x\n", Status);
        return false;
    }

    return true;
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int ErrorCode = -1;
    QUIC_DATAPATH_BINDING* Binding = nullptr;
    QUIC_STATUS Status;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    QuicDataPathInitialize(
        0,
        UdpRecvCallback,
        UdpUnreachCallback,
        &Datapath);
    QuicRandom(sizeof(PcpNonce), PcpNonce);

    Status =
        QuicDataPathGetGatewayAddresses(
            Datapath,
            &GatewayAddresses,
            &GatewayAddressesCount);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathGetGatewayAddresses failed, 0x%x\n", Status);
        goto Error;
    }

    QuicAddrSetPort(&GatewayAddresses[0], QUIC_PCP_PORT);

    QUIC_ADDR_STR AddrStr;
    QuicAddrToString(&GatewayAddresses[0], &AddrStr);
    printf("Gateway: %s\n", AddrStr.Address);

    Status =
        QuicDataPathBindingCreate(
            Datapath,
            nullptr,
            &GatewayAddresses[0],
            nullptr,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathBindingCreate failed, 0x%x\n", Status);
        goto Error;
    }

    if (!SendPcpMapRequest(Binding, 1234, 360000)) {
        goto Error;
    }
    QuicSleep(1000);

    if (!SendPcpMapRequest(Binding, 1234, 0)) {
        goto Error;
    }
    QuicSleep(1000);

    ErrorCode = 1;

Error:

    if (Binding) {
        QuicDataPathBindingDelete(Binding);
    }
    QUIC_FREE(GatewayAddresses);
    QuicDataPathUninitialize(Datapath);
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return ErrorCode;
}
