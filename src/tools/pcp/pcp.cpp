/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma warning(disable:4200)  // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4214)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:28931) // Unused Assignment

#include <precomp.h> // from 'core' dir
#include <msquichelper.h>

static QUIC_DATAPATH* Datapath;
static QUIC_ADDR ServerAddress;

const uint16_t QUIC_PCP_PORT = 5351;

const uint16_t PCP_MAX_UDP_PAYLOAD = 1100;

const uint8_t PCP_VERSION = 2;

const uint8_t PCP_RESULT_SUCCESS = 0;
const uint8_t PCP_RESULT_UNSUPP_VERSION = 1;
const uint8_t PCP_RESULT_NOT_AUTHORIZED = 2;
const uint8_t PCP_RESULT_MALFORMED_REQUEST = 3;

const uint8_t PCP_OPCODE_ANNOUNCE = 0;
const uint8_t PCP_OPCODE_MAP = 1;
const uint8_t PCP_OPCODE_PEER = 2;

#pragma pack(push)
#pragma pack(1)

typedef struct PCP_INVARIANT_HEADER {

    uint8_t Version;
    uint8_t Opcode : 7;
    uint8_t Request : 1;

} PCP_INVARIANT_HEADER;

typedef struct PCP_REQUEST_HEADER {

    uint8_t Version;
    uint8_t Opcode : 7;
    uint8_t Request : 1;
    uint16_t Reserved;
    uint32_t RequestLifetime;
    uint8_t ClientIpAddress[16];
    uint8_t OpcodePayload[0];

} PCP_REQUEST_HEADER;

typedef struct PCP_RESPONSE_HEADER {

    uint8_t Version;
    uint8_t Opcode : 7;
    uint8_t Request : 1;
    uint8_t Reserved1;
    uint8_t ResultCode;
    uint32_t Lifetime;
    uint32_t EpochTime;
    uint8_t Reserved2[12];
    uint8_t OpcodePayload[0];

} PCP_RESPONSE_HEADER;

typedef struct PCP_MAP_REQUEST {

    uint8_t MappingNonce[12];
    uint8_t Protocol;
    uint8_t Reserved[3];
    uint16_t InternalPort;
    uint16_t SuggestedExternalPort;
    uint8_t SuggestedExternalIpAddress[16];

} PCP_MAP_REQUEST;

typedef struct PCP_MAP_RESPONSE {

    uint8_t MappingNonce[12];
    uint8_t Protocol;
    uint8_t Reserved[3];
    uint16_t InternalPort;
    uint16_t AssignedExternalPort;
    uint8_t AssignedExternalIpAddress[16];

} PCP_MAP_RESPONSE;

#pragma pack(pop)

void PrintUsage()
{
    printf("quicpcp is used communicating with a PCP server.\n\n");

    printf("Usage:\n");
    printf("  quicattack.exe -server:address\n\n");
}

void
ProcessRecvDatagram(
    _In_ QUIC_RECV_DATAGRAM* Datagram
    )
{
    PCP_INVARIANT_HEADER* Invariant = (PCP_INVARIANT_HEADER*)Datagram->Buffer;
    if (Invariant->Version != PCP_VERSION) {
        printf("Invalid version: %hhu\n", Invariant->Version);
        return;
    }

    if (Invariant->Request != 1) {
        printf("Received unexpected request\n");
        return;
    }

    if (Invariant->Opcode != PCP_OPCODE_MAP) {
        printf("Received unexpected opcode, %hhu\n", Invariant->Opcode);
        return;
    }

    PCP_RESPONSE_HEADER* ResponseHeader = (PCP_RESPONSE_HEADER*)Datagram->Buffer;
    PCP_MAP_RESPONSE* MapResponse = (PCP_MAP_RESPONSE*)ResponseHeader->OpcodePayload;

    if (ResponseHeader->ResultCode != PCP_RESULT_SUCCESS) {
        printf("Received failure result, %hhu\n", ResponseHeader->ResultCode);
        return;
    }

    QUIC_ADDR ExternalAddr = {0};
    ExternalAddr.si_family = QUIC_ADDRESS_FAMILY_INET6;
    QuicCopyMemory(
        &ExternalAddr.Ipv6.sin6_addr,
        MapResponse->AssignedExternalIpAddress,
        sizeof(MapResponse->AssignedExternalIpAddress));
    ExternalAddr.Ipv6.sin6_port = MapResponse->AssignedExternalPort;
    QuicConvertFromMappedV6(&ExternalAddr, &ExternalAddr);

    QUIC_ADDR_STR AddrStr;
    QuicAddrToString(&ExternalAddr, &AddrStr);
    printf("Response: %s maps to :%hu for %u seconds\n",
        AddrStr.Address,
        QuicByteSwapUint16(MapResponse->InternalPort),
        QuicByteSwapUint32(ResponseHeader->Lifetime));
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

bool SendPcpMessage(QUIC_DATAPATH_BINDING* Binding)
{
    QUIC_ADDR LocalAddress;
    QuicDataPathBindingGetLocalAddress(Binding, &LocalAddress);

    QUIC_ADDR LocalMappedAddress;
    QuicConvertToMappedV6(&LocalAddress, &LocalMappedAddress);

    const uint16_t UdpPayloadLength =
        sizeof(PCP_REQUEST_HEADER) + sizeof(PCP_MAP_REQUEST);
    QUIC_FRE_ASSERT(UdpPayloadLength < PCP_MAX_UDP_PAYLOAD);

    QUIC_DATAPATH_SEND_CONTEXT* SendContext =
        QuicDataPathBindingAllocSendContext(
            Binding, QUIC_ECN_NON_ECT, UdpPayloadLength);
    if (SendContext == nullptr) {
        printf("QuicDataPathBindingAllocSendContext failed\n");
        return false;
    }

    QUIC_BUFFER* SendBuffer =
        QuicDataPathBindingAllocSendDatagram(SendContext, UdpPayloadLength);
    if (SendBuffer == nullptr) {
        printf("QuicDataPathBindingAllocSendDatagram failed\n");
        QuicDataPathBindingFreeSendContext(SendContext);
        return false;
    }

    PCP_REQUEST_HEADER* ReqHeader = (PCP_REQUEST_HEADER*)SendBuffer->Buffer;
    PCP_MAP_REQUEST* MapReq = (PCP_MAP_REQUEST*)ReqHeader->OpcodePayload;

    ReqHeader->Version = PCP_VERSION;
    ReqHeader->Request = 0;
    ReqHeader->Opcode = PCP_OPCODE_MAP;
    ReqHeader->Reserved = 0;
    ReqHeader->RequestLifetime = QuicByteSwapUint32(60);
    QuicCopyMemory(
        ReqHeader->ClientIpAddress,
        &LocalMappedAddress.Ipv6.sin6_addr,
        sizeof(ReqHeader->ClientIpAddress));
    QuicRandom(sizeof(MapReq->MappingNonce), MapReq->MappingNonce);
    MapReq->Protocol = 17; // UDP
    QuicZeroMemory(MapReq->Reserved, sizeof(MapReq->Reserved));
    MapReq->InternalPort = QuicByteSwapUint16(1234);
    MapReq->SuggestedExternalPort = 0;
    QuicZeroMemory(
        MapReq->SuggestedExternalIpAddress,
        sizeof(MapReq->SuggestedExternalIpAddress));

    printf("Request: Map :%hu for %u seconds\n",
        QuicByteSwapUint16(MapReq->InternalPort),
        QuicByteSwapUint32(ReqHeader->RequestLifetime));

    QUIC_STATUS Status =
        QuicDataPathBindingSend(
            Binding,
            &LocalAddress,
            &ServerAddress,
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
    const char* ServerStr;
    QUIC_DATAPATH_BINDING* Binding = nullptr;
    QUIC_STATUS Status;

    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    QuicDataPathInitialize(
        0,
        UdpRecvCallback,
        UdpUnreachCallback,
        &Datapath);

    if (argc < 2) {
        PrintUsage();
        goto Error;
    }

    if (!TryGetValue(argc, argv, "server", &ServerStr) ||
        !ConvertArgToAddress(ServerStr, 0, &ServerAddress)) {
        printf("Invalid 'server' arg!\n");
        goto Error;
    }
    QuicAddrSetPort(&ServerAddress, QUIC_PCP_PORT);

    Status =
        QuicDataPathBindingCreate(
            Datapath,
            nullptr,
            &ServerAddress,
            nullptr,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathBindingCreate failed, 0x%x\n", Status);
        goto Error;
    }

    if (!SendPcpMessage(Binding)) {
        goto Error;
    }

    QuicSleep(3000);
    ErrorCode = 1;

Error:

    if (Binding) {
        QuicDataPathBindingDelete(Binding);
    }
    QuicDataPathUninitialize(Datapath);
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return ErrorCode;
}
