/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Packet Fuzzer tool for the QUIC receive path.

    This tool sets up a generic MsQuic auto-accept listener and then uses a
    loopback UDP socket to send mostly well-formed QUIC packets to this listener
    to exercise the receive path. The packets are properly encrypted so that the
    MsQuic stack can decrypt and process them.

    Currently, there are two high level fuzzing modes:

    - Initial Packet Fuzzing: This generates a valid Initial packet with the TLS
    crypto frames, and then mutates the packet randomly. Then it properly
    encrypts the packet and sends it.

    - Handshake Packet Fuzzing: This generates a normal Initial packet, without
    any fuzzing, in order to elicit a valid response from the server. Then it
    continues the handshake from there. It does a similar mutation of subsequent
    packets at the handshake stages.

Future:

    Add fuzzing for 1-RTT packets.
    Add fuzzing for version 2.

--*/

#include <time.h>
#include <stdio.h>

#include <vector>
#include <map>
#include <mutex>
#include <algorithm>
#include <list>

#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // Needed for disabling 1-RTT encryption
#ifndef NOMINMAX
#define NOMINMAX
#endif

extern "C" {
#include "precomp.h" // from core directory
#ifndef QUIC_BUILD_STATIC // HACKS to statically link just the bits we need from core msquic
const char PacketLogPrefix[2][2] = {{'C', 'S'}, {'T', 'R'}};
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCloseLocally(
    _In_ QUIC_CONNECTION*,
    _In_ uint32_t,
    _In_ uint64_t,
    _In_opt_z_ const char*
    )
{
    // no-op
}
#endif // QUIC_BUILD_STATIC
}

#include "msquichelper.h"
#include "msquic.hpp"

#define MUST_SUCCEED(X) CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(X))

const MsQuicApi* MsQuic;
static const char* Alpn = "fuzz";
static uint32_t Version = QUIC_VERSION_1;
const char* Sni = "localhost";
const StrBuffer InitialSalt("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const QUIC_HKDF_LABELS HkdfLabels = { "quic key", "quic iv", "quic hp", "quic ku" };
const uint64_t MagicCid = 0x989898989898989ull;
const uint16_t MinInitialDatagramLength = 1200;
uint64_t RunTimeMs = 60000;
CxPlatEvent RecvPacketEvent(true);
QUIC_RX_PACKET* PacketQueue;
QUIC_RX_PACKET** PacketQueueTail = &PacketQueue;
CxPlatLock PacketQueueLock;
uint64_t CurrSrcCid = 0;

struct FuzzerStats {
    int64_t RecvDatagrams = 0;
    int64_t RecvInitialPackets = 0;
    int64_t RecvHandshakePackets = 0;
    int64_t Recv1RttPackets = 0;

    int64_t SendDatagrams = 0;
    int64_t SendInitialPackets = 0;
    int64_t SendHandshakePackets = 0;
    int64_t Send1RttPackets = 0;

    void Print() {
        printf("\n");
        printf("Send:\n");
        printf("  Datagrams:         %lld\n", (long long)SendDatagrams);
        printf("  Initial Packets:   %lld\n", (long long)SendInitialPackets);
        printf("  Handshake Packets: %lld\n", (long long)SendHandshakePackets);
        printf("  1-RTT Packets:     %lld\n", (long long)Send1RttPackets);
        printf("Recv:\n");
        printf("  Datagrams:         %lld\n", (long long)RecvDatagrams);
        printf("  Initial Packets:   %lld\n", (long long)RecvInitialPackets);
        printf("  Handshake Packets: %lld\n", (long long)RecvHandshakePackets);
        printf("  1-RTT Packets:     %lld\n", (long long)Recv1RttPackets);
    }
} Stats = { 0 };

struct PacketScope {
    QUIC_RX_PACKET* Packet;
    PacketScope(QUIC_RX_PACKET* Packet) : Packet(Packet) { }
    ~PacketScope() { CXPLAT_FREE(Packet, QUIC_POOL_TOOL); }
};

struct PacketParams {
    uint8_t DestCidLen;
    uint8_t SourceCidLen;
    uint64_t PacketNumber;
    uint8_t NumFrames;
    uint8_t NumPackets;
    QUIC_LONG_HEADER_TYPE_V1 PacketType;
    uint8_t Mode;
    uint8_t DestCid[20];
    uint8_t SourceCid[20];
    QUIC_FRAME_TYPE FrameTypes[2];
    uint64_t LargestAcknowledge; // For ACK Frame
};

class FuzzingData {
    const uint8_t* data {nullptr};
    const size_t size {0};
    size_t offset {0};
public:
    FuzzingData(const uint8_t* data, const size_t size) : data(data), size(size) {}
    void GetRandom(_In_ size_t Len, _Out_writes_bytes_(Len) void* Out) {
        for (size_t i = 0; i < Len; ++i) {
            ((uint8_t*)Out)[i] = data[offset++ % size];
        }
    }
    template<typename T>
    T GetRandom() {
        T Val = 0;
        GetRandom(sizeof(T), &Val);
        return Val;
    }
};

static FuzzingData* FuzzData = nullptr;

template<typename T>
T GetRandom() {
    return FuzzData ? FuzzData->GetRandom<T>() : (T)rand();
}

template<typename T>
T GetRandom(T UpperBound) {
    return (FuzzData ? FuzzData->GetRandom<T>() : (T)rand()) % UpperBound;
}

void GetRandomBytes(_In_ size_t Len, _Out_writes_bytes_(Len) void* Out) {
    if (!FuzzData) {
        for (size_t i = 0; i < Len; ++i) {
            ((uint8_t*)Out)[i] = (uint8_t)rand();
        }
    } else {
        FuzzData->GetRandom(Len, Out);
    }
}

void RandomizeSomeBytes(_In_ size_t Len, _Out_writes_bytes_(Len) uint8_t* Out) {
    uint8_t numIteration = GetRandom<uint8_t>();
    for(int i = 0; i < numIteration; i++){
        Out[GetRandom(Len)] = GetRandom<uint8_t>();
    }
}

bool ParseLongHeaderPacket(QUIC_RX_PACKET* Packet) {
    bool IsInitial = false;
    if (Packet->LH->Version == QUIC_VERSION_2) {
        if (Packet->LH->Type != QUIC_INITIAL_V2 && Packet->LH->Type != QUIC_HANDSHAKE_V2) {
            return false; // Not a type we care about
        }
        IsInitial = Packet->LH->Type == QUIC_INITIAL_V2;
        Packet->KeyType = QuicPacketTypeToKeyTypeV2(Packet->LH->Type);
    } else if (Packet->LH->Version == QUIC_VERSION_1) {
        if (Packet->LH->Type != QUIC_INITIAL_V1 && Packet->LH->Type != QUIC_HANDSHAKE_V1) {
            return false; // Not a type we care about
        }
        IsInitial = Packet->LH->Type == QUIC_INITIAL_V1;
        Packet->KeyType = QuicPacketTypeToKeyTypeV1(Packet->LH->Type);
    } else {
        return false; // Not a version we care about
    }

    Packet->DestCidLen = Packet->LH->DestCidLength;
    Packet->DestCid = Packet->LH->DestCid;
    Packet->SourceCidLen = *(Packet->DestCid + Packet->DestCidLen);
    Packet->SourceCid = Packet->DestCid + Packet->DestCidLen + sizeof(uint8_t);

    if (memcmp(Packet->DestCid, &CurrSrcCid, sizeof(uint64_t)) != 0) {
        return false; // Packet doesn't match our CID
    }

    uint16_t Offset = MIN_INV_LONG_HDR_LENGTH + Packet->DestCidLen + Packet->SourceCidLen;
    if (IsInitial) {
        QUIC_VAR_INT TokenLength;
        QuicVarIntDecode(
            Packet->AvailBufferLength,
            Packet->AvailBuffer,
            &Offset,
            &TokenLength);
        CXPLAT_FRE_ASSERT(TokenLength <= Packet->AvailBufferLength - Offset);
        Offset += (uint16_t)TokenLength; // Ignore token
        Stats.RecvInitialPackets++;
    } else {
        Stats.RecvHandshakePackets++;
    }

    QUIC_VAR_INT PayloadLength;
    QuicVarIntDecode(
        Packet->AvailBufferLength,
        Packet->AvailBuffer,
        &Offset,
        &PayloadLength);
    CXPLAT_FRE_ASSERT(PayloadLength <= Packet->AvailBufferLength - Offset);
    Packet->HeaderLength = Offset;
    Packet->PayloadLength = (uint16_t)PayloadLength;
    Packet->ValidatedHeaderVer = TRUE;
    Packet->Encrypted = TRUE;
    return true;
}

QUIC_RX_PACKET* CopyPacket(const QUIC_RX_PACKET* Packet) {
    uint16_t PacketLength = Packet->HeaderLength + Packet->PayloadLength;
    QUIC_RX_PACKET* Copy =
        (QUIC_RX_PACKET*)CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_RX_PACKET) + PacketLength +
            Packet->DestCidLen + Packet->SourceCidLen,
            QUIC_POOL_TOOL);
    CXPLAT_FRE_ASSERT(Copy != nullptr);
    memcpy(Copy, Packet, sizeof(QUIC_RX_PACKET));
    Copy->AvailBufferLength = PacketLength;
    Copy->AvailBuffer = (uint8_t*)(Copy + 1);
    memcpy((void *)Copy->AvailBuffer, Packet->AvailBuffer, PacketLength);
    Copy->DestCid = Copy->AvailBuffer + PacketLength;
    memcpy((void *)Copy->DestCid, Packet->DestCid, Packet->DestCidLen);
    Copy->SourceCid = Copy->DestCid + Packet->DestCidLen;
    memcpy((void *)Copy->SourceCid, Packet->SourceCid, Packet->SourceCidLen);
    Copy->_.Next = nullptr;
    return Copy;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
UdpRecvCallback(
    _In_ CXPLAT_SOCKET*,
    _In_ void*,
    _In_ CXPLAT_RECV_DATA* RecvBufferChain
    )
{
    bool SetPacketEvent = false;
    CXPLAT_RECV_DATA* Datagram = RecvBufferChain;
    while (Datagram != NULL) {
        QUIC_RX_PACKET Packet;
        CxPlatZeroMemory(&Packet, sizeof(Packet));
        Packet.AvailBuffer = Datagram->Buffer;
        Packet.AvailBufferLength = Datagram->BufferLength;
        Stats.RecvDatagrams++;

        do {
            if (!Packet.Invariant->IsLongHeader) {
                Stats.Recv1RttPackets++;
                break; // Ignore short header packets
            } else if (!ParseLongHeaderPacket(&Packet)) {
                break; // Not a packet we care about.
            }

            QUIC_RX_PACKET* PacketCopy = CopyPacket(&Packet);
            PacketQueueLock.Acquire();
            *PacketQueueTail = PacketCopy;
            PacketQueueTail = (QUIC_RX_PACKET**)&PacketCopy->_.Next;
            PacketQueueLock.Release();
            SetPacketEvent = true;

            uint16_t PacketLength = Packet.HeaderLength + Packet.PayloadLength;
            Packet.AvailBuffer += PacketLength;
            Packet.AvailBufferLength -= PacketLength;
        } while (Packet.AvailBufferLength > 0);
        Datagram = Datagram->Next;
    }
    if (PacketQueue != nullptr && SetPacketEvent) {
        RecvPacketEvent.Set();
    }
    CxPlatRecvDataReturn(RecvBufferChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
UdpUnreachCallback(_In_ CXPLAT_SOCKET*, _In_ void*, _In_ const QUIC_ADDR*) { }

struct TlsContext
{
    CXPLAT_TLS* Ptr {nullptr};
    CXPLAT_SEC_CONFIG* ClientSecConfig {nullptr};
    CXPLAT_TLS_PROCESS_STATE State;
    uint8_t AlpnListBuffer[256];

    TlsContext() {
        AlpnListBuffer[0] = (uint8_t)strlen(Alpn);
        memcpy(&AlpnListBuffer[1], Alpn, AlpnListBuffer[0]);
        State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(8000, QUIC_POOL_TOOL);
        State.BufferAllocLength = 8000;
    }

    void CreateContext(_In_reads_(8) const uint8_t* initSrcCid = (const uint8_t*)&MagicCid) {
        uint8_t *stateBuffer = State.Buffer;
        CxPlatZeroMemory(&State, sizeof(State));
        State.Buffer = stateBuffer;
        State.BufferAllocLength = 8000;
        QUIC_CREDENTIAL_CONFIG CredConfig = {
            QUIC_CREDENTIAL_TYPE_NONE,
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
            NULL, NULL, NULL, NULL
        };
        CXPLAT_TLS_CALLBACKS TlsCallbacks = {
            OnRecvQuicTP,
            NULL
        };

        MUST_SUCCEED(
            CxPlatTlsSecConfigCreate(
                &CredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsCallbacks,
                &ClientSecConfig,
                OnSecConfigCreateComplete));

        QUIC_CONNECTION Connection = {};

        QUIC_TRANSPORT_PARAMETERS TP = {0};
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_DATA;
        TP.InitialMaxData = 10000;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL;
        TP.InitialMaxStreamDataBidiLocal = 10000;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE;
        TP.InitialMaxStreamDataBidiRemote = 10000;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
        TP.InitialMaxBidiStreams = 3;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
        TP.InitialMaxUniStreams = 3;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
        TP.InitialSourceConnectionIDLength = sizeof(uint64_t);
        memcpy(TP.InitialSourceConnectionID, initSrcCid, sizeof(uint64_t));

        CXPLAT_TLS_CONFIG Config = {0};
        Config.IsServer = FALSE;
        Config.SecConfig = ClientSecConfig;
        Config.HkdfLabels = &HkdfLabels;
        Config.AlpnBuffer = AlpnListBuffer;
        Config.AlpnBufferLength = AlpnListBuffer[0] + 1;
        Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
        Config.LocalTPBuffer =
            QuicCryptoTlsEncodeTransportParameters(&Connection, FALSE, &TP, NULL, &Config.LocalTPLength);
        CXPLAT_FRE_ASSERT(Config.LocalTPBuffer != nullptr);
        Config.Connection = (QUIC_CONNECTION*)this;
        Config.ServerName = Sni;

        MUST_SUCCEED(
            CxPlatTlsInitialize(
                &Config,
                &State,
                &Ptr));
    }

    ~TlsContext() {
        CxPlatTlsUninitialize(Ptr);
        if (ClientSecConfig) {
            CxPlatTlsSecConfigDelete(ClientSecConfig);
        }
        if (State.Buffer != nullptr) {
            CXPLAT_FREE(State.Buffer, QUIC_POOL_TOOL);
            State.Buffer = nullptr;
        }
        for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            if (State.ReadKeys[i] != nullptr) {
                QuicPacketKeyFree(State.ReadKeys[i]);
                State.ReadKeys[i] = nullptr;
            }
            if (State.WriteKeys[i] != nullptr) {
                QuicPacketKeyFree(State.WriteKeys[i]);
                State.WriteKeys[i] = nullptr;
            }
        }
    }

private:

    _Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
    static void
    QUIC_API
    OnSecConfigCreateComplete(
        _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
        _In_opt_ void* Context,
        _In_ QUIC_STATUS /* Status */,
        _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
        )
    {
        *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
    }

    CXPLAT_TLS_RESULT_FLAGS
    ProcessData(
        _In_reads_bytes_(*BufferLength)
            const uint8_t * Buffer,
        _In_ uint32_t * BufferLength
        )
    {
        auto Result =
            CxPlatTlsProcessData(
                Ptr,
                CXPLAT_TLS_CRYPTO_DATA,
                Buffer,
                BufferLength,
                &State);
        CXPLAT_FRE_ASSERT(!(Result & CXPLAT_TLS_RESULT_ERROR));
        return Result;
    }

public:

    CXPLAT_TLS_RESULT_FLAGS
    ProcessData(
        _Inout_ CXPLAT_TLS_PROCESS_STATE* PeerState = nullptr
        )
    {
        if (PeerState == nullptr) {
            //
            // Special case for client hello/initial.
            //
            uint32_t Zero = 0;
            return ProcessData(nullptr, &Zero);
        }

        uint32_t Result = 0;

        while (PeerState->BufferLength != 0) {
            uint32_t BufferLength;
            uint32_t StartOffset = PeerState->BufferTotalLength - PeerState->BufferLength;
            if (PeerState->BufferOffset1Rtt != 0 && StartOffset >= PeerState->BufferOffset1Rtt) {
                BufferLength = PeerState->BufferLength;

            } else if (PeerState->BufferOffsetHandshake != 0 && StartOffset >= PeerState->BufferOffsetHandshake) {
                if (PeerState->BufferOffset1Rtt != 0) {
                    BufferLength = (uint16_t)(PeerState->BufferOffset1Rtt - StartOffset);
                } else {
                    BufferLength = PeerState->BufferLength;
                }

            } else {
                if (PeerState->BufferOffsetHandshake != 0) {
                    BufferLength = (uint16_t)(PeerState->BufferOffsetHandshake - StartOffset);
                } else {
                    BufferLength = PeerState->BufferLength;
                }
            }

            Result |=
                (uint32_t)ProcessData(
                    PeerState->Buffer,
                    &BufferLength);

            PeerState->BufferLength -= (uint16_t)BufferLength;
            CxPlatMoveMemory(
                PeerState->Buffer,
                PeerState->Buffer + BufferLength,
                PeerState->BufferLength);
        }

        return (CXPLAT_TLS_RESULT_FLAGS)Result;
    }

private:

    static BOOLEAN
    OnRecvQuicTP(
        _In_ QUIC_CONNECTION*,
        _In_ uint16_t,
        _In_reads_(TPLength) const uint8_t*
        )
    {
        return TRUE;
    }
};

void WriteAckFrame(
    _In_ uint64_t LargestAcknowledge,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    QUIC_RANGE AckRange;
    QuicRangeInitialize(QUIC_MAX_RANGE_DECODE_ACKS, &AckRange);
    BOOLEAN RangeUpdated;
    QuicRangeAddRange(&AckRange, LargestAcknowledge, 1, &RangeUpdated);
    uint64_t AckDelay = 40;
    CXPLAT_FRE_ASSERT(
        QuicAckFrameEncode(
            &AckRange,
            AckDelay,
            nullptr,
            Offset,
            BufferLength,
            Buffer));
}

void WriteCryptoFrame(
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer,
    _In_ TlsContext* ClientContext,
    _In_ PacketParams* PacketParams
    )
{
    if (PacketParams->Mode == 0) {
        if (ClientContext == nullptr) {
            ClientContext = new TlsContext();
            ClientContext->CreateContext(PacketParams->SourceCid);
            auto Result = ClientContext->ProcessData();
            CXPLAT_FRE_ASSERT(Result & CXPLAT_TLS_RESULT_DATA);
        }
    }

    QUIC_CRYPTO_EX Frame = {
        0, ClientContext->State.BufferLength, ClientContext->State.Buffer
    };

    //
    // TODO: The code in the recvfuzzer assumes that all data produced in
    // a single pass through CxPlatTlsProcessData will fit in a udp datagram
    // which is not the case with openssl when ML-KEM keyshares are offered.
    // We should update this code to allow for the splitting of CRYPTO frames
    // in the same way the core datapath does.  Until then, we disable ML-KEM
    // for the fuzzer only (see corresponding TODO in tls_openssl.c
    //
    CXPLAT_FRE_ASSERT(
        QuicCryptoFrameEncode(
            &Frame,
            Offset,
            BufferLength,
            Buffer));
}

//
// Build up the packet header and payload.
//
void WriteClientPacket(
    _In_ uint32_t PacketNumber,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *PacketLength)
        uint8_t* Buffer,
    _Out_ uint16_t* PacketLength,
    _Out_ uint16_t* HeaderLength,
    _In_ TlsContext* ClientContext,
    _In_ PacketParams* PacketParams
    )
{
    uint8_t DestCidBuffer[sizeof(QUIC_CID) + 256] = {0};
    QUIC_CID* DestCid = (QUIC_CID*)DestCidBuffer;
    DestCid->IsInitial = TRUE;
    DestCid->Length = PacketParams->DestCidLen;
    if (PacketParams->DestCid == nullptr) {
        GetRandomBytes(sizeof(uint64_t), DestCid->Data);
    } else {
        memcpy(DestCid->Data, PacketParams->DestCid, PacketParams->DestCidLen);
    }

    uint8_t SourceCidBuffer[sizeof(QUIC_CID) + 256] = {0};
    QUIC_CID* SourceCid = (QUIC_CID*)SourceCidBuffer;
    SourceCid->IsInitial = TRUE;
    SourceCid->Length = PacketParams->SourceCidLen;
    if (PacketParams->SourceCid == nullptr) {
        GetRandomBytes(sizeof(uint64_t), SourceCid->Data);
    } else {
        memcpy(SourceCid->Data, PacketParams->SourceCid, PacketParams->SourceCidLen);
    }

    uint16_t PayloadLengthOffset = 0;
    uint8_t PacketNumberLength;
    *HeaderLength =
        QuicPacketEncodeLongHeaderV1(
            Version,
            (uint8_t)PacketParams->PacketType,
            1, // Fixed bit must be 1 in this case
            DestCid,
            SourceCid,
            0,
            nullptr,
            PacketNumber,
            BufferLength,
            Buffer,
            &PayloadLengthOffset,
            &PacketNumberLength);

    uint16_t BufferSize = BufferLength - *HeaderLength;
    uint16_t PayloadLength = 0;
    for (int i = 0; i < PacketParams->NumFrames; i++) {
        PayloadLength += GetRandom<uint8_t>(64); // Random padding

        if (PacketParams->FrameTypes[i] == QUIC_FRAME_ACK) {
            WriteAckFrame(
                PacketParams->LargestAcknowledge,
                &PayloadLength,
                BufferSize,
                Buffer + *HeaderLength);

        } else if (PacketParams->FrameTypes[i] == QUIC_FRAME_CRYPTO) {
            WriteCryptoFrame(
                &PayloadLength,
                BufferSize,
                Buffer + *HeaderLength,
                ClientContext,
                PacketParams);
        }
    }

    PayloadLength += GetRandom<uint8_t>(64); // More random padding

    *PacketLength = *HeaderLength + PayloadLength + CXPLAT_ENCRYPTION_OVERHEAD;
    CXPLAT_FRE_ASSERT(*PacketLength + PacketNumberLength < BufferLength);
    QuicVarIntEncode2Bytes(
        PacketNumberLength + PayloadLength + CXPLAT_ENCRYPTION_OVERHEAD,
        Buffer + PayloadLengthOffset);
}

//
// Finalizes the packet number, encryption, and header protection.
//
void FinalizePacket(
    _Out_writes_(PacketLength)
        uint8_t* Packet,
    _In_ uint16_t PacketLength,
    _In_ uint16_t HeaderLength,
    _In_ uint64_t PacketNumber,
    _In_ PacketParams* PacketParams,
    _In_opt_ TlsContext* ClientContext
    )
{
    uint8_t* DestCid = Packet + sizeof(QUIC_LONG_HEADER_V1);
    QUIC_PACKET_KEY_TYPE KeyType = QuicPacketTypeToKeyTypeV1((uint8_t)PacketParams->PacketType);

    QUIC_PACKET_KEY* WriteKey = nullptr;
    if (PacketParams->Mode == 0) {
        MUST_SUCCEED(
            QuicPacketKeyCreateInitial(
                FALSE,
                &HkdfLabels,
                InitialSalt.Data,
                PacketParams->DestCidLen,
                (uint8_t*)DestCid,
                nullptr,
                &WriteKey));
    } else {
        if (ClientContext->State.WriteKeys[0] == nullptr) {
            MUST_SUCCEED(
                QuicPacketKeyCreateInitial(
                    FALSE,
                    &HkdfLabels,
                    InitialSalt.Data,
                    PacketParams->DestCidLen,
                    (uint8_t*)DestCid,
                    &ClientContext->State.ReadKeys[0],
                    &ClientContext->State.WriteKeys[0]));
            ClientContext->State.ReadKey = QUIC_PACKET_KEY_INITIAL;
            ClientContext->State.WriteKey = QUIC_PACKET_KEY_INITIAL;
        }
        WriteKey = ClientContext->State.WriteKeys[KeyType];
    }
    uint8_t Iv[CXPLAT_IV_LENGTH];
    QuicCryptoCombineIvAndPacketNumber(
        WriteKey->Iv, (uint8_t*)&PacketNumber, Iv);

    CxPlatEncrypt(
        WriteKey->PacketKey,
        Iv,
        HeaderLength,
        Packet,
        PacketLength - HeaderLength,
        Packet + HeaderLength);

    uint8_t HpMask[16];
    CxPlatHpComputeMask(
        WriteKey->HeaderKey,
        1,
        Packet + HeaderLength,
        HpMask);

    uint16_t PacketNumberOffset = HeaderLength - sizeof(uint32_t);
    Packet[0] ^= HpMask[0] & 0x0F;
    for (uint8_t i = 0; i < 4; ++i) {
        Packet[PacketNumberOffset + i] ^= HpMask[i + 1];
    }
}

void BuildAndSendPackets(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ CXPLAT_ROUTE* Route,
    _In_ PacketParams* PacketParams,
    _In_ TlsContext* ClientContext,
    _In_ bool FuzzPacket = true
    )
{
    const uint16_t DatagramLength = MinInitialDatagramLength;
    CXPLAT_SEND_CONFIG SendConfig = { Route, DatagramLength, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0 };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Binding, &SendConfig);
    CXPLAT_FRE_ASSERT(SendData != nullptr);

    uint8_t numPacketsSent = 0;
    while (!CxPlatSendDataIsFull(SendData) && numPacketsSent <= PacketParams->NumPackets) {

        QUIC_BUFFER* SendBuffer =
            CxPlatSendDataAllocBuffer(SendData, DatagramLength);
        CXPLAT_FRE_ASSERT(SendBuffer != nullptr);
        CxPlatZeroMemory(SendBuffer->Buffer, DatagramLength);

        uint16_t PacketLength, HeaderLength;
        uint64_t PacketNum = PacketParams->PacketNumber++;
        WriteClientPacket(
            (uint32_t)PacketNum,
            (uint16_t)SendBuffer->Length,
            SendBuffer->Buffer,
            &PacketLength,
            &HeaderLength,
            ClientContext,
            PacketParams);

        if (FuzzPacket) {
            RandomizeSomeBytes(PacketLength, SendBuffer->Buffer);
        }

        FinalizePacket(
            SendBuffer->Buffer,
            PacketLength,
            HeaderLength,
            PacketNum,
            PacketParams,
            ClientContext);

        if (PacketParams->Mode == 0) {
            Stats.SendInitialPackets++;
        } else {
            Stats.SendHandshakePackets++;
        }
        Stats.SendDatagrams++;
        numPacketsSent++;

        if (!FuzzPacket) {
            break;
        }
    }

    CxPlatSocketSend(Binding, Route, SendData);
}

bool DecryptPacket(
    _In_ QUIC_RX_PACKET* Packet,
    _In_ PacketParams* PacketParams,
    _In_ TlsContext* ClientContext
    )
{
    uint8_t Cipher[CXPLAT_HP_SAMPLE_LENGTH];
    uint8_t HpMask[16];
    CxPlatCopyMemory(
        Cipher,
        Packet->AvailBuffer + Packet->HeaderLength + 4,
        CXPLAT_HP_SAMPLE_LENGTH);

    QUIC_PACKET_KEY_TYPE KeyType = Packet->KeyType;
    if (ClientContext->State.ReadKeys[KeyType] == nullptr) {
        return false;
    }

    MUST_SUCCEED(
        CxPlatHpComputeMask(
            ClientContext->State.ReadKeys[KeyType]->HeaderKey,
            1,
            Cipher,
            HpMask));
    uint8_t CompressedPacketNumberLength = 0;
    ((uint8_t*)Packet->AvailBuffer)[0] ^= HpMask[0] & 0x0F;
    CompressedPacketNumberLength = Packet->LH->PnLength + 1;
    for (uint8_t i = 0; i < CompressedPacketNumberLength; i++) {
        ((uint8_t*)Packet->AvailBuffer)[Packet->HeaderLength + i] ^= HpMask[1 + i];
    }
    uint64_t CompressedPacketNumber = 0;
    QuicPktNumDecode(
        CompressedPacketNumberLength,
        Packet->AvailBuffer + Packet->HeaderLength,
        &CompressedPacketNumber);

    Packet->HeaderLength += CompressedPacketNumberLength;
    Packet->PayloadLength -= CompressedPacketNumberLength;
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    Packet->PacketNumber =
        QuicPktNumDecompress(
            PacketParams->PacketNumber + 1,
            CompressedPacketNumber,
            CompressedPacketNumberLength);
    Packet->PacketNumberSet = TRUE;
    const uint8_t* Payload = Packet->AvailBuffer + Packet->HeaderLength;
    uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
    QuicCryptoCombineIvAndPacketNumber(
        ClientContext->State.ReadKeys[KeyType]->Iv,
        (uint8_t*)&Packet->PacketNumber,
        Iv);

    MUST_SUCCEED(
        CxPlatDecrypt(
            ClientContext->State.ReadKeys[KeyType]->PacketKey,
            Iv,
            Packet->HeaderLength,   // HeaderLength
            Packet->AvailBuffer,    // Header
            Packet->PayloadLength,  // BufferLength
            (uint8_t*)Payload));    // Buffer
    Packet->PayloadLength -= CXPLAT_ENCRYPTION_OVERHEAD;
    return true;
}

void FuzzInitial(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ CXPLAT_ROUTE* Route
    )
{
    PacketParams PacketParams = {
        sizeof(uint64_t),
        sizeof(uint64_t),
        0,
        1,
        100
    };
    PacketParams.PacketType = QUIC_INITIAL_V1;
    PacketParams.FrameTypes[0] = QUIC_FRAME_CRYPTO;
    PacketParams.Mode = 0;
    GetRandomBytes(sizeof(uint64_t), &PacketParams.SourceCid);

    TlsContext ClientContext;
    ClientContext.CreateContext(PacketParams.SourceCid);
    CXPLAT_FRE_ASSERT(ClientContext.ProcessData() & CXPLAT_TLS_RESULT_DATA);

    BuildAndSendPackets(Binding, Route, &PacketParams, &ClientContext);
}

void FuzzHandshake(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ CXPLAT_ROUTE* Route,
    _In_ uint64_t StartTimeMs
    )
{
    PacketParams PacketParams = {
        sizeof(uint64_t),
        sizeof(uint64_t),
        0,
        1
    };
    PacketParams.PacketType = QUIC_INITIAL_V1;
    PacketParams.FrameTypes[0] = QUIC_FRAME_CRYPTO;
    PacketParams.Mode = 1;
    GetRandomBytes(sizeof(uint64_t), &PacketParams.SourceCid);
    memcpy(&CurrSrcCid, PacketParams.SourceCid, sizeof(uint64_t)); // Save for receive path

    TlsContext ClientContext;
    ClientContext.CreateContext(PacketParams.SourceCid);
    CXPLAT_FRE_ASSERT(ClientContext.ProcessData() & CXPLAT_TLS_RESULT_DATA);

    //
    // Keep sending the packet until we receive a response or the time runs out.
    //
    do {
        BuildAndSendPackets(Binding, Route, &PacketParams, &ClientContext, false); // Don't fuzz this one
    } while (!RecvPacketEvent.WaitTimeout(250) && CxPlatTimeDiff64(StartTimeMs, CxPlatTimeMs64()) < RunTimeMs);

    //
    // Proceed with the rest of the handshake.
    //
    uint8_t CryptoBuffer[8192];
    uint32_t CryptoBufferOffset = 0;
    while (PacketQueue != nullptr) { // TODO - Handle race conditions where packets aren't all here yet
        QUIC_RX_PACKET* Packet = PacketQueue;
        PacketScope PacketScope(Packet);

        PacketQueueLock.Acquire();
        if (Packet->_.Next == nullptr) {
            PacketQueueTail = &PacketQueue;
        }
        PacketQueue = (QUIC_RX_PACKET*)Packet->_.Next;
        PacketQueueLock.Release();

        if (!Packet->DestCidLen ||
            memcmp(Packet->DestCid, &CurrSrcCid, sizeof(uint64_t)) != 0) {
            continue; // Packet doesn't match our current connection
        }

        if (Packet->LH->Type == QUIC_INITIAL_V1) {
            PacketParams.DestCidLen = Packet->SourceCidLen;
            memcpy(PacketParams.DestCid, Packet->SourceCid, Packet->SourceCidLen);
        }

        if (!DecryptPacket(Packet, &PacketParams, &ClientContext)) {
            continue;
        }

        PacketParams.LargestAcknowledge = Packet->PacketNumber;

        uint16_t PayloadOffset = 0;
        uint16_t PayloadLength = Packet->PayloadLength;
        const uint8_t* Payload = Packet->AvailBuffer + Packet->HeaderLength;
        while (PayloadOffset < PayloadLength) {
            QUIC_VAR_INT FrameType INIT_NO_SAL(0);
            CXPLAT_FRE_ASSERT(QuicVarIntDecode(PayloadLength, Payload, &PayloadOffset, &FrameType));
            if (FrameType == QUIC_FRAME_ACK) { // Just ignore all ACK frame payload
                QUIC_VAR_INT temp INIT_NO_SAL(0);
                for (int i=0; i < 4; i++) {
                    CXPLAT_FRE_ASSERT(
                        QuicVarIntDecode(PayloadLength, Payload, &PayloadOffset, &temp));
                }

            } else if (FrameType == QUIC_FRAME_CRYPTO) {
                QUIC_CRYPTO_EX Frame;
                CXPLAT_FRE_ASSERT(
                    QuicCryptoFrameDecode(
                        Packet->PayloadLength,
                        Payload,
                        &PayloadOffset,
                        &Frame));
                CxPlatCopyMemory(
                    CryptoBuffer + (uint32_t)Frame.Offset,
                    Frame.Data,
                    (uint32_t)Frame.Length);
                uint32_t RecvBufferLength =
                    (uint32_t)Frame.Length + (uint32_t)Frame.Offset - CryptoBufferOffset;
                RecvBufferLength =
                    QuicCryptoTlsGetCompleteTlsMessagesLength(
                        CryptoBuffer + CryptoBufferOffset, RecvBufferLength);
                if (RecvBufferLength == 0) {
                    continue;
                }

                auto Result =
                    CxPlatTlsProcessData(
                        ClientContext.Ptr,
                        CXPLAT_TLS_CRYPTO_DATA,
                        CryptoBuffer + CryptoBufferOffset,
                        &RecvBufferLength,
                        &ClientContext.State);
                CXPLAT_FRE_ASSERT(!(Result & CXPLAT_TLS_RESULT_ERROR));

                CryptoBufferOffset += RecvBufferLength;
                if (Packet->LH->Type == QUIC_INITIAL_V1) {
                    //
                    // Send the initial packet ACK.
                    //
                    PacketParams.NumFrames = 1;
                    PacketParams.FrameTypes[0] = QUIC_FRAME_ACK;
                    PacketParams.PacketType = QUIC_INITIAL_V1;
                    BuildAndSendPackets(Binding, Route, &PacketParams, &ClientContext);
                    CryptoBufferOffset = 0; // Reset to zero for handshake data
                }
            }
        }

        if (ClientContext.State.HandshakeComplete) {
            //
            // Send the rest of the handshake packets.
            //
            PacketParams.PacketType = QUIC_HANDSHAKE_V1;
            PacketParams.NumFrames = 1;
            PacketParams.FrameTypes[0] = QUIC_FRAME_CRYPTO;
            PacketParams.NumPackets = GetRandom<uint8_t>(3) + 1;
            BuildAndSendPackets(Binding, Route, &PacketParams, &ClientContext);
            break;
        }
    }
}

void FuzzReceivePath(CXPLAT_SOCKET* Binding, CXPLAT_ROUTE* Route) {
    uint64_t StartTimeMs = CxPlatTimeMs64(), LastPrintTimeMs = StartTimeMs, CurrentTimeMs;
    while (CxPlatTimeDiff64(StartTimeMs, (CurrentTimeMs = CxPlatTimeMs64())) < RunTimeMs) {
        if (CxPlatTimeDiff64(LastPrintTimeMs, CurrentTimeMs) > S_TO_MS(60)) {
            LastPrintTimeMs = CurrentTimeMs;
            Stats.Print();
        }

        if (GetRandom<uint8_t>(16) == 0) {
            FuzzInitial(Binding, Route);
        } else {
            FuzzHandshake(Binding, Route, StartTimeMs);
        }

        CurrSrcCid = 0xFFFFFFFFFFFFFFFF; // Reset the CID to ignore old packets

        //
        // Drain any leftovers
        //
        PacketQueueLock.Acquire();
        QUIC_RX_PACKET* PacketQueueCopy = PacketQueue;
        PacketQueue = nullptr;
        PacketQueueTail = &PacketQueue;
        PacketQueueLock.Release();
        while (PacketQueueCopy != nullptr) {
            QUIC_RX_PACKET* Packet = PacketQueueCopy;
            PacketQueueCopy = (QUIC_RX_PACKET*)Packet->_.Next;
            CXPLAT_FREE(Packet, QUIC_POOL_TOOL);
        }
        RecvPacketEvent.Reset();
    }

    Stats.Print();
}

void SetupAndFuzz() {
    CxPlatSystemLoad();
    CxPlatInitialize();

    CXPLAT_DATAPATH* Datapath;
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        UdpRecvCallback,
        UdpUnreachCallback,
    };
    CXPLAT_WORKER_POOL* WorkerPool = CxPlatWorkerPoolCreate(nullptr, CXPLAT_WORKER_POOL_REF_TOOL);
    CXPLAT_DATAPATH_INIT_CONFIG InitConfig = {0};
    MUST_SUCCEED(
        CxPlatDataPathInitialize(
            0,
            &DatapathCallbacks,
            NULL,
            WorkerPool,
            &InitConfig,
            &Datapath));
    QUIC_ADDRESS_FAMILY Family =
        GetRandom<uint8_t>(2) == 0 ?
            QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET;
    QUIC_ADDR sockAddr = {0};
    QuicAddrSetFamily(&sockAddr, Family);
    MUST_SUCCEED(
        CxPlatDataPathResolveAddress(
            Datapath,
            Sni,
            &sockAddr));
    QuicAddrSetPort(&sockAddr, 9999);

    //
    // Create a client socket to send fuzzed packets to the server
    //
    CXPLAT_SOCKET* Binding;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = nullptr;
    UdpConfig.RemoteAddress = &sockAddr;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    MUST_SUCCEED(
        CxPlatSocketCreateUdp(
            Datapath,
            &UdpConfig,
            &Binding));

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Binding, &Route.LocalAddress);
    Route.RemoteAddress = sockAddr;

    MsQuic = new MsQuicApi();

    {
        //
        // Set up a QUIC server and fuzz it.
        //
        uint16_t RetryPercent = 0xFFFF; // Disable retry for now
        MUST_SUCCEED(
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                sizeof(uint16_t),
                &RetryPercent));
        MsQuicRegistration Registration(true);
        MUST_SUCCEED(Registration.GetInitStatus());
        auto CredConfig = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);
        MsQuicSettings Settings;
        Settings.SetPeerBidiStreamCount(10);
        Settings.SetPeerUnidiStreamCount(10);
        MsQuicConfiguration ServerConfiguration(Registration, Alpn, Settings, *CredConfig);
        MUST_SUCCEED(ServerConfiguration.GetInitStatus());
        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
        MUST_SUCCEED(Listener.Start(Alpn, &sockAddr));
        MUST_SUCCEED(Listener.GetInitStatus());

        FuzzReceivePath(Binding, &Route);
    }

    delete MsQuic;
    MsQuic = nullptr;

    CxPlatSocketDelete(Binding);
    CxPlatDataPathUninitialize(Datapath);
    CxPlatWorkerPoolDelete(WorkerPool, CXPLAT_WORKER_POOL_REF_TOOL);

    while (PacketQueue != nullptr) {
        QUIC_RX_PACKET* packet = PacketQueue;
        PacketQueue = (QUIC_RX_PACKET*)packet->_.Next;
        CXPLAT_FREE(packet, QUIC_POOL_TOOL);
    }

    CxPlatUninitialize();
    CxPlatSystemUnload();
}

#ifdef FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzData = new FuzzingData(data, size);
    SetupAndFuzz();
    delete FuzzData;
    return 0;
}

#else

int
QUIC_MAIN_EXPORT
main(int argc, char **argv) {
    TryGetValue(argc, argv, "timeout", &RunTimeMs);
    uint32_t RngSeed = 0;
    if (!TryGetValue(argc, argv, "seed", &RngSeed)) {
        GetRandomBytes(sizeof(RngSeed), &RngSeed);
    }
    printf("Using seed value: %u\n", RngSeed);
    srand(RngSeed);
    SetupAndFuzz();
    return 0;
}

#endif // FUZZING
