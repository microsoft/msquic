/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract: 
    Packet Fuzzer tool in the receive path.
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
#include "precomp.h" // from core directory
#include "msquichelper.h"
#include "msquic.hpp"


const MsQuicApi* MsQuic;
uint64_t MagicCid = 0x989898989898989ull;
const QUIC_HKDF_LABELS HkdfLabels = { "quic key", "quic iv", "quic hp", "quic ku" };
uint64_t RunTimeMs = 60000;
HANDLE RecvPacketEvent;

// std::mutex PacketQueueMutex;
QUIC_RX_PACKET Batch[QUIC_MAX_CRYPTO_BATCH_COUNT];
uint8_t BatchCount = 0;
std::list<QUIC_RX_PACKET*> PacketQueue;

static const char* Alpn = "fuzz";
static uint32_t Version = QUIC_VERSION_1;
const char* Sni = "localhost";

#define QUIC_MIN_INITIAL_LENGTH 1200

struct PacketParams {
    uint8_t DestCidLen;
    uint8_t SourceCidLen;
    uint8_t* DestCid;
    uint8_t* SourceCid;
    uint64_t packetNumber;
    uint8_t numFrames;
    QUIC_LONG_HEADER_TYPE_V1 PacketType;
    QUIC_FRAME_TYPE FrameTypes[2];
    uint64_t largestAcknowledge; // For ACK Frame
};

struct StrBuffer {
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

const StrBuffer InitialSalt("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

class FuzzingData {
    const uint8_t* data {nullptr};
    const size_t size {0};
    size_t offset {0};
    bool CheckBoundary(size_t Adding) {
        if (size < offset + Adding) {
            offset = 0;
        }
        return true;
    }
public:
    FuzzingData(const uint8_t* data, const size_t size) : data(data), size(size) {}
    template<typename T>
    bool TryGetRandom(T UpperBound, T* Val) {
        int type_size = sizeof(T);
        if (!CheckBoundary(type_size)) {
            return false;
        }
        memcpy(Val, &data[offset], type_size);
        *Val = (T)(*Val % UpperBound);
        offset += type_size;
        return true;
    }

};

static FuzzingData* FuzzData = nullptr;

template<typename T>
T GetRandom(T UpperBound) {
    if (!FuzzData) {
        return (T)(rand() % (int)UpperBound);
    }

    uint64_t out = 0;
    if ((uint64_t)UpperBound <= 0xff) {
        (void)FuzzData->TryGetRandom((uint8_t)UpperBound, (uint8_t*)&out);
    } else if ((uint64_t)UpperBound <= 0xffff) {
        (void)FuzzData->TryGetRandom((uint16_t)UpperBound, (uint16_t*)&out);
    } else if ((uint64_t)UpperBound <= 0xffffffff) {
        (void)FuzzData->TryGetRandom((uint32_t)UpperBound, (uint32_t*)&out);
    } else {
        (void)FuzzData->TryGetRandom((uint64_t)UpperBound, &out);
    }
    return (T)out;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
UdpRecvCallback( 
    _In_ CXPLAT_SOCKET* Binding ,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvBufferChain
    )
{
    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvBufferChain) != NULL) {

        RecvBufferChain = Datagram->Next;
        Datagram->Next = NULL;

        uint8_t DestCidLen, SourceCidLen;
        const uint8_t* DestCid, *SourceCid;
        
        QUIC_RX_PACKET* Packet = (QUIC_RX_PACKET*)Datagram;
        Packet->AvailBuffer = Datagram->Buffer;
  
        int j = 0;
        do {
            Packet->AvailBufferLength = Datagram->BufferLength;
            DestCidLen = Packet->Invariant->LONG_HDR.DestCidLength;
            DestCid = Packet->Invariant->LONG_HDR.DestCid;
            SourceCidLen = *(DestCid + DestCidLen);
            SourceCid = DestCid + sizeof(uint8_t) + DestCidLen;
            uint16_t Offset = MIN_INV_LONG_HDR_LENGTH + DestCidLen + SourceCidLen;
            Packet->DestCidLen = DestCidLen;
            Packet->SourceCidLen = SourceCidLen;
            Packet->DestCid = DestCid;
            Packet->SourceCid = SourceCid;
            if (Packet->LH->Type == QUIC_INITIAL_V1) {
                QUIC_VAR_INT TokenLengthVarInt;
                QuicVarIntDecode(
                        Packet->AvailBufferLength,
                        Packet->AvailBuffer,
                        &Offset,
                        &TokenLengthVarInt);
                Offset += (uint16_t)TokenLengthVarInt;
            }
            QUIC_VAR_INT LengthVarInt;
            QuicVarIntDecode(
                Packet->AvailBufferLength,
                Packet->AvailBuffer,
                &Offset,
                &LengthVarInt);
            Packet->HeaderLength = Offset;
            Packet->PayloadLength = (uint16_t)LengthVarInt;
            Packet->AvailBufferLength = Packet->HeaderLength + Packet->PayloadLength;
            Packet->ValidatedHeaderVer = TRUE;
            if (Packet->LH->Version == QUIC_VERSION_2) {
                Packet->KeyType = QuicPacketTypeToKeyTypeV2(Packet->LH->Type);
            } else {
                Packet->KeyType = QuicPacketTypeToKeyTypeV1(Packet->LH->Type);
            }
            Packet->Encrypted = TRUE;
            // std::lock_guard<std::mutex> lock(PacketQueueMutex);
            
            if (Packet->LH->Type == QUIC_INITIAL_V1 || Packet->LH->Type == QUIC_HANDSHAKE_V1) {
                QUIC_RX_PACKET* PacketCopy = (QUIC_RX_PACKET *)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_RX_PACKET), QUIC_POOL_TOOL); 
                memcpy(PacketCopy, Packet, sizeof(QUIC_RX_PACKET));
                PacketCopy->AvailBuffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(Packet->AvailBufferLength, QUIC_POOL_TOOL);
                memcpy((void *)PacketCopy->AvailBuffer, Packet->AvailBuffer, Packet->AvailBufferLength);
                PacketQueue.push_back(PacketCopy);
            }
            
            Packet->AvailBuffer += Packet->AvailBufferLength;
        } while (Packet->AvailBuffer - Datagram->Buffer < Datagram->BufferLength);
        
        // QuicPacketKeyFree(Keys.ReadKey);
    }
    SetEvent(RecvPacketEvent);
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

struct TlsContext
{
    CXPLAT_TLS* Ptr {nullptr};
    CXPLAT_SEC_CONFIG* ClientSecConfig {nullptr};
    CXPLAT_SEC_CONFIG* ServerSecConfig {nullptr};
    CXPLAT_TLS_PROCESS_STATE State;
    uint8_t AlpnListBuffer[256];

    void CreateContext(uint64_t initSrcCid = MagicCid)  {
        AlpnListBuffer[0] = (uint8_t)strlen(Alpn);
        memcpy(&AlpnListBuffer[1], Alpn, AlpnListBuffer[0]);
        CxPlatZeroMemory(&State, sizeof(State));
        State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(8000, QUIC_POOL_TOOL);
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
         
        if (QUIC_FAILED(
            CxPlatTlsSecConfigCreate(
                &CredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsCallbacks,
                &ClientSecConfig,
                OnSecConfigCreateComplete))) {
            printf("Failed to create sec config!\n");
        }

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
        *(uint64_t*)&TP.InitialSourceConnectionID[0] = initSrcCid;

        CXPLAT_TLS_CONFIG Config = {0};
        Config.IsServer = FALSE;
        Config.SecConfig = ClientSecConfig;
        Config.HkdfLabels = &HkdfLabels;
        Config.AlpnBuffer = AlpnListBuffer;
        Config.AlpnBufferLength = AlpnListBuffer[0] + 1;
        Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
        Config.LocalTPBuffer =
            QuicCryptoTlsEncodeTransportParameters(&Connection, FALSE, &TP, NULL, &Config.LocalTPLength);
        if (!Config.LocalTPBuffer) {
            printf("Failed to encode transport parameters!\n");
        }
        Config.Connection = (QUIC_CONNECTION*)this;
        Config.ServerName = Sni;

        if (QUIC_FAILED(
            CxPlatTlsInitialize(
                &Config,
                &State,
                &Ptr))){
            printf("Failed to initialize TLS!\n");
        }
    }

    ~TlsContext() {
        CxPlatTlsUninitialize(Ptr);
        if (ClientSecConfig) {
            CxPlatTlsSecConfigDelete(ClientSecConfig);
        }
        CXPLAT_FREE(State.Buffer, QUIC_POOL_TOOL);
        for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(State.ReadKeys[i]);
            QuicPacketKeyFree(State.WriteKeys[i]);
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

        if (Result & CXPLAT_TLS_RESULT_ERROR) {
            printf("Failed to process data!\n");
            exit(0);
        }

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
        _In_ QUIC_CONNECTION* Connection,
        _In_ uint16_t TPLength,
        _In_reads_(TPLength) const uint8_t* TPBuffer
        )
    {
        UNREFERENCED_PARAMETER(Connection);
        UNREFERENCED_PARAMETER(TPLength);
        UNREFERENCED_PARAMETER(TPBuffer);
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
    if (!QuicAckFrameEncode(
            &AckRange, 
            AckDelay, 
            nullptr, 
            Offset, 
            BufferLength, 
            Buffer)) {
        printf("QuicAckFrameEncode failure!\n");
        }

}

void WriteCryptoFrame(    
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer,
    _In_ TlsContext* ClientContext)
{

    QUIC_CRYPTO_EX Frame = {
        0, ClientContext->State.BufferLength, ClientContext->State.Buffer
    };

    if (!QuicCryptoFrameEncode(
            &Frame,
            Offset,
            BufferLength,
            Buffer)) {
        printf("QuicCryptoFrameEncode failure!\n");
        exit(0);
    }
}

void WriteClientPacket(  
    _In_ uint32_t PacketNumber,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *PacketLength)
        uint8_t* Buffer,
    _Out_ uint16_t* PacketLength,
    _Out_ uint16_t* HeaderLength,
    _In_ TlsContext* ClientContext,
    _In_ PacketParams PacketParams
    )
{
    uint32_t QuicVersion = Version;
    uint8_t FrameBuffer[4096];
    uint16_t BufferSize = sizeof(FrameBuffer);
    uint16_t FrameBufferLength = 0;
    for(int i=0; i < PacketParams.numFrames; i++) {
        if (PacketParams.FrameTypes[i] == QUIC_FRAME_ACK) {
            WriteAckFrame(PacketParams.largestAcknowledge, &FrameBufferLength, BufferSize, FrameBuffer);
        }

        if (PacketParams.FrameTypes[i] == QUIC_FRAME_CRYPTO) {
            WriteCryptoFrame(
                &FrameBufferLength, BufferSize, FrameBuffer, ClientContext);
        }
    }
    uint8_t DestCidBuffer[sizeof(QUIC_CID) + 256] = {0};
    uint8_t SourceCidBuffer[sizeof(QUIC_CID) + 256] = {0};

    QUIC_CID* DestCid = (QUIC_CID*)DestCidBuffer;
    QUIC_CID* SourceCid = (QUIC_CID*)SourceCidBuffer;
    
    DestCid->IsInitial = TRUE;
    DestCid->Length = PacketParams.DestCidLen;

    SourceCid->IsInitial = TRUE;
    SourceCid->Length = PacketParams.SourceCidLen;

    uint16_t PayloadLengthOffset = 0;
    uint8_t PacketNumberLength;

    *PacketLength =
        QuicPacketEncodeLongHeaderV1(
            QuicVersion,
            (uint8_t)PacketParams.PacketType,
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
    if (*PacketLength + FrameBufferLength > BufferLength) {
        printf("Crypto Too Big!\n");
        exit(0);
    }

    QuicVarIntEncode2Bytes(
        PacketNumberLength + FrameBufferLength + CXPLAT_ENCRYPTION_OVERHEAD,
        Buffer + PayloadLengthOffset);
    *HeaderLength = *PacketLength;

    CxPlatCopyMemory(Buffer + *PacketLength, FrameBuffer, FrameBufferLength);
    *PacketLength += FrameBufferLength;
    *PacketLength += CXPLAT_ENCRYPTION_OVERHEAD;
}

void fuzzPacket(uint8_t* Packet, uint16_t PacketLength) {
    uint8_t numIteration = (uint8_t)GetRandom(256);
    for(int i = 0; i < numIteration; i++){
        Packet[GetRandom(PacketLength)] = (uint8_t)GetRandom(256); 
    }
}

void sendPacket(CXPLAT_SOCKET* Binding, CXPLAT_ROUTE Route, int64_t* PacketCount, int64_t* TotalByteCount,  PacketParams PacketParams, bool fuzzing = true, TlsContext* ClientContext = nullptr) {
    const uint16_t DatagramLength = QUIC_MIN_INITIAL_LENGTH; 
    CXPLAT_SEND_CONFIG SendConfig = { &Route, DatagramLength, CXPLAT_ECN_NON_ECT, 0 };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Binding, &SendConfig);
    if (!SendData) {
        printf("CxPlatSendDataAlloc failed\n");
    }
    // uint64_t d = 1;
    // uint64_t s = 2;
    while (!CxPlatSendDataIsFull(SendData)) {
        uint8_t Packet[512] = {0};
        uint16_t PacketLength, HeaderLength;
        uint64_t packetNum = PacketParams.packetNumber++;
        WriteClientPacket(
            (uint32_t)packetNum,
            sizeof(Packet),
            Packet,
            &PacketLength,
            &HeaderLength,
            ClientContext,
            PacketParams);

        uint16_t PacketNumberOffset = HeaderLength - sizeof(uint32_t);

        uint8_t* DestCid = (uint8_t*)(Packet + sizeof(QUIC_LONG_HEADER_V1));
        uint8_t* SrcCid = (uint8_t*)(Packet + sizeof(QUIC_LONG_HEADER_V1) + PacketParams.DestCidLen + sizeof(uint8_t));
        if (PacketParams.DestCid == nullptr) {
            CxPlatRandom(sizeof(uint64_t), DestCid);
        }
        else {
            memcpy(DestCid, PacketParams.DestCid, PacketParams.DestCidLen);
        }
        
        memcpy(SrcCid, PacketParams.SourceCid, PacketParams.SourceCidLen);
        
        if (fuzzing) {
            fuzzPacket(Packet, sizeof(Packet));
        }
        QUIC_BUFFER* SendBuffer =
            CxPlatSendDataAllocBuffer(SendData, DatagramLength);
            if (!SendBuffer) {
                printf("CxPlatSendDataAllocBuffer failed\n");
                return;
            }
        CxPlatZeroMemory(SendBuffer->Buffer, DatagramLength);
        memcpy(SendBuffer->Buffer, Packet, PacketLength);
        if(ClientContext->State.WriteKeys[0] == nullptr) {
            if (QUIC_FAILED(
                QuicPacketKeyCreateInitial(
                    FALSE,
                    &HkdfLabels,
                    InitialSalt.Data,
                    PacketParams.DestCidLen,
                    (uint8_t*)DestCid,
                    &ClientContext->State.ReadKeys[0],
                    &ClientContext->State.WriteKeys[0]))) {
                printf("QuicPacketKeyCreateInitial failed\n");
                return;
            }
            ClientContext->State.ReadKey = QUIC_PACKET_KEY_INITIAL;
            ClientContext->State.WriteKey = QUIC_PACKET_KEY_INITIAL;
        }
        QUIC_PACKET_KEY_TYPE KeyType = QuicPacketTypeToKeyTypeV1((uint8_t)PacketParams.PacketType);
        uint8_t Iv[CXPLAT_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(
            ClientContext->State.WriteKeys[KeyType]->Iv, (uint8_t*)&packetNum, Iv);

        CxPlatEncrypt(
            ClientContext->State.WriteKeys[KeyType]->PacketKey,
            Iv,
            HeaderLength,
            SendBuffer->Buffer,
            PacketLength - HeaderLength,
            SendBuffer->Buffer + HeaderLength);

        uint8_t HpMask[16];
        CxPlatHpComputeMask(
            ClientContext->State.WriteKeys[KeyType]->HeaderKey,
            1,
            SendBuffer->Buffer + HeaderLength,
            HpMask);

        // QuicPacketKeyFree(Keys.WriteKey);
        SendBuffer->Buffer[0] ^= HpMask[0] & 0x0F;
        for (uint8_t i = 0; i < 4; ++i) {
            SendBuffer->Buffer[PacketNumberOffset + i] ^= HpMask[i + 1];
        }
        InterlockedExchangeAdd64(PacketCount, 1);
        InterlockedExchangeAdd64(TotalByteCount, DatagramLength);
        QUIC_LONG_HEADER_V1* Header = (QUIC_LONG_HEADER_V1*)Packet;

        // printf("Sending Packet Type: %d\n", Header->Type);
        if (!fuzzing) {
            break;
        }
        
    }
    
    if (QUIC_FAILED(
        CxPlatSocketSend(
            Binding,
            &Route,
            SendData))) {
        printf("Send failed!\n");
        exit(0);
    }
}

void fuzz(CXPLAT_SOCKET* Binding, CXPLAT_ROUTE Route) {
    int64_t PacketCount = 0;
    int64_t TotalByteCount = 0;
    uint8_t mode;
    uint64_t StartTimeMs = CxPlatTimeMs64();
    uint64_t SrcCid;
    PacketParams PacketParams = {
        sizeof(uint64_t),
        sizeof(uint64_t),
        nullptr,
        nullptr,
        0,
        1
    };
    RecvPacketEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    PacketParams.FrameTypes[0] = QUIC_FRAME_CRYPTO;
    TlsContext HandshakeClientContext; 
    bool ServerHello = FALSE;
    uint8_t recvBuffer[8192];
    uint32_t bufferoffset = 0;
    bool handshakeComplete = FALSE;
    while (CxPlatTimeDiff64(StartTimeMs, CxPlatTimeMs64()) < RunTimeMs) {
        mode = 1;//(uint8_t)GetRandom(2);
        if (mode == 0) {
            PacketParams = {
                sizeof(uint64_t),
                sizeof(uint64_t),
                nullptr,
                nullptr,
                0,
                1
            };
            PacketParams.PacketType = QUIC_INITIAL_V1;
            PacketParams.FrameTypes[0] = QUIC_FRAME_CRYPTO;
            CxPlatRandom(sizeof(uint64_t), &SrcCid);
            PacketParams.SourceCid = (uint8_t *)&SrcCid;
            TlsContext InitialClientContext;
            InitialClientContext.CreateContext(SrcCid);
            InitialClientContext.ProcessData();
            sendPacket(Binding, Route, &PacketCount, &TotalByteCount, PacketParams, true, &InitialClientContext);
        } else if (mode == 1) {
            if (handshakeComplete == FALSE) {
                // QUIC_RECV_BUFFER RecvBuffer[4096];
                RecvPacketEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                if (ServerHello == FALSE) {
                    do {
                        CxPlatRandom(sizeof(uint64_t), &SrcCid);
                        PacketParams.SourceCid = (uint8_t *)&SrcCid;
                        HandshakeClientContext.CreateContext(SrcCid);
                        HandshakeClientContext.ProcessData();
                        PacketParams.PacketType = QUIC_INITIAL_V1;
                        printf("Sending Client Hello\n");
                        sendPacket(Binding, Route, &PacketCount, &TotalByteCount, PacketParams, false, &HandshakeClientContext);
                    } while (WaitForSingleObject(RecvPacketEvent, 100) != (DWORD)WAIT_OBJECT_0 && CxPlatTimeDiff64(StartTimeMs, CxPlatTimeMs64()) < RunTimeMs);
                }
                // std::lock_guard<std::mutex> lock(PacketQueueMutex);
                while (!PacketQueue.empty()) {
                    QUIC_RX_PACKET* packet = PacketQueue.front();
                    if (packet->DestCidLen ==NULL|| packet->DestCid == NULL || (memcmp(packet->DestCid, PacketParams.SourceCid, PacketParams.SourceCidLen) != 0) || packet->PayloadLength < 4 + CXPLAT_HP_SAMPLE_LENGTH) {
                        CXPLAT_FREE(packet->AvailBuffer, QUIC_POOL_TOOL);
                        CXPLAT_FREE(packet, QUIC_POOL_TOOL);
                        PacketQueue.pop_front(); 
                        continue;
                    }
                    if (packet->LH->Type == QUIC_INITIAL_V1) {
                        bufferoffset = 0;
                    }
                    uint8_t Cipher[CXPLAT_HP_SAMPLE_LENGTH];
                    uint8_t HpMask[16];
                    printf("Packet Header Length: %d\n", packet->HeaderLength);    
                    printf("Packet Payload Length: %d\n", packet->PayloadLength);
                    printf("Packet Avail Buffer Length: %d\n", packet->AvailBufferLength);   
                       
                    CxPlatCopyMemory(
                        Cipher,
                        packet->AvailBuffer + packet->HeaderLength + 4,
                        CXPLAT_HP_SAMPLE_LENGTH);
                    // same step for all long header packets
                    
                    QUIC_PACKET_KEY_TYPE KeyType = packet->KeyType;   
                    if (QUIC_FAILED(
                        CxPlatHpComputeMask(
                            HandshakeClientContext.State.ReadKeys[KeyType]->HeaderKey,
                            1,
                            Cipher,
                            HpMask))) {
                        printf("Failed to Compute Mask\n");
                        }
                    uint8_t CompressedPacketNumberLength = 0;
                    ((uint8_t*)packet->AvailBuffer)[0] ^= HpMask[0] & 0x0F; 
                    CompressedPacketNumberLength = packet->LH->PnLength + 1;
                    for (uint8_t i = 0; i < CompressedPacketNumberLength; i++) {
                        ((uint8_t*)packet->AvailBuffer)[packet->HeaderLength + i] ^= HpMask[1 + i];
                    }
                    uint64_t CompressedPacketNumber = 0;
                    QuicPktNumDecode(
                        CompressedPacketNumberLength,
                        packet->AvailBuffer + packet->HeaderLength,
                        &CompressedPacketNumber);

                    packet->HeaderLength += CompressedPacketNumberLength;
                    packet->PayloadLength -= CompressedPacketNumberLength;
                    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(packet->KeyType);
                    packet->PacketNumber =
                        QuicPktNumDecompress(
                            PacketParams.packetNumber + 1,
                            CompressedPacketNumber,
                            CompressedPacketNumberLength);
                    packet->PacketNumberSet = TRUE;
                    const uint8_t* Payload = packet->AvailBuffer + packet->HeaderLength;
                    uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
                    QuicCryptoCombineIvAndPacketNumber(
                        HandshakeClientContext.State.ReadKeys[KeyType]->Iv,
                        (uint8_t*)&packet->PacketNumber,
                        Iv);
                    if (QUIC_FAILED(
                        CxPlatDecrypt(
                            HandshakeClientContext.State.ReadKeys[KeyType]->PacketKey,
                            Iv,
                            packet->HeaderLength,   // HeaderLength
                            packet->AvailBuffer,    // Header
                            packet->PayloadLength,  // BufferLength
                            (uint8_t*)Payload))) {  // Buffer
                        printf("CxPlatDecrypt failed\n");
                        CXPLAT_FREE(packet->AvailBuffer, QUIC_POOL_TOOL);
                        CXPLAT_FREE(packet, QUIC_POOL_TOOL);
                        PacketQueue.pop_front(); 
                        continue;
                        }
                    packet->PayloadLength -= CXPLAT_ENCRYPTION_OVERHEAD;
                    
                    QUIC_VAR_INT FrameType INIT_NO_SAL(0);
                    uint16_t offset = 0;
                    uint16_t PayloadLength = packet->PayloadLength;
                    while (offset < PayloadLength) {
                        QuicVarIntDecode(PayloadLength, Payload, &offset, &FrameType);
                        if(FrameType == QUIC_FRAME_ACK) {
                            QUIC_VAR_INT temp INIT_NO_SAL(0);
                            for(int i=0; i<4; i++) {
                                QuicVarIntDecode(PayloadLength, Payload, &offset, &temp);
                            }
                            printf("Received ACK Frame\n");
                        }
                        if(FrameType == QUIC_FRAME_CRYPTO) {
                            printf("Received CRYPTO Frame\n");
                            QUIC_CRYPTO_EX Frame;
                            QuicCryptoFrameDecode(packet->PayloadLength, Payload, &offset, &Frame);
                            uint64_t FlowControlLimit = UINT16_MAX;
                            BOOLEAN DataReady;
                            DataReady = FALSE;
                            CxPlatCopyMemory(
                                recvBuffer + (uint32_t)Frame.Offset,
                                Frame.Data,
                                (uint32_t)Frame.Length);
                            uint32_t recvBufferLength  = (uint32_t)Frame.Length + (uint32_t)Frame.Offset - bufferoffset;
                            recvBufferLength = QuicCryptoTlsGetCompleteTlsMessagesLength(
                                recvBuffer + bufferoffset, recvBufferLength);
                            auto Result = CxPlatTlsProcessData(
                                HandshakeClientContext.Ptr,
                                CXPLAT_TLS_CRYPTO_DATA,
                                recvBuffer + bufferoffset,
                                &recvBufferLength,
                                &HandshakeClientContext.State);
                            if (Result & CXPLAT_TLS_RESULT_ERROR) {
                                printf("Failed to process handshake data!\n");
                            }
                            bufferoffset += recvBufferLength;
                            PacketParams.largestAcknowledge = packet->PacketNumber;
                            if (packet->LH->Type == QUIC_INITIAL_V1) {
                                bufferoffset = 0;
                                ServerHello = TRUE;
                                PacketParams.numFrames = 1;
                                PacketParams.FrameTypes[0] = QUIC_FRAME_ACK;
                                PacketParams.largestAcknowledge = packet->PacketNumber;
                                PacketParams.SourceCid = (uint8_t *)packet->DestCid;
                                PacketParams.SourceCidLen = packet->DestCidLen;
                                PacketParams.DestCid = (uint8_t *)packet->SourceCid;
                                PacketParams.DestCidLen = packet->SourceCidLen;
                                PacketParams.PacketType = QUIC_INITIAL_V1;
                                printf("Sending ACK Packet\n");
                                sendPacket(Binding, Route, &PacketCount, &TotalByteCount, PacketParams, false, &HandshakeClientContext);
                            }
                            
                        }
                    }
                    if (HandshakeClientContext.State.HandshakeComplete) {
                        handshakeComplete = TRUE;
                        break;
                    }
                    CXPLAT_FREE(packet->AvailBuffer, QUIC_POOL_TOOL);
                    CXPLAT_FREE(packet, QUIC_POOL_TOOL);
                    PacketQueue.pop_front(); 
                }
                BatchCount = 0;
            }
            else {
                bufferoffset = 0;
                PacketParams.PacketType = QUIC_HANDSHAKE_V1;
                PacketParams.numFrames = 2;
                PacketParams.FrameTypes[0] = QUIC_FRAME_ACK;
                PacketParams.FrameTypes[1] = QUIC_FRAME_CRYPTO;
                printf("Sending Handshake Packet\n");
                sendPacket(Binding, Route, &PacketCount, &TotalByteCount, PacketParams, true, &HandshakeClientContext);
            }
            handshakeComplete = HandshakeClientContext.State.HandshakeComplete;
        }
    }
        printf("Total Packets sent: %lld\n", (long long)PacketCount);
        printf("Total Bytes sent: %lld\n", (long long)TotalByteCount);
}

void start() {
    CXPLAT_DATAPATH* Datapath;
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        UdpRecvCallback,
        UdpUnreachCallback,
    };
    MsQuic = new MsQuicApi();
    QUIC_STATUS Status = CxPlatDataPathInitialize(
        0,
        &DatapathCallbacks,
        NULL,
        NULL,
        &Datapath);
    if (QUIC_FAILED(Status)) {
        printf("Datapath init failed 0x%x", Status);
        return;
    }
    QUIC_ADDR sockAddr = {0};
    auto value = GetRandom(2);
    QUIC_ADDRESS_FAMILY Family = (value == 0) ? QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET; // fuzz
    QuicAddrSetFamily(&sockAddr, Family);
    Status = CxPlatDataPathResolveAddress(
                    Datapath,
                    Sni,
                    &sockAddr);
    if (QUIC_FAILED(Status)) {
        printf("Address Resolution Failed 0x%x", Status);
        return;
    }
    QuicAddrSetPort(&sockAddr, 9999);
    // make a server
    MsQuicRegistration Registration(true);
    QUIC_SUCCEEDED(Registration.GetInitStatus());

    auto CredConfig = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, *CredConfig);

    QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    QUIC_SUCCEEDED(Listener.Start(Alpn, &sockAddr));
    QUIC_SUCCEEDED(Listener.GetInitStatus());

    CXPLAT_SOCKET* Binding;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = nullptr;
    UdpConfig.RemoteAddress = &sockAddr;
    UdpConfig.Flags = 0;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    QUIC_ADDR_STR str;
    QuicAddrToString(&sockAddr, &str);
    printf("Remote address: %s\n", str.Address);

    Status =
        CxPlatSocketCreateUdp(
            Datapath,
            &UdpConfig,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("CxPlatSocketCreateUdp failed, 0x%x\n", Status);
        return;
    }

    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Binding, &Route.LocalAddress);
    Route.RemoteAddress = sockAddr;
    QuicAddrToString(&Route.LocalAddress, &str);
    printf("Local address: %s\n", str.Address);
    // Fuzzing
    fuzz(Binding, Route);
}

#ifdef FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzData = new FuzzingData(data, size);
    start();
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
        CxPlatRandom(sizeof(RngSeed), &RngSeed);
    }   
    printf("Using seed value: %u\n", RngSeed);
    srand(RngSeed);
    start();

    return 0;
}

#endif // FUZZING
