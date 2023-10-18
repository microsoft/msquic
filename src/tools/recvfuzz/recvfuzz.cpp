/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <time.h>
#include <stdio.h>

#include <vector>
#include <map>
#include <mutex>
#include <algorithm>


#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // Needed for disabling 1-RTT encryption
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "precomp.h" // from core directory
#include "msquichelper.h"
#include "msquic.hpp"

const MsQuicApi* MsQuic;
#define MagicCid 0x989898989898989ull
const QUIC_HKDF_LABELS HkdfLabels = { "quic key", "quic iv", "quic hp", "quic ku" };
uint64_t RunTimeMs;

#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)
#define ASSERT_ON_NOT(x) CXPLAT_FRE_ASSERT(x)

static const char* Alpn = "fuzz";
static uint32_t Version = QUIC_VERSION_DRAFT_29;
const char* Sni = "localhost";

#define QUIC_MIN_INITIAL_LENGTH 1200

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

const uint32_t MaxBufferSizes[] = { 0, 1, 2, 32, 50, 256, 500, 1000, 1024, 1400, 5000, 10000, 64000, 10000000 };
static const size_t BufferCount = ARRAYSIZE(MaxBufferSizes);


class FuzzingData {
    const uint8_t* data;
    size_t size;
    std::mutex mux;
    // TODO: support bit level pointers
    size_t Ptrs;
    size_t NumIterated;
    bool Cyclic;

    bool CheckBoundary(size_t Adding) {
        // TODO: efficient cyclic access
        if (size < Ptrs + Adding) {
            if (!Cyclic) {
                return false;
            }
            Ptrs = 0;
            NumIterated++;
        }
        return true;
    }
public:
    // 128 for main data, 20 for callback's issue workaround
    static const size_t MinDataSize = 148;
    static const size_t UtilityDataSize = 20;
    // hard code for determinisity

    FuzzingData() : data(nullptr), size(0), Ptrs({}), NumIterated({}), Cyclic(true) {}
    FuzzingData(const uint8_t* data, size_t size) : data(data), size(size - UtilityDataSize), Ptrs({}), NumIterated({}), Cyclic(true) {}
    bool Initialize() {
        Ptrs = 0;
        NumIterated = 0;
        return true;
    }
    template<typename T>
    bool TryGetRandom(T UpperBound, T* Val) {
        int type_size = sizeof(T);
        if (!CheckBoundary(type_size)) {
            return false;
        }
        memcpy(Val, &data[Ptrs], type_size);
        *Val = (T)(*Val % UpperBound);
        Ptrs += type_size;
        return true;
    }
    size_t GetIterateCount(uint16_t ThreadId) {
        return NumIterated;
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
        (void)FuzzData->TryGetRandom((uint8_t)UpperBound, (uint8_t*)&out, ThreadID);
    } else if ((uint64_t)UpperBound <= 0xffff) {
        (void)FuzzData->TryGetRandom((uint16_t)UpperBound, (uint16_t*)&out, ThreadID);
    } else if ((uint64_t)UpperBound <= 0xffffffff) {
        (void)FuzzData->TryGetRandom((uint32_t)UpperBound, (uint32_t*)&out, ThreadID);
    } else {
        (void)FuzzData->TryGetRandom((uint64_t)UpperBound, &out, ThreadID);
    }
    return (T)out;
}

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

void printf_buf(const char* name, void* buf, uint32_t len)
{
    printf("%s: ", name);
    for (uint32_t i = 0; i < len; i++) {
        printf("%.2X", ((uint8_t*)buf)[i]);
    }
    printf("\n");
}

struct TlsContext
{
    CXPLAT_TLS* Ptr;
    CXPLAT_SEC_CONFIG* SecConfig;
    CXPLAT_TLS_PROCESS_STATE State;
    uint8_t AlpnListBuffer[256];

    TlsContext() :
        Ptr(nullptr), SecConfig(nullptr) {

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
        QUIC_SUCCEEDED(
            CxPlatTlsSecConfigCreate(
                &CredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsCallbacks,
                &SecConfig,
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
        *(uint64_t*)&TP.InitialSourceConnectionID[0] = MagicCid;

        CXPLAT_TLS_CONFIG Config = {0};
        Config.IsServer = FALSE;
        Config.SecConfig = SecConfig;
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

        QUIC_SUCCEEDED(
            CxPlatTlsInitialize(
                &Config,
                &State,
                &Ptr));
    }

    ~TlsContext() {
        CxPlatTlsUninitialize(Ptr);
        if (SecConfig) {
            CxPlatTlsSecConfigDelete(SecConfig);
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

static 
void WriteInitialCryptoFrame(    
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer)
{
    TlsContext ClientContext;
    ClientContext.ProcessData();

    QUIC_CRYPTO_EX Frame = {
        0, ClientContext.State.BufferLength, ClientContext.State.Buffer
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


void WriteClientInitialPacket(  
    _In_ uint32_t PacketNumber,
    _In_ uint8_t CidLength,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *PacketLength)
        uint8_t* Buffer,
    _Out_ uint16_t* PacketLength,
    _Out_ uint16_t* HeaderLength
    )
{
    uint32_t QuicVersion = Version;
    uint8_t CryptoBuffer[4096];
    uint16_t BufferSize = sizeof(CryptoBuffer);
    uint16_t CryptoBufferLength = 0;

    WriteInitialCryptoFrame(
         &CryptoBufferLength, BufferSize, CryptoBuffer);
    uint8_t CidBuffer[sizeof(QUIC_CID) + 256] = {0};
    QUIC_CID* Cid = (QUIC_CID*)CidBuffer;
    Cid->IsInitial = TRUE;
    Cid->Length = CidLength;

    uint16_t PayloadLengthOffset = 0;
    uint8_t PacketNumberLength;

    *PacketLength =
        QuicPacketEncodeLongHeaderV1(
            QuicVersion,
            QUIC_INITIAL_V1,
            1, // Fixed bit must be 1 in this case
            Cid,
            Cid,
            0,
            nullptr,
            PacketNumber,
            BufferLength,
            Buffer,
            &PayloadLengthOffset,
            &PacketNumberLength);

    if (*PacketLength + CryptoBufferLength > BufferLength) {
        printf("Crypto Too Big!\n");
        exit(0);
    }

    QuicVarIntEncode2Bytes(
        PacketNumberLength + CryptoBufferLength + CXPLAT_ENCRYPTION_OVERHEAD,
        Buffer + PayloadLengthOffset);
    *HeaderLength = *PacketLength;

    CxPlatCopyMemory(Buffer + *PacketLength, CryptoBuffer, CryptoBufferLength);
    *PacketLength += CryptoBufferLength;
    *PacketLength += CXPLAT_ENCRYPTION_OVERHEAD;
}


void start(){
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
    QUIC_ADDRESS_FAMILY Family = QUIC_ADDRESS_FAMILY_INET6; // fuzz
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

    // Make  a Client
    CXPLAT_SOCKET* Binding;
    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = nullptr;
    UdpConfig.RemoteAddress = &sockAddr;
    UdpConfig.Flags = 0;
    UdpConfig.InterfaceIndex = 0;
    UdpConfig.CallbackContext = nullptr;
    QUIC_ADDR_STR str;
    QuicAddrToString(&sockAddr, &str);
    printf("Local address: %s\n", str.Address);

    Status =
        CxPlatSocketCreateUdp(
            Datapath,
            &UdpConfig,
            &Binding);
    if (QUIC_FAILED(Status)) {
        printf("CxPlatSocketCreateUdp failed, 0x%x\n", Status);
    }
    //
    const StrBuffer InitialSalt("afbfec289993d24c9e9786f19c6111e04390a899");
    const uint16_t DatagramLength = QUIC_MIN_INITIAL_LENGTH;
    CXPLAT_ROUTE Route = {0};
    CxPlatSocketGetLocalAddress(Binding, &Route.LocalAddress);
    Route.RemoteAddress = sockAddr;

    //


    uint64_t StartTimeMs = CxPlatTimeMs64();
    int packetcount = 0;
    while (CxPlatTimeDiff64(StartTimeMs, CxPlatTimeMs64()) < RunTimeMs) {
        const uint64_t PacketNumber = 0;
        uint8_t Packet[512] = {0};
        uint16_t PacketLength, HeaderLength;

        WriteClientInitialPacket(
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
        CXPLAT_SEND_CONFIG SendConfig = { &Route, DatagramLength, CXPLAT_ECN_NON_ECT, 0 };
        CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Binding, &SendConfig);
        if(!SendData){
            printf("CxPlatSendDataAlloc failed\n");
        }
        // VERIFY(SendData);

        while (!CxPlatSendDataIsFull(SendData)) {
            QUIC_BUFFER* SendBuffer =
                CxPlatSendDataAllocBuffer(SendData, DatagramLength);
             if(!SendBuffer) {
                printf("CxPlatSendDataAllocBuffer failed\n");
                }

            (*DestCid)++; (*SrcCid)++;
            *OrigSrcCid = *SrcCid;
            memcpy(SendBuffer->Buffer, Packet, PacketLength);

            // printf_buf("cleartext", SendBuffer->Buffer, PacketLength - CXPLAT_ENCRYPTION_OVERHEAD);

            QUIC_PACKET_KEY* WriteKey;
            
            if(!QUIC_SUCCEEDED(
            QuicPacketKeyCreateInitial(
                FALSE,
                &HkdfLabels,
                InitialSalt.Data,
                sizeof(uint64_t),
                (uint8_t*)DestCid,
                nullptr,
                &WriteKey))){
                    printf("QuicPacketKeyCreateInitial failed\n");
                }

            // printf_buf("salt", InitialSalt.Data, InitialSalt.Length);
            // printf_buf("cid", DestCid, sizeof(uint64_t));

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

            // printf_buf("encrypted", SendBuffer->Buffer, PacketLength);

            uint8_t HpMask[16];
            CxPlatHpComputeMask(
                WriteKey->HeaderKey,
                1,
                SendBuffer->Buffer + HeaderLength,
                HpMask);

            // printf_buf("cipher_text", SendBuffer->Buffer + HeaderLength, 16);
            // printf_buf("hp_mask", HpMask, 16);

            QuicPacketKeyFree(WriteKey);

            SendBuffer->Buffer[0] ^= HpMask[0] & 0x0F;
            for (uint8_t i = 0; i < 4; ++i) {
                SendBuffer->Buffer[PacketNumberOffset + i] ^= HpMask[i + 1];
            }

            // printf_buf("protected", SendBuffer->Buffer, PacketLength);

        }

        
        QUIC_SUCCEEDED(
        CxPlatSocketSend(
            Binding,
            &Route,
            SendData));
        printf("Initial Packet Sent: %d\n", packetcount);
        packetcount++;
    }
}

#ifdef FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzData = new FuzzingData(data, size);
    if (!FuzzData->Initialize()) {
        return 0;
    }


    start();
    delete FuzzData;
    return 0;
}
#else
int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    RunTimeMs = 60000;
    TryGetValue(argc, argv, "timeout", &RunTimeMs);
    FuzzData = new FuzzingData();
    if (!FuzzData->Initialize()) {
        return 0;
    }
    start();

    return 0;
}

#endif // FUZZING
