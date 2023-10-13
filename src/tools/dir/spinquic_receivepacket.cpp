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
#include "precomp.h"
#include "msquichelper.h"
#include "msquic.hpp"


#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)
#define ASSERT_ON_NOT(x) CXPLAT_FRE_ASSERT(x)

const MsQuicApi* MsQuic;
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
    std::vector<size_t> EachSize;
    std::mutex mux;
    // TODO: support bit level pointers
    std::vector<size_t> Ptrs;
    std::vector<size_t> NumIterated;
    bool Cyclic;

    bool CheckBoundary(uint16_t ThreadId, size_t Adding) {
        // TODO: efficient cyclic access
        if (EachSize[ThreadId] < Ptrs[ThreadId] + Adding) {
            if (!Cyclic) {
                return false;
            }
            Ptrs[ThreadId] = 0;
            NumIterated[ThreadId]++;
        }
        return true;
    }
public:
    // 128 for main data, 20 for callback's issue workaround
    static const size_t MinDataSize = 148;
    static const size_t UtilityDataSize = 20;
    // hard code for determinisity
    static const uint16_t NumSpinThread = 2;

    FuzzingData() : data(nullptr), size(0), Ptrs({}), NumIterated({}), Cyclic(true) {}
    FuzzingData(const uint8_t* data, size_t size) : data(data), size(size - UtilityDataSize), Ptrs({}), NumIterated({}), Cyclic(true) {}
    bool Initialize() {
        // TODO: support non divisible size
        if (size % (size_t)NumSpinThread != 0 || size < (size_t)NumSpinThread * 8) {
            return false;
        }

        EachSize.resize(NumSpinThread + 1);
        std::fill(EachSize.begin(), EachSize.end(), size / (size_t)NumSpinThread);
        EachSize.back() = UtilityDataSize;
        Ptrs.resize(NumSpinThread + 1);
        std::fill(Ptrs.begin(), Ptrs.end(), 0);
        NumIterated.resize(NumSpinThread + 1);
        std::fill(NumIterated.begin(), NumIterated.end(), 0);
        return true;
    }
    bool TryGetByte(uint8_t* Val, uint16_t ThreadId = 0) {
        if (!CheckBoundary(ThreadId, 1)) {
            return false;
        }
        *Val = data[Ptrs[ThreadId]++ + EachSize[ThreadId] * ThreadId];
        return true;
    }
    bool TryGetBool(bool* Flag, uint16_t ThreadId = 0) {
        uint8_t Val = 0;
        if (TryGetByte(&Val, ThreadId)) {
            *Flag = (bool)(Val & 0b1);
            return true;
        }
        return false;
    }
    template<typename T>
    bool TryGetRandom(T UpperBound, T* Val, uint16_t ThreadId = 0) {
        int type_size = sizeof(T);
        if (!CheckBoundary(ThreadId, type_size)) {
            return false;
        }
        memcpy(Val, &data[Ptrs[ThreadId]] + EachSize[ThreadId] * ThreadId, type_size);
        *Val = (T)(*Val % UpperBound);
        Ptrs[ThreadId] += type_size;
        if (ThreadId == NumSpinThread) {
            mux.unlock();
        }
        return true;
    }
    size_t GetIterateCount(uint16_t ThreadId) {
        return NumIterated[ThreadId];
    }
};

static FuzzingData* FuzzData = nullptr;

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
    // WriteInitialCryptoFrame(
    //     Alpn, Sni, &CryptoBufferLength, BufferSize, CryptoBuffer);
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
    CxPlatSystemLoad();
    CxPlatInitialize();
    CxPlatDataPathInitialize(
        0,
        &DatapathCallbacks,
        NULL,
        NULL,
        &Datapath);
    QUIC_ADDR sockAddr;
    CxPlatDataPathResolveAddress(
                    Datapath,
                    Sni,
                    &sockAddr);
    QuicAddrSetPort(&sockAddr, 9999);
    MsQuic = new(std::nothrow) MsQuicApi();
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
    QUIC_STATUS Status =
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
    QUIC_ADDR_STR *str = nullptr;
    QuicAddrToString(&sockAddr, str);
    printf("Local address: %s\n", str->Address);
    //
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


    // make a client
    // make a random parameter generator using fuzzing data
    // make a initial packet
    // CXPLAT_SOCKET* Binding;
    // PacketWriter* Writer;
    // uint64_t PacketNumber = 0;
    // uint8_t Packet[512] = {0};
    // uint16_t PacketLength, HeaderLength;
    // Writer->WriteClientInitialPacket(
    //     PacketNumber,
    //     sizeof(uint64_t),
    //     sizeof(Packet),
    //     Packet,
    //     &PacketLength,
    //     &HeaderLength);

    // send the packet


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
main()
{
    FuzzData = new FuzzingData();
    // if (!FuzzData->Initialize()) {
    //     return 0;
    // }
    start();

    return 0;
}

#endif // FUZZING
