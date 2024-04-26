/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Test Helpers

--*/

#ifdef QUIC_CLOG
#include "TestHelpers.h.clog.h"
#endif

extern bool UseDuoNic;

//
// Connect to the duonic address (if using duonic) or localhost (if not).
//
#define QUIC_TEST_LOOPBACK_FOR_AF(Af) (UseDuoNic ? ((Af == QUIC_ADDRESS_FAMILY_INET) ? "192.168.1.11" : "fc00::1:11") : QUIC_LOCALHOST_FOR_AF(Af))

//
// Set a QUIC_ADDR to the duonic "server" address.
//
inline
void
QuicAddrSetToDuoNic(
    _Inout_ QUIC_ADDR* Addr
    )
{
    if (QuicAddrGetFamily(Addr) == QUIC_ADDRESS_FAMILY_INET) {
        // 192.168.1.11
        ((uint32_t*)&(Addr->Ipv4.sin_addr))[0] = 184658112;
    } else {
        CXPLAT_DBG_ASSERT(QuicAddrGetFamily(Addr) == QUIC_ADDRESS_FAMILY_INET6);
        // fc00::1:11
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[0] = 252;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[1] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[2] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[3] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[4] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[5] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[6] = 256;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[7] = 4352;
    }
}

inline
uint32_t
QuitTestGetDatapathFeatureFlags() {
    static uint32_t Length = sizeof(uint32_t);
    uint32_t Features = 0;
    MsQuic->GetParam(
        nullptr,
        QUIC_PARAM_GLOBAL_DATAPATH_FEATURES,
        &Length,
        &Features);
    return Features;
}

inline
bool
QuitTestIsFeatureSupported(uint32_t Feature) {
    return static_cast<bool>(QuitTestGetDatapathFeatureFlags() & Feature);
}

#include "msquic.hpp"
#include "quic_toeplitz.h"

#define OLD_SUPPORTED_VERSION       QUIC_VERSION_1_MS_H
#define LATEST_SUPPORTED_VERSION    QUIC_VERSION_LATEST_H

const uint16_t TestUdpPortBase = 0x8000;

#define QUIC_TEST_NO_ERROR          0
#define QUIC_TEST_SESSION_CLOSED    1
#define QUIC_TEST_SPECIAL_ERROR     0x1234

struct TestScopeLogger {
    const char* Name;
    TestScopeLogger(const char* name) : Name(name) {
        QuicTraceLogInfo(
            TestScopeEntry,
            "[test]---> %s",
            Name);
    }
    ~TestScopeLogger() {
        QuicTraceLogInfo(
            TestScopeExit,
            "[test]<--- %s",
            Name);
    }
};

class TestConnection;

struct ServerAcceptContext {
    CXPLAT_EVENT NewConnectionReady;
    TestConnection** NewConnection;
    void* NewStreamHandler{nullptr};
    QUIC_TLS_SECRETS* TlsSecrets{nullptr};
    QUIC_STATUS ExpectedTransportCloseStatus{QUIC_STATUS_SUCCESS};
    QUIC_STATUS ExpectedClientCertValidationResult[2]{};
    uint32_t ExpectedClientCertValidationResultCount{0};
    QUIC_STATUS PeerCertEventReturnStatus{false};
    QUIC_PRIVATE_TRANSPORT_PARAMETER* TestTP{nullptr};
    bool AsyncCustomTicketValidation{false};
    QUIC_STATUS ExpectedCustomTicketValidationResult{QUIC_STATUS_SUCCESS};
    bool AsyncCustomCertValidation{false};
    bool IsCustomCertValidationResultSet{false};
    bool CustomCertValidationResult{false};
    ServerAcceptContext(TestConnection** _NewConnection) :
        NewConnection(_NewConnection) {
        CxPlatEventInitialize(&NewConnectionReady, TRUE, FALSE);
    }
    ~ServerAcceptContext() {
        CxPlatEventUninitialize(NewConnectionReady);
    }
    void AddExpectedClientCertValidationResult(QUIC_STATUS Status) {
        CXPLAT_FRE_ASSERTMSG(
            ExpectedClientCertValidationResultCount < ARRAYSIZE(ExpectedClientCertValidationResult),
            "Only two expected values supported.");
        ExpectedClientCertValidationResult[ExpectedClientCertValidationResultCount++] = Status;
    }
};

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
struct ClearGlobalVersionListScope {
    ~ClearGlobalVersionListScope() {
        MsQuicVersionSettings Settings(nullptr, 0);
        BOOLEAN Default = FALSE;

        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                sizeof(Settings),
                &Settings));
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                NULL,
                QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED,
                sizeof(Default),
                &Default));
    }
};
#endif

//
// Simulating Connection's status to be QUIC_CONN_BAD_START_STATE
// ConnectionStart -> ConnectionShutdown
//
inline
void SimulateConnBadStartState(MsQuicConnection& Connection, MsQuicConfiguration& Configuration) {
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            Configuration,
            QUIC_ADDRESS_FAMILY_INET,
            "localhost",
            4433));
    CxPlatSleep(100);

    Connection.Shutdown(
        QUIC_TEST_NO_ERROR,
        QUIC_CONNECTION_SHUTDOWN_FLAG_NONE);
}

//
// almost all Parameter for GetParam is
// 1. call with only BufferLength pointer
// 2. return QUIC_STATUS_BUFFER_TOO_SMALL by filling value in BufferLength
// 3. call again to get actual value in Buffer
//
inline
void SimpleGetParamTest(HQUIC Handle, uint32_t Param, size_t ExpectedLength, void* ExpectedData, bool GreaterOrEqualLength = false) {
    uint32_t Length = 0;
    TEST_QUIC_STATUS(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        MsQuic->GetParam(
                Handle,
                Param,
                &Length,
                nullptr));
    if (GreaterOrEqualLength) {
        if (Length < ExpectedLength) {
            TEST_FAILURE("ExpectedLength (%u) > Length (%u)", ExpectedLength, Length);
            return;
        }
    } else {
        if (ExpectedLength != Length) {
            TEST_FAILURE("ExpectedLength (%u) != Length (%u)", ExpectedLength, Length);
            return;
        }
    }

    Length = (uint32_t)ExpectedLength; // Only query the expected size, which might be less.
    void* Value = CXPLAT_ALLOC_NONPAGED(Length, QUIC_POOL_TEST);
    if (Value == nullptr) {
        TEST_FAILURE("Out of memory for testing SetParam for global parameter");
        return;
    }
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Handle,
            Param,
            &Length,
            Value));

    // if SetParam is not allowed and have random value
    if (ExpectedData) {
        TEST_EQUAL(memcmp(Value, ExpectedData, ExpectedLength), 0);
    }

    if (Value != nullptr) {
        CXPLAT_FREE(Value, QUIC_POOL_TEST);
    }
}

//
// Global parameter setting might affect other tests' behavior.
// This sets back the original value
//
struct GlobalSettingScope {
    uint32_t Parameter;
    uint32_t BufferLength {0};
    void* OriginalValue {nullptr};
    GlobalSettingScope(uint32_t Parameter) : Parameter(Parameter) {
         // can be both too samll or success
        auto Status = MsQuic->GetParam(
                nullptr,
                Parameter,
                &BufferLength,
                nullptr);
        TEST_TRUE(Status == QUIC_STATUS_BUFFER_TOO_SMALL || Status == QUIC_STATUS_SUCCESS);

        if (BufferLength != 0) {
            OriginalValue = CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_TEST);
            if (OriginalValue == nullptr) {
                TEST_FAILURE("Out of memory for testing SetParam for global parameter");
            }
            TEST_QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    nullptr,
                    Parameter,
                    &BufferLength,
                    OriginalValue));
        }
    }

    ~GlobalSettingScope() {
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                nullptr,
                Parameter,
                BufferLength,
                OriginalValue));
        if (OriginalValue != nullptr) {
            CXPLAT_FREE(OriginalValue, QUIC_POOL_TEST);
        }
    }
};

//
// No 64-bit version for this existed globally. This defines an interlocked
// helper for subtracting 64-bit numbers.
//
inline
int64_t
InterlockedSubtract64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend,
    _In_ int64_t Value
    ) {
    return InterlockedExchangeAdd64(Addend, -Value) - Value;
}

//
// Helper function to get a resumption ticket.
//
// TODO - Schannel currently requires the same configurations to be used for
// resumption to work. Once this is fixed, we shouldn't need to pass in any
// input parameters to make this work.
//
void
QuicTestPrimeResumption(
    _In_ QUIC_ADDRESS_FAMILY QuicAddrFamily,
    _In_ MsQuicRegistration& Registration,
    _In_ MsQuicConfiguration& ServerConfiguration,
    _In_ MsQuicConfiguration& ClientConfiguration,
    _Out_ QUIC_BUFFER** ResumptionTicket
    );

struct StatelessRetryHelper
{
    bool DoRetry;
    StatelessRetryHelper(bool Enabled) : DoRetry(Enabled) {
        if (DoRetry) {
            uint16_t value = 0;
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                    sizeof(value),
                    &value));
        }
    }
    ~StatelessRetryHelper() {
        if (DoRetry) {
            uint16_t value = 65;
            TEST_QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                    sizeof(value),
                    &value));
        }
    }
};

#define PRIVATE_TP_TYPE   77
#define PRIVATE_TP_LENGTH 2345
#define PRIVATE_TP_LENGTH_HUGE 4134

struct PrivateTransportHelper : QUIC_PRIVATE_TRANSPORT_PARAMETER
{
    PrivateTransportHelper(bool Enabled, bool Resumption = false) {
        if (Enabled) {
            Type = PRIVATE_TP_TYPE;
            Length = Resumption ? PRIVATE_TP_LENGTH : PRIVATE_TP_LENGTH_HUGE;
            Buffer = new(std::nothrow) uint8_t[Length];
            TEST_TRUE(Buffer != nullptr);
        } else {
            Buffer = nullptr;
        }
    }
    ~PrivateTransportHelper() {
        delete [] Buffer;
    }
};

struct DatapathHook
{
    DatapathHook* Next;

    DatapathHook() : Next(nullptr) { }

    virtual ~DatapathHook() { }

    virtual
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    Create(
        _Inout_opt_ QUIC_ADDR* /* RemoteAddress */,
        _Inout_opt_ QUIC_ADDR* /* LocalAddress */
        ) {
    }

    virtual
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    GetLocalAddress(
        _Inout_ QUIC_ADDR* /* Address */
        ) {
    }

    virtual
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    GetRemoteAddress(
        _Inout_ QUIC_ADDR* /* Address */
        ) {
    }

    virtual
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* /* Datagram */
        ) {
        return FALSE; // Don't drop by default
    }

    virtual
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* /* RemoteAddress */,
        _Inout_opt_ QUIC_ADDR* /* LocalAddress */,
        _Inout_ struct CXPLAT_SEND_DATA* /* SendData */
        ) {
        return FALSE; // Don't drop by default
    }
};

class DatapathHooks
{
    static QUIC_TEST_DATAPATH_HOOKS FuncTable;

    DatapathHook* Hooks;
    CXPLAT_DISPATCH_LOCK Lock;

    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    QUIC_API
    CreateCallback(
        _Inout_opt_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress
        ) {
        return Instance->Create(RemoteAddress, LocalAddress);
    }

    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    QUIC_API
    GetLocalAddressCallback(
        _Inout_ QUIC_ADDR* Address
        ) {
        return Instance->GetLocalAddress(Address);
    }

    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    QUIC_API
    GetRemoteAddressCallback(
        _Inout_ QUIC_ADDR* Address
        ) {
        return Instance->GetRemoteAddress(Address);
    }

    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    QUIC_API
    ReceiveCallback(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        return Instance->Receive(Datagram);
    }

    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    QUIC_API
    SendCallback(
        _Inout_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress,
        _Inout_ struct CXPLAT_SEND_DATA* SendData
        ) {
        return Instance->Send(RemoteAddress, LocalAddress, SendData);
    }

    void Register() {
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
        QuicTraceLogInfo(
            TestHookRegister,
            "[test][hook] Registering");
        QUIC_TEST_DATAPATH_HOOKS* Value = &FuncTable;
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS,
                sizeof(Value),
                &Value));
#endif
    }

    void Unregister() {
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
        QuicTraceLogInfo(
            TestHookUnregistering,
            "[test][hook] Unregistering");
        QUIC_TEST_DATAPATH_HOOKS* Value = nullptr;
        uint32_t TryCount = 0;
        while (TryCount++ < 20) {
            if (QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS,
                    sizeof(Value),
                    &Value))) {
                break;
            }
            CxPlatSleep(100); // Let the current datapath queue drain.
        }
        if (TryCount == 20) {
            TEST_FAILURE("Failed to disable test datapath hook");
        }
        QuicTraceLogInfo(
            TestHookUnregistered,
            "[test][hook] Unregistered");
#endif
    }

    void
    Create(
        _Inout_opt_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress
        ) {
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            Iter->Create(RemoteAddress, LocalAddress);
            Iter = Iter->Next;
        }
        CxPlatDispatchLockRelease(&Lock);
    }

    void
    GetLocalAddress(
        _Inout_ QUIC_ADDR* Address
        ) {
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            Iter->GetLocalAddress(Address);
            Iter = Iter->Next;
        }
        CxPlatDispatchLockRelease(&Lock);
    }

    void
    GetRemoteAddress(
        _Inout_ QUIC_ADDR* Address
        ) {
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            Iter->GetRemoteAddress(Address);
            Iter = Iter->Next;
        }
        CxPlatDispatchLockRelease(&Lock);
    }

    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        BOOLEAN Result = FALSE;
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            if (Iter->Receive(Datagram)) {
                Result = TRUE;
                break;
            }
            Iter = Iter->Next;
        }
        CxPlatDispatchLockRelease(&Lock);
        return Result;
    }

    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress,
        _Inout_ struct CXPLAT_SEND_DATA* SendData
        ) {
        BOOLEAN Result = FALSE;
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            if (Iter->Send(RemoteAddress, LocalAddress, SendData)) {
                Result = TRUE;
                break;
            }
            Iter = Iter->Next;
        }
        CxPlatDispatchLockRelease(&Lock);
        return Result;
    }

public:

    static DatapathHooks* Instance;

    DatapathHooks() : Hooks(nullptr) {
        CxPlatDispatchLockInitialize(&Lock);
    }

    ~DatapathHooks() {
        CxPlatDispatchLockUninitialize(&Lock);
    }

    void AddHook(DatapathHook* Hook) {
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook** Iter = &Hooks;
        while (*Iter != nullptr) {
            Iter = &((*Iter)->Next);
        }
        *Iter = Hook;
        bool DoRegister = Hooks == Hook;
        CxPlatDispatchLockRelease(&Lock);
        if (DoRegister) {
            Register();
        }
    }

    void RemoveHook(DatapathHook* Hook) {
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook** Iter = &Hooks;
        while (*Iter != Hook) {
            Iter = &((*Iter)->Next);
        }
        *Iter = Hook->Next;
        bool DoUnregister = Hooks == nullptr;
        CxPlatDispatchLockRelease(&Lock);
        if (DoUnregister) {
            Unregister();
        }
    }
};

struct EcnModifyHelper : public DatapathHook
{
    CXPLAT_ECN_TYPE EcnType = CXPLAT_ECN_NON_ECT;
    EcnModifyHelper() {
        DatapathHooks::Instance->AddHook(this);
    }
    ~EcnModifyHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    void SetEcnType(CXPLAT_ECN_TYPE Type) { EcnType = Type; }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        Datagram->TypeOfService = (uint8_t)EcnType;
        return false;
    }
};

struct RandomLossHelper : public DatapathHook
{
    uint8_t LossPercentage;
    RandomLossHelper(uint8_t _LossPercentage) : LossPercentage(_LossPercentage) {
        if (LossPercentage != 0) {
            DatapathHooks::Instance->AddHook(this);
        }
    }
    ~RandomLossHelper() {
        if (LossPercentage != 0) {
            DatapathHooks::Instance->RemoveHook(this);
        }
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* /* Datagram */
        ) {
        uint8_t RandomValue;
        CxPlatRandom(sizeof(RandomValue), &RandomValue);
        auto Result = (RandomValue % 100) < LossPercentage;
        if (Result) {
            QuicTraceLogVerbose(
                TestHookDropPacketRandom,
                "[test][hook] Random packet drop");
        }
        return Result;
    }
};

struct SelectiveLossHelper : public DatapathHook
{
    uint32_t DropPacketCount;
    SelectiveLossHelper(uint32_t Count = 0) : DropPacketCount(Count) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~SelectiveLossHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    void DropPackets(uint32_t Count) { DropPacketCount = Count; }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* /* Datagram */
        ) {
        if (DropPacketCount == 0) {
            return FALSE;
        }
        QuicTraceLogVerbose(
            TestHookDropPacketSelective,
            "[test][hook] Selective packet drop");
        DropPacketCount--;
        return TRUE;
    }
};

struct NthLossHelper : public DatapathHook
{
    uint32_t DropPacketIndex;
    NthLossHelper(uint32_t Index = UINT32_MAX) : DropPacketIndex(Index) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~NthLossHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    void DropIndex(uint32_t Index) { DropPacketIndex = Index; }
    bool Dropped() { return DropPacketIndex == UINT32_MAX; }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* /* Datagram */
        ) {
        if (DropPacketIndex == UINT32_MAX) { return FALSE; }
        if (DropPacketIndex == 0) {
            DropPacketIndex = UINT32_MAX;
            QuicTraceLogVerbose(
                TestHookDropPacketNth,
                "[test][hook] Nth packet drop");
            return TRUE;
        }
        --DropPacketIndex;
        return FALSE;
    }
};

struct BitmapLossHelper : public DatapathHook
{
    long RxCount {0};
    uint64_t LossBitmap; // a 1 indicates drop
    BitmapLossHelper(uint64_t Bitmap) : LossBitmap(Bitmap) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~BitmapLossHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* /* Datagram */
        ) {
        uint32_t RxNumber = (uint32_t)(InterlockedIncrement(&RxCount) - 1);
        if (RxNumber >= 64 || !(LossBitmap & (uint64_t)(1ull << RxNumber))) {
            return FALSE;
        }
        QuicTraceLogVerbose(
            TestHookDropPacketBitmap,
            "[test][hook] Bitmap packet drop");
        return TRUE;
    }
};

struct MtuDropHelper : public DatapathHook
{
    uint16_t ServerDropPacketSize;
    uint16_t ServerDropPort;
    uint16_t ClientDropPacketSize;
    MtuDropHelper(uint16_t ServerPacket, uint16_t ServerPort, uint16_t ClientPacket) :
        ServerDropPacketSize(ServerPacket), ServerDropPort(ServerPort),
        ClientDropPacketSize(ClientPacket) {
        if (ServerDropPacketSize != 0 || ClientDropPacketSize != 0) {
            DatapathHooks::Instance->AddHook(this);
        }
    }
    ~MtuDropHelper() {
        if (ServerDropPacketSize != 0 || ClientDropPacketSize != 0) {
            DatapathHooks::Instance->RemoveHook(this);
        }
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        uint16_t PacketMtu =
            PacketSizeFromUdpPayloadSize(
                QuicAddrGetFamily(&Datagram->Route->RemoteAddress),
                Datagram->BufferLength);
        if (ServerDropPacketSize != 0 && PacketMtu > ServerDropPacketSize &&
            QuicAddrGetPort(&Datagram->Route->RemoteAddress) == ServerDropPort) {
            return TRUE;
        }
        if (ClientDropPacketSize != 0 && PacketMtu > ClientDropPacketSize &&
            QuicAddrGetPort(&Datagram->Route->RemoteAddress) != ServerDropPort) {
            return TRUE;
        }
        return FALSE;
    }
};

struct ReplaceAddressHelper : public DatapathHook
{
    QUIC_ADDR Original;
    QUIC_ADDR New;
    ReplaceAddressHelper(const QUIC_ADDR& OrigAddr) :
        Original(OrigAddr), New(OrigAddr) {
        DatapathHooks::Instance->AddHook(this);
    }
    ReplaceAddressHelper(const QUIC_ADDR& OrigAddr, const QUIC_ADDR& NewAddr) :
        Original(OrigAddr), New(NewAddr) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~ReplaceAddressHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    void IncrementPort() {
        CXPLAT_DBG_ASSERT(QuicAddrGetPort(&New) != 0xFFFF);
        QuicAddrSetPort(&New, (uint16_t)1 + QuicAddrGetPort(&New));
    }
    void IncrementAddr() {
        QuicAddrIncrement(&New);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        if (QuicAddrCompare(
                &Datagram->Route->RemoteAddress,
                &Original)) {
            Datagram->Route->RemoteAddress = New;
            QuicTraceLogVerbose(
                TestHookReplaceAddrRecv,
                "[test][hook] Recv Addr :%hu => :%hu",
                QuicAddrGetPort(&Original),
                QuicAddrGetPort(&New));
        }
        return FALSE;
    }
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* /* LocalAddress */,
        _Inout_ struct CXPLAT_SEND_DATA* /* SendData */
        ) {
        if (QuicAddrCompare(RemoteAddress, &New)) {
            *RemoteAddress = Original;
            QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&New),
                QuicAddrGetPort(&Original));
        } else if (QuicAddrCompare(RemoteAddress, &Original)) {
            QuicTraceLogVerbose(
                TestHookDropOldAddrSend,
                "[test][hook] Dropping send to old addr");
            return TRUE; // Drop if it tries to explicitly send to the old address.
        }
        return FALSE;
    }
};

struct ReplaceAddressThenDropHelper : public DatapathHook
{
    QUIC_ADDR Original;
    QUIC_ADDR New;
    uint32_t AllowPacketCount;
    ReplaceAddressThenDropHelper(const QUIC_ADDR& OrigAddr, const QUIC_ADDR& NewAddr, uint32_t AllowCount) :
        Original(OrigAddr), New(NewAddr), AllowPacketCount(AllowCount) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~ReplaceAddressThenDropHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        if (QuicAddrCompare(
                &Datagram->Route->RemoteAddress,
                &Original)) {
            if (AllowPacketCount == 0) {
                QuicTraceLogVerbose(
                    TestHookDropLimitAddrRecv,
                    "[test][hook] Dropping recv over limit to new addr");
                return TRUE; // Drop
            }
            AllowPacketCount--;
            Datagram->Route->RemoteAddress = New;
            QuicTraceLogVerbose(
                TestHookReplaceAddrRecv,
                "[test][hook] Recv Addr :%hu => :%hu",
                QuicAddrGetPort(&Original),
                QuicAddrGetPort(&New));
        }
        return FALSE;
    }
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* /* LocalAddress */,
        _Inout_ struct CXPLAT_SEND_DATA* /* SendData */
        ) {
        if (QuicAddrCompare(RemoteAddress, &New)) {
            if (AllowPacketCount == 0) {
                QuicTraceLogVerbose(
                    TestHookDropLimitAddrSend,
                    "[test][hook] Dropping send over limit to new addr");
                return TRUE; // Drop
            }
            AllowPacketCount--;
            *RemoteAddress = Original;
            QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&New),
                QuicAddrGetPort(&Original));
        } else if (QuicAddrCompare(RemoteAddress, &Original)) {
            QuicTraceLogVerbose(
                TestHookDropOldAddrSend,
                "[test][hook] Dropping send to old addr");
            return TRUE; // Drop if it tries to explicitly send to the old address.
        }
        return FALSE;
    }
};

struct LoadBalancerHelper : public DatapathHook
{
    CXPLAT_TOEPLITZ_HASH Toeplitz;
    QUIC_ADDR PublicAddress;
    const QUIC_ADDR* PrivateAddresses;
    uint32_t PrivateAddressesCount;
    LoadBalancerHelper(const QUIC_ADDR& Public, const QUIC_ADDR* Private, uint32_t PrivateCount) :
        PublicAddress(Public), PrivateAddresses(Private), PrivateAddressesCount(PrivateCount) {
        CxPlatRandom(CXPLAT_TOEPLITZ_KEY_SIZE, &Toeplitz.HashKey);
        CxPlatToeplitzHashInitialize(&Toeplitz);
        DatapathHooks::Instance->AddHook(this);
    }
    ~LoadBalancerHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    Create(
        _Inout_opt_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress
        ) {
        if (RemoteAddress && LocalAddress &&
            QuicAddrCompare(RemoteAddress, &PublicAddress)) {
            *RemoteAddress = MapSendToPublic(LocalAddress);
            QuicTraceLogVerbose(
                TestHookReplaceCreateSend,
                "[test][hook] Create (remote) Addr :%hu => :%hu",
                QuicAddrGetPort(&PublicAddress),
                QuicAddrGetPort(RemoteAddress));
        }
    }
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    GetLocalAddress(
        _Inout_ QUIC_ADDR* /* Address */
        ) {
    }
    _IRQL_requires_max_(PASSIVE_LEVEL)
    void
    GetRemoteAddress(
        _Inout_ QUIC_ADDR* Address
        ) {
        for (uint32_t i = 0; i < PrivateAddressesCount; ++i) {
            if (QuicAddrCompare(
                    Address,
                    &PrivateAddresses[i])) {
                *Address = PublicAddress;
                break;
            }
        }
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        for (uint32_t i = 0; i < PrivateAddressesCount; ++i) {
            if (QuicAddrCompare(
                    &Datagram->Route->RemoteAddress,
                    &PrivateAddresses[i])) {
                Datagram->Route->RemoteAddress = PublicAddress;
                QuicTraceLogVerbose(
                    TestHookReplaceAddrRecv,
                    "[test][hook] Recv Addr :%hu => :%hu",
                    QuicAddrGetPort(&PrivateAddresses[i]),
                    QuicAddrGetPort(&PublicAddress));
                break;
            }
        }
        return FALSE;
    }
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress,
        _Inout_ struct CXPLAT_SEND_DATA* /* SendData */
        ) {
        if (QuicAddrCompare(RemoteAddress, &PublicAddress)) {
            *RemoteAddress = MapSendToPublic(LocalAddress);
            QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&PublicAddress),
                QuicAddrGetPort(RemoteAddress));
        }
        return FALSE;
    }
private:
    const QUIC_ADDR& MapSendToPublic(_In_ const QUIC_ADDR* SourceAddress) {
        uint32_t Key = 0, Offset;
        CxPlatToeplitzHashComputeAddr(&Toeplitz, SourceAddress, &Key, &Offset);
        return PrivateAddresses[Key % PrivateAddressesCount];
    }
};

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
BOOLEAN
WaitForMsQuicInUse() {
    int Count = 0;
    BOOLEAN MsQuicInUse = FALSE;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t MsQuicInUseLen = sizeof(MsQuicInUse);
    do {
        CxPlatSleep(100);
        Status = MsQuic->GetParam(nullptr, QUIC_PARAM_GLOBAL_IN_USE, &MsQuicInUseLen, &MsQuicInUse);
    } while(!MsQuicInUse && Count++ < 100);

    return MsQuicInUse && Status == QUIC_STATUS_SUCCESS;
}
