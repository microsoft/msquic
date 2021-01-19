/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Test Helpers

--*/

#ifdef QUIC_CLOG
#include "TestHelpers.h.clog.h"
#endif

#include "msquic.hpp"

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
                    QUIC_PARAM_LEVEL_GLOBAL,
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
                    QUIC_PARAM_LEVEL_GLOBAL,
                    QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                    sizeof(value),
                    &value));
        }
    }
};

#define PRIVATE_TP_TYPE   77
#define PRIVATE_TP_LENGTH 2345

struct PrivateTransportHelper : QUIC_PRIVATE_TRANSPORT_PARAMETER
{
    PrivateTransportHelper(bool Enabled) {
        if (Enabled) {
            Type = PRIVATE_TP_TYPE;
            Length = PRIVATE_TP_LENGTH;
            Buffer = new(std::nothrow) uint8_t[PRIVATE_TP_LENGTH];
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
        _Inout_ struct CXPLAT_SEND_DATA* /* SendContext */
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
        _Inout_ struct CXPLAT_SEND_DATA* SendContext
        ) {
        return Instance->Send(RemoteAddress, LocalAddress, SendContext);
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
                QUIC_PARAM_LEVEL_GLOBAL,
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
                    QUIC_PARAM_LEVEL_GLOBAL,
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
        _Inout_ struct CXPLAT_SEND_DATA* SendContext
        ) {
        BOOLEAN Result = FALSE;
        CxPlatDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            if (Iter->Send(RemoteAddress, LocalAddress, SendContext)) {
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

struct ReplaceAddressHelper : public DatapathHook
{
    QUIC_ADDR Original;
    QUIC_ADDR New;
    ReplaceAddressHelper(const QUIC_ADDR& OrigAddr, const QUIC_ADDR& NewAddr) :
        Original(OrigAddr), New(NewAddr) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~ReplaceAddressHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        if (QuicAddrCompare(
                &Datagram->Tuple->RemoteAddress,
                &Original)) {
            Datagram->Tuple->RemoteAddress = New;
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
        _Inout_ struct CXPLAT_SEND_DATA* /* SendContext */
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
                &Datagram->Tuple->RemoteAddress,
                &Original)) {
            if (AllowPacketCount == 0) {
                QuicTraceLogVerbose(
                    TestHookDropLimitAddrRecv,
                    "[test][hook] Dropping recv over limit to new addr");
                return TRUE; // Drop
            }
            AllowPacketCount--;
            Datagram->Tuple->RemoteAddress = New;
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
        _Inout_ struct CXPLAT_SEND_DATA* /* SendContext */
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
