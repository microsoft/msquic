/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Test Helpers

--*/

#ifdef QUIC_CLOG
#include "TestHelpers.h.clog.h"
#endif

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

struct QuicAddr {
    QUIC_ADDR SockAddr;
    QuicAddr() {
        QuicZeroMemory(&SockAddr, sizeof(SockAddr));
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af) {
        QuicZeroMemory(&SockAddr, sizeof(SockAddr));
        QuicAddrSetFamily(&SockAddr, af);
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af, bool /*unused*/) {
        QuicZeroMemory(&SockAddr, sizeof(SockAddr));
        QuicAddrSetFamily(&SockAddr, af);
        QuicAddrSetToLoopback(&SockAddr);
    }
    QuicAddr(const QuicAddr &Addr, uint16_t Port) {
        SockAddr = Addr.SockAddr;
        QuicAddrSetPort(&SockAddr, Port);
    }
    void IncrementPort() {
        TEST_NOT_EQUAL(0xFFFF, QuicAddrGetPort(&SockAddr));
        QuicAddrSetPort(&SockAddr, (uint16_t)1 + QuicAddrGetPort(&SockAddr));
    }
    void IncrementAddr() {
        QuicAddrIncrement(&SockAddr);
    }
    uint16_t GetPort() const { return QuicAddrGetPort(&SockAddr); }
};

template<class T>
class UniquePtr {
    T* ptr;
public:
    UniquePtr() : ptr(nullptr) { }
    UniquePtr(T* _ptr) : ptr(_ptr) { }
    ~UniquePtr() { delete ptr; }
    T* get() { return ptr; }
    const T* get() const { return ptr; }
    T& operator*() const { return *ptr; }
    T* operator->() const { return ptr; }
    operator bool() const { return ptr != nullptr; }
    bool operator == (T* _ptr) const { return ptr == _ptr; }
    bool operator != (T* _ptr) const { return ptr != _ptr; }
};

template<class T>
class UniquePtrArray {
    T* ptr;
public:
    UniquePtrArray() : ptr(nullptr) { }
    UniquePtrArray(T* _ptr) : ptr(_ptr) { }
    ~UniquePtrArray() { delete [] ptr; }
    T* get() { return ptr; }
    const T* get() const { return ptr; }
    T& operator*() const { return *ptr; }
    T* operator->() const { return ptr; }
    operator bool() const { return ptr != nullptr; }
    bool operator == (T* _ptr) const { return ptr == _ptr; }
    bool operator != (T* _ptr) const { return ptr != _ptr; }
};

class MsQuicRegistration {
    HQUIC Registration;
public:
    MsQuicRegistration() {
        QuicZeroMemory(&Registration, sizeof(Registration));
        if (QUIC_FAILED(MsQuic->RegistrationOpen(nullptr, &Registration))) {
            Registration = nullptr;
        }
    }
    ~MsQuicRegistration() {
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
    }
    bool IsValid() const { return Registration != nullptr; }
    MsQuicRegistration(MsQuicRegistration& other) = delete;
    MsQuicRegistration operator=(MsQuicRegistration& Other) = delete;
    operator HQUIC () {
        return Registration;
    }
};

struct MsQuicSession {
    HQUIC Handle;
    bool CloseAllConnectionsOnDelete;
    MsQuicSession(_In_z_ const char* RawAlpn = "MsQuicTest")
        : Handle(nullptr), CloseAllConnectionsOnDelete(false) {
        QUIC_BUFFER Alpn;
        Alpn.Buffer = (uint8_t*)RawAlpn;
        Alpn.Length = (uint32_t)strlen(RawAlpn);
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Registration,
                &Alpn,
                1,
                nullptr,
                &Handle))) {
            Handle = nullptr;
        }
    }
    MsQuicSession(_In_z_ const char* RawAlpn1, _In_z_ const char* RawAlpn2)
        : Handle(nullptr), CloseAllConnectionsOnDelete(false) {
        QUIC_BUFFER Alpns[2];
        Alpns[0].Buffer = (uint8_t*)RawAlpn1;
        Alpns[0].Length = (uint32_t)strlen(RawAlpn1);
        Alpns[1].Buffer = (uint8_t*)RawAlpn2;
        Alpns[1].Length = (uint32_t)strlen(RawAlpn2);
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Registration,
                Alpns,
                ARRAYSIZE(Alpns),
                nullptr,
                &Handle))) {
            Handle = nullptr;
        }
    }
    ~MsQuicSession() {
        if (Handle != nullptr) {
            if (CloseAllConnectionsOnDelete) {
                MsQuic->SessionShutdown(
                    Handle,
                    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
                    QUIC_TEST_SESSION_CLOSED);
            }
            MsQuic->SessionClose(Handle);
        }
    }
    bool IsValid() const {
        return Handle != nullptr;
    }
    MsQuicSession(MsQuicSession& other) = delete;
    MsQuicSession operator=(MsQuicSession& Other) = delete;
    operator HQUIC () {
        return Handle;
    }
    void SetAutoCleanup() {
        CloseAllConnectionsOnDelete = true;
    }
    void Shutdown(
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
        _In_ QUIC_UINT62 ErrorCode
        ) {
        MsQuic->SessionShutdown(Handle, Flags, ErrorCode);
    }
    QUIC_STATUS
    SetTlsTicketKey(
        _In_reads_bytes_(44)
            const uint8_t* const Buffer
        ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_TLS_TICKET_KEY,
                44,
                Buffer);
    }
    QUIC_STATUS
    SetPeerBidiStreamCount(
        uint16_t value
        ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT,
                sizeof(value),
                &value);
    }
    QUIC_STATUS
    SetPeerUnidiStreamCount(
        uint16_t value
        ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT,
                sizeof(value),
                &value);
    }
    QUIC_STATUS
    SetIdleTimeout(
        uint64_t value  // milliseconds
        ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_IDLE_TIMEOUT,
                sizeof(value),
                &value);
    }
    QUIC_STATUS
    SetDisconnectTimeout(
        uint32_t value  // milliseconds
        ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_DISCONNECT_TIMEOUT,
                sizeof(value),
                &value);
    }
    QUIC_STATUS
    SetMaxBytesPerKey(
        uint64_t value
        ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY,
                sizeof(value),
                &value);
    }
    QUIC_STATUS
    SetDatagramReceiveEnabled(
        bool value
        ) {
        BOOLEAN Value = value ? TRUE : FALSE;
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED,
                sizeof(Value),
                &Value);
    }
    QUIC_STATUS
    SetServerResumptionLevel(
        QUIC_SERVER_RESUMPTION_LEVEL Level
    ) {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
                sizeof(Level),
                &Level);
    }
};

void
QuicTestPrimeResumption(
    MsQuicSession& Session,
    QUIC_ADDRESS_FAMILY Family,
    bool& Success
    );

struct ListenerScope {
    HQUIC Handle;
    ListenerScope() : Handle(nullptr) { }
    ListenerScope(HQUIC handle) : Handle(handle) { }
    ~ListenerScope() { if (Handle) { MsQuic->ListenerClose(Handle); } }
};

struct ConnectionScope {
    HQUIC Handle;
    ConnectionScope() : Handle(nullptr) { }
    ConnectionScope(HQUIC handle) : Handle(handle) { }
    ~ConnectionScope() { if (Handle) { MsQuic->ConnectionClose(Handle); } }
};

struct StreamScope {
    HQUIC Handle;
    StreamScope() : Handle(nullptr) { }
    StreamScope(HQUIC handle) : Handle(handle) { }
    ~StreamScope() { if (Handle) { MsQuic->StreamClose(Handle); } }
};

struct EventScope {
    QUIC_EVENT Handle;
    EventScope() { QuicEventInitialize(&Handle, FALSE, FALSE); }
    EventScope(QUIC_EVENT event) : Handle(event) { }
    ~EventScope() { QuicEventUninitialize(Handle); }
};

struct QuicBufferScope {
    QUIC_BUFFER* Buffer;
    QuicBufferScope() : Buffer(nullptr) { }
    QuicBufferScope(uint32_t Size) : Buffer((QUIC_BUFFER*) new uint8_t[sizeof(QUIC_BUFFER) + Size]) {
        QuicZeroMemory(Buffer, sizeof(*Buffer) + Size);
        Buffer->Length = Size;
        Buffer->Buffer = (uint8_t*)(Buffer + 1);
    }
    operator QUIC_BUFFER* () { return Buffer; }
    ~QuicBufferScope() { if (Buffer) { delete[](uint8_t*) Buffer; } }
};

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
            Buffer = new uint8_t[PRIVATE_TP_LENGTH];
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
        _Inout_ struct QUIC_RECV_DATAGRAM* /* Datagram */
        ) {
        return FALSE; // Don't drop by default
    }

    virtual
    _IRQL_requires_max_(PASSIVE_LEVEL)
    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* /* RemoteAddress */,
        _Inout_opt_ QUIC_ADDR* /* LocalAddress */,
        _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* /* SendContext */
        ) {
        return FALSE; // Don't drop by default
    }
};

class DatapathHooks
{
    static QUIC_TEST_DATAPATH_HOOKS FuncTable;

    DatapathHook* Hooks;
    QUIC_DISPATCH_LOCK Lock;

    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    QUIC_API
    ReceiveCallback(
        _Inout_ struct QUIC_RECV_DATAGRAM* Datagram
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
        _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* SendContext
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
            QuicSleep(100); // Let the current datapath queue drain.
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
        _Inout_ struct QUIC_RECV_DATAGRAM* Datagram
        ) {
        BOOLEAN Result = FALSE;
        QuicDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            if (Iter->Receive(Datagram)) {
                Result = TRUE;
                break;
            }
            Iter = Iter->Next;
        }
        QuicDispatchLockRelease(&Lock);
        return Result;
    }

    BOOLEAN
    Send(
        _Inout_ QUIC_ADDR* RemoteAddress,
        _Inout_opt_ QUIC_ADDR* LocalAddress,
        _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* SendContext
        ) {
        BOOLEAN Result = FALSE;
        QuicDispatchLockAcquire(&Lock);
        DatapathHook* Iter = Hooks;
        while (Iter) {
            if (Iter->Send(RemoteAddress, LocalAddress, SendContext)) {
                Result = TRUE;
                break;
            }
            Iter = Iter->Next;
        }
        QuicDispatchLockRelease(&Lock);
        return Result;
    }

public:

    static DatapathHooks* Instance;

    DatapathHooks() : Hooks(nullptr) {
        QuicDispatchLockInitialize(&Lock);
    }

    ~DatapathHooks() {
        QuicDispatchLockUninitialize(&Lock);
    }

    void AddHook(DatapathHook* Hook) {
        QuicDispatchLockAcquire(&Lock);
        DatapathHook** Iter = &Hooks;
        while (*Iter != nullptr) {
            Iter = &((*Iter)->Next);
        }
        *Iter = Hook;
        if (Hooks == Hook) {
            Register();
        }
        QuicDispatchLockRelease(&Lock);
    }

    void RemoveHook(DatapathHook* Hook) {
        QuicDispatchLockAcquire(&Lock);
        DatapathHook** Iter = &Hooks;
        while (*Iter != Hook) {
            Iter = &((*Iter)->Next);
        }
        *Iter = Hook->Next;
        if (Hooks == nullptr) {
            Unregister();
        }
        QuicDispatchLockRelease(&Lock);
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
        _Inout_ struct QUIC_RECV_DATAGRAM* /* Datagram */
        ) {
        uint8_t RandomValue;
        QuicRandom(sizeof(RandomValue), &RandomValue);
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
        _Inout_ struct QUIC_RECV_DATAGRAM* /* Datagram */
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
        _Inout_ struct QUIC_RECV_DATAGRAM* Datagram
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
        _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* /* SendContext */
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
        _Inout_ struct QUIC_RECV_DATAGRAM* Datagram
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
        _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* /* SendContext */
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
