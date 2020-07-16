/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Perf Helpers

--*/

#pragma once

#ifdef QUIC_CLOG
#include "PerfHelpers.h.clog.h"
#endif

#include "PerfAbstractionLayer.h"
#include <quic_trace.h>
#include <msquic.h>
#include <quic_platform.h>
#include <msquichelper.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _KERNEL_MODE
#include <new> // Needed for placement new
#else
#include <new.h>
#endif

extern const QUIC_API_TABLE* MsQuic;
extern uint8_t SelfSignedSecurityHash[20];
extern bool IsSelfSignedValid;

#define QUIC_TEST_SESSION_CLOSED    1

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
    uint16_t GetPort() const { return QuicAddrGetPort(&SockAddr); }
};

template<typename T>
class UniquePtr {
public:
    UniquePtr() noexcept = default;

    explicit UniquePtr(T* _ptr) :
        ptr{_ptr}
    {
    }

    UniquePtr(const UniquePtr& other) = delete;
    UniquePtr& operator=(const UniquePtr& other) = delete;

    UniquePtr(UniquePtr&& other) noexcept {
        this->ptr = other->ptr;
        other->ptr = nullptr;
    }

    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
        this->ptr = other->ptr;
        other->ptr = nullptr;
    }

    ~UniquePtr() noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
    }

    void reset(T* lptr) noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
        this->ptr = lptr;
    }

    T* release() noexcept {
        auto tmp = ptr;
        ptr = nullptr;
        return tmp;
    }

    T* get() const noexcept { return ptr; }

    T& operator*() const { return *ptr; }
    T* operator->() const noexcept { return ptr; }
    operator bool() const noexcept { return ptr != nullptr; }
    bool operator == (T* _ptr) const noexcept { return ptr == _ptr; }
    bool operator != (T* _ptr) const noexcept { return ptr != _ptr; }

private:
    T* ptr = nullptr;
};

template<typename T>
class UniquePtr<T[]> {
public:
    UniquePtr() noexcept = default;

    explicit UniquePtr(T* _ptr) :
        ptr{_ptr}
    {
    }

    UniquePtr(const UniquePtr& other) = delete;
    UniquePtr& operator=(const UniquePtr& other) = delete;

    UniquePtr(UniquePtr&& other) noexcept {
        this->ptr = other->ptr;
        other->ptr = nullptr;
    }

    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = other->ptr;
        other->ptr = nullptr;
    }

    ~UniquePtr() noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
    }

    void reset(T* _ptr) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = _ptr;
    }

    T* release() noexcept {
        auto tmp = ptr;
        ptr = nullptr;
        return tmp;
    }

    T* get() const noexcept { return ptr; }

    T& operator[](size_t i) const {
        return *(ptr + i);
    }

    operator bool() const noexcept { return ptr != nullptr; }
    bool operator == (T* _ptr) const noexcept { return ptr == _ptr; }
    bool operator != (T* _ptr) const noexcept { return ptr != _ptr; }

private:
    T* ptr = nullptr;
};

inline
int
WriteOutput(
    _In_z_ const char* format
    ...
    )
{
#ifndef _KERNEL_MODE
    va_list args;
    va_start(args, format);
    int rval = vprintf(format, args);
    va_end(args);
    return rval;
#else
    UNREFERENCED_PARAMETER(format);
    return 0;
#endif
}

template<typename Ret, typename... Param>
struct CallableBase {
    CallableBase() = default;
    virtual ~CallableBase() noexcept = default;
    virtual Ret Invoke(Param... Event) = 0;
    virtual CallableBase<Ret, Param...>* Clone(void* Data) const = 0;
};


template<typename Ret, typename... Param>
struct FunctionCallable : public CallableBase<Ret, Param...> {
    Ret(*Callback)(Param...);

    FunctionCallable(Ret (*Callback)(Param...)) : Callback{ Callback } {}

    Ret Invoke(Param... Event) override {
        return Callback(Event...);
    }

    CallableBase<Ret, Param...>* Clone(void* Storage) const override {
        return new(Storage)FunctionCallable{ Callback };
    }
};

template<typename T, typename Ret, typename... Param>
struct MemberCallable : public CallableBase<Ret, Param...> {
    T* Obj;
    Ret(T::* Callback)(Param...);


    MemberCallable(Ret(T::* Callback)(Param...), T* obj) : Callback{ Callback }, Obj{ obj } {}

    Ret Invoke(Param... Event) override {
        return (Obj->*Callback)(Event...);
    }

    CallableBase<Ret, Param...>* Clone(void* Storage) const override {
        return new(Storage)MemberCallable{ Callback, Obj };
    }
};

template<typename Ret, typename... Param>
struct Function {
private:
    //
    // 3 pointers is the size of a pointer to member, plus an object
    //
    constexpr static size_t FunctionStorageSize = sizeof(void*) * 3;
    alignas(sizeof(void*)) unsigned char Data[Function<Ret, Param...>::FunctionStorageSize];

    CallableBase<Ret, Param...>* Callback = nullptr;

    void* Storage() { return Data; }

public:

    Function() = default;

    Function& operator=(const Function& other) {
        if (this->Callback) {
            this->Callback->~CallableBase();
            this->Callback = nullptr;
        }
        if (other.Callback) {
            this->Callback = other.Callback->Clone(Storage());
        }
        return *this;
    }

    Function(const Function& other) {
        if (other.Callback) {
            this->Callback = other.Callback->Clone(Storage());
        }
    }

    // Delete move
    Function(Function&& other) = delete;
    Function& operator=(Function&& other) = delete;

    ~Function() noexcept {
        if (Callback) {
            Callback->~CallableBase();
        }
    }

    template<typename T>
    Function(Ret(T::*callback)(Param...), T* obj) noexcept {
        static_assert(sizeof(MemberCallable<T, Ret, Param...>) <= FunctionStorageSize);
        Callback = new(Storage()) MemberCallable{ callback, obj };
    }

    Function(Ret(*callback)(Param...)) noexcept {
        static_assert(sizeof(FunctionCallable<Ret, Param...>) <= FunctionStorageSize);
        Callback = new(Storage()) FunctionCallable<Ret, Param...>{ callback };
    }

    Ret operator()(Param... param) {
        return Callback->Invoke(param...);
    }

    bool IsValid() const { return Callback != nullptr; }
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
    operator HQUIC () const {
        return Registration;
    }
};

struct MsQuicSession {
    HQUIC Handle;
    bool CloseAllConnectionsOnDelete;
    MsQuicSession(_In_ const MsQuicRegistration& Reg, _In_z_ const char* RawAlpn)
        : Handle(nullptr), CloseAllConnectionsOnDelete(false) {
        if (!Reg.IsValid()) {
            return;
        }
        QUIC_BUFFER Alpn;
        Alpn.Buffer = (uint8_t*)RawAlpn;
        Alpn.Length = (uint32_t)strlen(RawAlpn);
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Reg,
                &Alpn,
                1,
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
    operator HQUIC () const {
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

struct MsQuicListener {
    HQUIC Handle{ nullptr };
    Function<QUIC_STATUS, HQUIC, QUIC_LISTENER_EVENT*> Callback;
    MsQuicListener(const MsQuicSession& Session) {
        if (!Session.IsValid()) {
            return;
        }
        if (QUIC_FAILED(
            MsQuic->ListenerOpen(Session,
                [] (HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                    return ((MsQuicListener*)Context)->ListenerCallback(Listener, Event);
                },
                this,
                &Handle))) {
            Handle = nullptr;
        }
    }
    ~MsQuicListener() noexcept {
        if (Callback.IsValid()) {
            MsQuic->ListenerStop(Handle);
        }
        if (Handle) {
            MsQuic->ListenerClose(Handle);
        }
    }

    QUIC_STATUS
    Start(_In_ QUIC_ADDR* Address, const Function<QUIC_STATUS, HQUIC, QUIC_LISTENER_EVENT*>& Handler) {
        Callback = Handler;
        return MsQuic->ListenerStart(Handle, Address);
    }

    QUIC_STATUS
    ListenerCallback(HQUIC Listener, QUIC_LISTENER_EVENT* Event) {
        return Callback(Listener, Event);
    }

    bool IsValid() const { return Handle != nullptr; }
};

struct MsQuicSecurityConfig {
    QUIC_STATUS Initialize(int argc, char** argv, const MsQuicRegistration& Registration) {
        uint16_t useSelfSigned = 0;
        if (TryGetValue(argc, argv, "selfsign", &useSelfSigned)) {
            if (!IsSelfSignedValid) {
                WriteOutput("Self Signed Not Configured Correctly\n");
                return QUIC_STATUS_INVALID_STATE;
            }
            CreateSecConfigHelper Helper;
            SecurityConfig =
                Helper.Create(
                    MsQuic,
                    Registration,
                    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
                    &SelfSignedSecurityHash,
                    nullptr);
            if (!SecurityConfig) {
                WriteOutput("Failed to create security config for self signed certificate\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else {
            // TODO
            WriteOutput("Non self signed not yet supported\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        return QUIC_STATUS_SUCCESS;
    }

    ~MsQuicSecurityConfig() {
        if (SecurityConfig) {
            MsQuic->SecConfigDelete(SecurityConfig);
        }
    }

    operator QUIC_SEC_CONFIG*() const { return SecurityConfig; }

    QUIC_SEC_CONFIG* SecurityConfig {nullptr};
};

struct ListenerScope {
    HQUIC Handle;
    ListenerScope() : Handle(nullptr) { }
    ListenerScope(HQUIC handle) : Handle(handle) { }
    ~ListenerScope() { if (Handle) { MsQuic->ListenerClose(Handle); } }
    operator HQUIC() const { return Handle; }
};

struct ConnectionScope {
    HQUIC Handle;
    ConnectionScope() : Handle(nullptr) { }
    ConnectionScope(HQUIC handle) : Handle(handle) { }
    ~ConnectionScope() { if (Handle) { MsQuic->ConnectionClose(Handle); } }
    operator HQUIC() const { return Handle; }
};

struct StreamScope {
    HQUIC Handle;
    StreamScope() : Handle(nullptr) { }
    StreamScope(HQUIC handle) : Handle(handle) { }
    ~StreamScope() { if (Handle) { MsQuic->StreamClose(Handle); } }
    operator HQUIC() const { return Handle; }
};

struct EventScope {
    QUIC_EVENT Handle;
    EventScope() { QuicEventInitialize(&Handle, FALSE, FALSE); }
    EventScope(QUIC_EVENT event) : Handle(event) { }
    ~EventScope() { QuicEventUninitialize(Handle); }
    operator QUIC_EVENT() const { return Handle; }
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


struct CountHelper {
    long RefCount;

    QUIC_EVENT Done;

    CountHelper() :
        RefCount{1}, Done{} {}

    CountHelper(QUIC_EVENT Done) :
        RefCount{1}, Done{Done} { }

    bool
    Wait(
        uint32_t Milliseconds
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return true;
        } else {
            return !QuicEventWaitWithTimeout(Done, Milliseconds);
        }
    }

    void
    WaitForever(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return;
        } else {
            QuicEventWaitForever(Done);
        }
    }

    void
    AddItem(
        ) {
        InterlockedIncrement(&RefCount);
    }

    void
    CompleteItem(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            QuicEventSet(Done);
        }
    }
};

struct PerfRunner {
    //
    // Virtual destructor so we can destruct the base class
    //
    virtual
    ~PerfRunner() = default;

    //
    // Called to initialize the runner.
    //
    virtual
    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) = 0;

    //
    // Start the runner. The StopEvent can be triggered to stop early
    // Passed here rather then Wait so we can synchronize off of it.
    // This event must be kept alive until Wait is called.
    //
    virtual
    QUIC_STATUS
    Start(
        _In_ QUIC_EVENT StopEvent
        ) = 0;

    //
    // Wait for a run to finish, until timeout.
    // If 0 or less, wait forever
    //
    virtual
    QUIC_STATUS
    Wait(
        int Timeout
        ) = 0;
};

//
// Arg Value Parsers
//

inline
_Success_(return != false)
bool
IsValue(
    _In_z_ const char* name,
    _In_z_ const char* toTestAgainst
    )
{
    return _strnicmp(name, toTestAgainst, min(strlen(name), strlen(toTestAgainst))) == 0;
}
