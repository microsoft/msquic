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

#ifndef _KERNEL_MODE
#include <new> // Needed for placement new
#else
#include <new.h>
#endif

extern const QUIC_API_TABLE* MsQuic;

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

    void reset(T* ptr) noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
        this->ptr = ptr;
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

    void reset(T* ptr) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = ptr;
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
    constexpr static size_t Max(size_t a, size_t b) { return a > b ? a : b; }
    struct Empty {
    };

    constexpr static size_t FunctionStorageSize = sizeof(void*) * 3;//Max(sizeof(FunctionCallable<Ret, Param...>), sizeof(MemberCallable<Empty, Ret, Param...>));
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
        Callback->~CallableBase();
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
    HQUIC Handle;
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


struct CountHelper {
    long RefCount;

    QUIC_EVENT Done;

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

//
// Arg Value Parsers
//

//
// Helper function that searches the list of args for a given
// parameter name, insensitive to case.
//
inline
_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 1; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0) {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return nullptr;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ _Null_terminated_ const char** pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = value;
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint8_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint8_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint16_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint16_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint32_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint32_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint64_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    char* End;
#ifdef _WIN32
    *pValue = _strtoui64(value, &End, 10);
#else
    *pValue = strtoull(value, &End, 10);
#endif
    return true;
}