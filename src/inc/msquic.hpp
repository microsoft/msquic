/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    C++ Declarations for the MsQuic API, which enables applications and
    drivers to create QUIC connections as a client or server.

    For more detailed information, see ../docs/API.md

Supported Platforms:

    Windows User mode
    Windows Kernel mode
    Linux User mode

--*/

#pragma once

#include <msquic.h>

struct QuicAddr {
    QUIC_ADDR SockAddr;
    QuicAddr() {
        QuicZeroMemory(&SockAddr, sizeof(SockAddr));
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af) {
        QuicZeroMemory(&SockAddr, sizeof(SockAddr));
        QuicAddrSetFamily(&SockAddr, af);
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af, uint16_t Port) {
        QuicZeroMemory(&SockAddr, sizeof(SockAddr));
        QuicAddrSetFamily(&SockAddr, af);
        QuicAddrSetPort(&SockAddr, Port);
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
        QUIC_DBG_ASSERT(QuicAddrGetPort(&SockAddr) != 0xFFFF);
        QuicAddrSetPort(&SockAddr, (uint16_t)1 + QuicAddrGetPort(&SockAddr));
    }
    void IncrementAddr() {
        QuicAddrIncrement(&SockAddr);
    }
    uint16_t GetPort() const { return QuicAddrGetPort(&SockAddr); }
    void SetPort(uint16_t Port) noexcept { QuicAddrSetPort(&SockAddr, Port); }
};

template<class T>
class UniquePtr {
public:
    UniquePtr() noexcept = default;

    explicit UniquePtr(T* _ptr) : ptr{_ptr} { }
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
        T* tmp = ptr;
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

    explicit UniquePtr(T* _ptr) : ptr{_ptr} { }

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
        T* tmp = ptr;
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

class QuicApiTable : public QUIC_API_TABLE {
    QUIC_STATUS Init;
    const QUIC_API_TABLE* ApiTable{nullptr};
public:
    QuicApiTable() noexcept {
        if (QUIC_SUCCEEDED(Init = MsQuicOpen(&ApiTable))) {
            QUIC_API_TABLE* thisTable = this;
            QuicCopyMemory(thisTable, ApiTable, sizeof(*ApiTable));
        }
    }

    ~QuicApiTable() noexcept {
        if (QUIC_SUCCEEDED(Init)) {
            MsQuicClose(ApiTable);
            ApiTable = nullptr;
            QUIC_API_TABLE* thisTable = this;
            QuicZeroMemory(thisTable, sizeof(*thisTable));
        }
    }

    QUIC_STATUS InitStatus() const noexcept {
        return Init;
    }
};

class MsQuicRegistration {
    HQUIC Registration;
    QUIC_STATUS InitStatus;
public:
    MsQuicRegistration() noexcept {
        QuicZeroMemory(&Registration, sizeof(Registration));
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->RegistrationOpen(
                    nullptr,
                    &Registration))) {
            Registration = nullptr;
        }
    }
    ~MsQuicRegistration() noexcept {
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept { return Registration != nullptr; }
    MsQuicRegistration(MsQuicRegistration& other) = delete;
    MsQuicRegistration operator=(MsQuicRegistration& Other) = delete;
    operator HQUIC () const noexcept {
        return Registration;
    }
};

class MsQuicSession {
    bool CloseAllConnectionsOnDelete {false};
    QUIC_STATUS InitStatus;
public:
    HQUIC Handle {nullptr};
    MsQuicSession(
        _In_ const MsQuicRegistration& Reg,
        _In_z_ const char* RawAlpn = "MsQuicTest") noexcept
        : CloseAllConnectionsOnDelete(false), Handle(nullptr) {
        if (!Reg.IsValid()) {
            InitStatus = Reg.GetInitStatus();
            return;
        }
        QUIC_BUFFER Alpn;
        Alpn.Buffer = (uint8_t*)RawAlpn;
        Alpn.Length = (uint32_t)strlen(RawAlpn);
        if (QUIC_FAILED(
                InitStatus =
                    MsQuic->SessionOpen(
                    Reg,
                    &Alpn,
                    1,
                    nullptr,
                    &Handle))) {
            Handle = nullptr;
        }
    }

#ifndef QUIC_SKIP_GLOBAL_CONSTRUCTORS

    MsQuicSession(_In_z_ const char* RawAlpn = "MsQuicTest") noexcept
        : CloseAllConnectionsOnDelete(false), Handle(nullptr) {
        QUIC_BUFFER Alpn;
        Alpn.Buffer = (uint8_t*)RawAlpn;
        Alpn.Length = (uint32_t)strlen(RawAlpn);
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->SessionOpen(
                    Registration,
                    &Alpn,
                    1,
                    nullptr,
                    &Handle))) {
            Handle = nullptr;
        }
    }
    MsQuicSession(_In_z_ const char* RawAlpn1, _In_z_ const char* RawAlpn2) noexcept
        : CloseAllConnectionsOnDelete(false), Handle(nullptr) {
        QUIC_BUFFER Alpns[2];
        Alpns[0].Buffer = (uint8_t*)RawAlpn1;
        Alpns[0].Length = (uint32_t)strlen(RawAlpn1);
        Alpns[1].Buffer = (uint8_t*)RawAlpn2;
        Alpns[1].Length = (uint32_t)strlen(RawAlpn2);
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->SessionOpen(
                    Registration,
                    Alpns,
                    ARRAYSIZE(Alpns),
                    nullptr,
                    &Handle))) {
            Handle = nullptr;
        }
    }
#endif
    ~MsQuicSession() noexcept {
        if (Handle != nullptr) {
            if (CloseAllConnectionsOnDelete) {
                MsQuic->SessionShutdown(
                    Handle,
                    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
                    1);
            }
            MsQuic->SessionClose(Handle);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept {
        return Handle != nullptr;
    }
    MsQuicSession(MsQuicSession& other) = delete;
    MsQuicSession operator=(MsQuicSession& Other) = delete;
    operator HQUIC () const noexcept {
        return Handle;
    }
    void SetAutoCleanup() noexcept {
        CloseAllConnectionsOnDelete = true;
    }
    void Shutdown(
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
        _In_ QUIC_UINT62 ErrorCode
        ) noexcept {
        MsQuic->SessionShutdown(Handle, Flags, ErrorCode);
    }
    QUIC_STATUS
    SetTlsTicketKey(
        _In_reads_bytes_(44)
            const uint8_t* const Buffer
        ) noexcept {
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
        ) noexcept {
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
        ) noexcept {
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
        ) noexcept {
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
        ) noexcept {
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
        ) noexcept {
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
        ) noexcept {
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
    ) noexcept {
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
    HQUIC Handle { nullptr };
    QUIC_STATUS InitStatus;
    QUIC_LISTENER_CALLBACK_HANDLER Handler { nullptr };
    void* Context{ nullptr };

    MsQuicListener(const MsQuicSession& Session) noexcept {
        if (!Session.IsValid()) {
            InitStatus = Session.GetInitStatus();
            return;
        }
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->ListenerOpen(
                    Session,
                    [](HQUIC Handle, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                        MsQuicListener* Listener = (MsQuicListener*)Context;
                        return Listener->Handler(Handle, Listener->Context, Event);
                    },
                    this,
                    &Handle))) {
            Handle = nullptr;
        }
    }
    ~MsQuicListener() noexcept {
        if (Handler != nullptr) {
            MsQuic->ListenerStop(Handle);
        }
        if (Handle) {
            MsQuic->ListenerClose(Handle);
        }
    }

    QUIC_STATUS
    Start(
        _In_ QUIC_ADDR* Address,
        _In_ QUIC_LISTENER_CALLBACK_HANDLER _Handler,
        _In_ void* _Context) noexcept {
        Handler = _Handler;
        Context = _Context;
        return MsQuic->ListenerStart(Handle, Address);
    }

    QUIC_STATUS
    ListenerCallback(HQUIC Listener, QUIC_LISTENER_EVENT* Event) noexcept {
        return Handler(Listener, Context, Event);
    }

    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const {
        return Handle != nullptr;
    }
    MsQuicListener(MsQuicListener& other) = delete;
    MsQuicListener operator=(MsQuicListener& Other) = delete;
    operator HQUIC () const noexcept {
        return Handle;
    }
};

struct ListenerScope {
    HQUIC Handle;
    ListenerScope() noexcept : Handle(nullptr) { }
    ListenerScope(HQUIC handle) noexcept : Handle(handle) { }
    ~ListenerScope() noexcept { if (Handle) { MsQuic->ListenerClose(Handle); } }
    operator HQUIC() const noexcept { return Handle; }
};

struct ConnectionScope {
    HQUIC Handle;
    ConnectionScope() noexcept : Handle(nullptr) { }
    ConnectionScope(HQUIC handle) noexcept : Handle(handle) { }
    ~ConnectionScope() noexcept { if (Handle) { MsQuic->ConnectionClose(Handle); } }
    operator HQUIC() const noexcept { return Handle; }
};

struct StreamScope {
    HQUIC Handle;
    StreamScope() noexcept : Handle(nullptr) { }
    StreamScope(HQUIC handle) noexcept : Handle(handle) { }
    ~StreamScope() noexcept { if (Handle) { MsQuic->StreamClose(Handle); } }
    operator HQUIC() const noexcept { return Handle; }
};

struct EventScope {
    QUIC_EVENT Handle;
    EventScope() noexcept { QuicEventInitialize(&Handle, FALSE, FALSE); }
    EventScope(bool ManualReset) noexcept { QuicEventInitialize(&Handle, ManualReset, FALSE); }
    EventScope(QUIC_EVENT event) noexcept : Handle(event) { }
    ~EventScope() noexcept { QuicEventUninitialize(Handle); }
    operator QUIC_EVENT() const noexcept { return Handle; }
};

struct QuicBufferScope {
    QUIC_BUFFER* Buffer;
    QuicBufferScope() noexcept : Buffer(nullptr) { }
    QuicBufferScope(uint32_t Size) noexcept : Buffer((QUIC_BUFFER*) new uint8_t[sizeof(QUIC_BUFFER) + Size]) {
        QuicZeroMemory(Buffer, sizeof(*Buffer) + Size);
        Buffer->Length = Size;
        Buffer->Buffer = (uint8_t*)(Buffer + 1);
    }
    operator QUIC_BUFFER* () noexcept { return Buffer; }
    ~QuicBufferScope() noexcept { if (Buffer) { delete[](uint8_t*) Buffer; } }
};
