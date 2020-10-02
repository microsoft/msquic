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

#ifndef QUIC_DBG_ASSERT
#define QUIC_DBG_ASSERT(X) // no-op if not already defined
#endif

struct QuicAddr {
    QUIC_ADDR SockAddr;
    QuicAddr() {
        memset(&SockAddr, 0, sizeof(SockAddr));
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af) {
        memset(&SockAddr, 0, sizeof(SockAddr));
        QuicAddrSetFamily(&SockAddr, af);
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af, uint16_t Port) {
        memset(&SockAddr, 0, sizeof(SockAddr));
        QuicAddrSetFamily(&SockAddr, af);
        QuicAddrSetPort(&SockAddr, Port);
    }
    QuicAddr(QUIC_ADDRESS_FAMILY af, bool /*unused*/) {
        memset(&SockAddr, 0, sizeof(SockAddr));
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
        this->ptr = other.ptr;
        other.ptr = nullptr;
    }

    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
        this->ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
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
        this->ptr = other.ptr;
        other.ptr = nullptr;
    }

    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
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

class MsQuicApi : public QUIC_API_TABLE {
    const QUIC_API_TABLE* ApiTable {nullptr};
    QUIC_STATUS InitStatus;
public:
    MsQuicApi() noexcept {
        if (QUIC_SUCCEEDED(InitStatus = MsQuicOpen(&ApiTable))) {
            QUIC_API_TABLE* thisTable = this;
            memcpy(thisTable, ApiTable, sizeof(*ApiTable));
        }
    }
    ~MsQuicApi() noexcept {
        if (QUIC_SUCCEEDED(InitStatus)) {
            MsQuicClose(ApiTable);
            ApiTable = nullptr;
            QUIC_API_TABLE* thisTable = this;
            memset(thisTable, 0, sizeof(*thisTable));
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
};

extern const MsQuicApi* MsQuic;

class MsQuicRegistration {
    bool CloseAllConnectionsOnDelete {false};
    HQUIC Handle {nullptr};
    QUIC_STATUS InitStatus;
public:
    operator HQUIC () const noexcept { return Handle; }
    MsQuicRegistration(
        _In_ bool AutoCleanUp = false
        ) noexcept : CloseAllConnectionsOnDelete(AutoCleanUp) {
        InitStatus = MsQuic->RegistrationOpen(nullptr, &Handle);
    }
    MsQuicRegistration(
        _In_z_ const char* AppName,
        QUIC_EXECUTION_PROFILE Profile = QUIC_EXECUTION_PROFILE_LOW_LATENCY,
        _In_ bool AutoCleanUp = false
        ) noexcept : CloseAllConnectionsOnDelete(AutoCleanUp) {
        const QUIC_REGISTRATION_CONFIG RegConfig = { AppName, Profile };
        InitStatus = MsQuic->RegistrationOpen(&RegConfig, &Handle);
    }
    ~MsQuicRegistration() noexcept {
        if (Handle != nullptr) {
            if (CloseAllConnectionsOnDelete) {
                MsQuic->RegistrationShutdown(
                    Handle,
                    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
                    1);
            }
            MsQuic->RegistrationClose(Handle);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicRegistration(MsQuicRegistration& other) = delete;
    MsQuicRegistration operator=(MsQuicRegistration& Other) = delete;
    void Shutdown(
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
        _In_ QUIC_UINT62 ErrorCode
        ) noexcept {
        MsQuic->RegistrationShutdown(Handle, Flags, ErrorCode);
    }
};

class MsQuicAlpn {
    QUIC_BUFFER Buffers[2];
    uint32_t BuffersLength;
public:
    MsQuicAlpn(_In_z_ const char* RawAlpn1) noexcept {
        Buffers[0].Buffer = (uint8_t*)RawAlpn1;
        Buffers[0].Length = (uint32_t)strlen(RawAlpn1);
        BuffersLength = 1;
    }
    MsQuicAlpn(_In_z_ const char* RawAlpn1, _In_z_ const char* RawAlpn2) noexcept {
        Buffers[0].Buffer = (uint8_t*)RawAlpn1;
        Buffers[0].Length = (uint32_t)strlen(RawAlpn1);
        Buffers[1].Buffer = (uint8_t*)RawAlpn2;
        Buffers[1].Length = (uint32_t)strlen(RawAlpn2);
        BuffersLength = 2;
    }
    operator const QUIC_BUFFER* () const noexcept { return Buffers; }
    uint32_t Length() const noexcept { return BuffersLength; }
};

class MsQuicSettings : public QUIC_SETTINGS {
public:
    MsQuicSettings() noexcept { IsSetFlags = 0; }
    MsQuicSettings& SetSendBufferingEnabled(bool Value) { SendBufferingEnabled = Value; IsSet.SendBufferingEnabled = TRUE; return *this; }
    MsQuicSettings& SetPacingEnabled(bool Value) { PacingEnabled = Value; IsSet.PacingEnabled = TRUE; return *this; }
    MsQuicSettings& SetMigrationEnabled(bool Value) { MigrationEnabled = Value; IsSet.MigrationEnabled = TRUE; return *this; }
    MsQuicSettings& SetDatagramReceiveEnabled(bool Value) { DatagramReceiveEnabled = Value; IsSet.DatagramReceiveEnabled = TRUE; return *this; }
    MsQuicSettings& SetServerResumptionLevel(QUIC_SERVER_RESUMPTION_LEVEL Value) { ServerResumptionLevel = Value; IsSet.ServerResumptionLevel = TRUE; return *this; }
    MsQuicSettings& SetIdleTimeoutMs(uint64_t Value) { IdleTimeoutMs = Value; IsSet.IdleTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetHandshakeIdleTimeoutMs(uint64_t Value) { HandshakeIdleTimeoutMs = Value; IsSet.HandshakeIdleTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetDisconnectTimeoutMs(uint32_t Value) { DisconnectTimeoutMs = Value; IsSet.DisconnectTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetPeerBidiStreamCount(uint16_t Value) { PeerBidiStreamCount = Value; IsSet.PeerBidiStreamCount = TRUE; return *this; }
    MsQuicSettings& SetPeerUnidiStreamCount(uint16_t Value) { PeerUnidiStreamCount = Value; IsSet.PeerUnidiStreamCount = TRUE; return *this; }
    MsQuicSettings& SetMaxBytesPerKey(uint64_t Value) { MaxBytesPerKey = Value; IsSet.MaxBytesPerKey = TRUE; return *this; }
};

#ifndef QUIC_DEFAULT_CLIENT_CRED_FLAGS
#define QUIC_DEFAULT_CLIENT_CRED_FLAGS QUIC_CREDENTIAL_FLAG_CLIENT
#endif

class MsQuicCredentialConfig : public QUIC_CREDENTIAL_CONFIG {
public:
    MsQuicCredentialConfig(const QUIC_CREDENTIAL_CONFIG& Config) {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memcpy(thisStruct, &Config, sizeof(QUIC_CREDENTIAL_CONFIG));
    }
    MsQuicCredentialConfig(QUIC_CREDENTIAL_FLAGS _Flags = QUIC_DEFAULT_CLIENT_CRED_FLAGS) {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memset(thisStruct, 0, sizeof(QUIC_CREDENTIAL_CONFIG));
        Flags = _Flags;
    }
};

class MsQuicConfiguration {
    HQUIC Handle {nullptr};
    QUIC_STATUS InitStatus;
public:
    operator HQUIC () const noexcept { return Handle; }
    MsQuicConfiguration(
        _In_ const MsQuicRegistration& Reg,
        _In_ const MsQuicAlpn& Alpns
        )  {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            MsQuic->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                nullptr,
                0,
                nullptr,
                &Handle);
    }
    MsQuicConfiguration(
        _In_ const MsQuicRegistration& Reg,
        _In_ const MsQuicAlpn& Alpns,
        _In_ const MsQuicCredentialConfig& CredConfig
        )  {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            MsQuic->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                nullptr,
                0,
                nullptr,
                &Handle);
        if (IsValid()) {
            InitStatus = LoadCredential(&CredConfig);
        }
    }
    MsQuicConfiguration(
        _In_ const MsQuicRegistration& Reg,
        _In_ const MsQuicAlpn& Alpns,
        _In_ const MsQuicSettings& Settings
        ) noexcept {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            MsQuic->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                &Settings,
                sizeof(Settings),
                nullptr,
                &Handle);
    }
    MsQuicConfiguration(
        _In_ const MsQuicRegistration& Reg,
        _In_ const MsQuicAlpn& Alpns,
        _In_ const MsQuicSettings& Settings,
        _In_ const MsQuicCredentialConfig& CredConfig
        ) noexcept {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            MsQuic->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                &Settings,
                sizeof(Settings),
                nullptr,
                &Handle);
        if (IsValid()) {
            InitStatus = LoadCredential(&CredConfig);
        }
    }
    ~MsQuicConfiguration() noexcept {
        if (Handle != nullptr) {
            MsQuic->ConfigurationClose(Handle);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicConfiguration(MsQuicConfiguration& other) = delete;
    MsQuicConfiguration operator=(MsQuicConfiguration& Other) = delete;
    QUIC_STATUS
    LoadCredential(_In_ const QUIC_CREDENTIAL_CONFIG* CredConfig) noexcept {
        return MsQuic->ConfigurationLoadCredential(Handle, CredConfig);
    }
};

struct MsQuicListener {
    HQUIC Handle { nullptr };
    QUIC_STATUS InitStatus;
    QUIC_LISTENER_CALLBACK_HANDLER Handler { nullptr };
    void* Context{ nullptr };

    MsQuicListener(const MsQuicRegistration& Registration) noexcept {
        if (!Registration.IsValid()) {
            InitStatus = Registration.GetInitStatus();
            return;
        }
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->ListenerOpen(
                    Registration,
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
        _In_ const MsQuicAlpn& Alpns,
        _In_ QUIC_ADDR* Address,
        _In_ QUIC_LISTENER_CALLBACK_HANDLER _Handler,
        _In_ void* _Context) noexcept {
        Handler = _Handler;
        Context = _Context;
        return MsQuic->ListenerStart(Handle, Alpns, Alpns.Length(), Address);
    }

    QUIC_STATUS
    ListenerCallback(HQUIC Listener, QUIC_LISTENER_EVENT* Event) noexcept {
        return Handler(Listener, Context, Event);
    }

    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicListener(MsQuicListener& other) = delete;
    MsQuicListener operator=(MsQuicListener& Other) = delete;
    operator HQUIC () const noexcept { return Handle; }
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

struct QuicBufferScope {
    QUIC_BUFFER* Buffer;
    QuicBufferScope() noexcept : Buffer(nullptr) { }
    QuicBufferScope(uint32_t Size) noexcept : Buffer((QUIC_BUFFER*) new uint8_t[sizeof(QUIC_BUFFER) + Size]) {
        memset(Buffer, 0, sizeof(*Buffer) + Size);
        Buffer->Length = Size;
        Buffer->Buffer = (uint8_t*)(Buffer + 1);
    }
    operator QUIC_BUFFER* () noexcept { return Buffer; }
    ~QuicBufferScope() noexcept { if (Buffer) { delete[](uint8_t*) Buffer; } }
};

#ifdef QUIC_PLATFORM_TYPE

//
// Abstractions for platform specific types/interfaces
//

struct EventScope {
    QUIC_EVENT Handle;
    EventScope() noexcept { QuicEventInitialize(&Handle, FALSE, FALSE); }
    EventScope(bool ManualReset) noexcept { QuicEventInitialize(&Handle, ManualReset, FALSE); }
    EventScope(QUIC_EVENT event) noexcept : Handle(event) { }
    ~EventScope() noexcept { QuicEventUninitialize(Handle); }
    operator QUIC_EVENT() const noexcept { return Handle; }
};

#endif
