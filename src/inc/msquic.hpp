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

#ifndef CXPLAT_DBG_ASSERT
#define CXPLAT_DBG_ASSERT(X) // no-op if not already defined
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
        CXPLAT_DBG_ASSERT(QuicAddrGetPort(&SockAddr) != 0xFFFF);
        QuicAddrSetPort(&SockAddr, (uint16_t)1 + QuicAddrGetPort(&SockAddr));
    }
    void IncrementAddr() {
        QuicAddrIncrement(&SockAddr);
    }
    QUIC_ADDRESS_FAMILY GetFamily() const { return QuicAddrGetFamily(&SockAddr); }
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
    MsQuicSettings& SetServerResumptionLevel(QUIC_SERVER_RESUMPTION_LEVEL Value) { ServerResumptionLevel = (uint8_t)Value; IsSet.ServerResumptionLevel = TRUE; return *this; }
    MsQuicSettings& SetInitialRttMs(uint32_t Value) { InitialRttMs = Value; IsSet.InitialRttMs = TRUE; return *this; }
    MsQuicSettings& SetIdleTimeoutMs(uint64_t Value) { IdleTimeoutMs = Value; IsSet.IdleTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetHandshakeIdleTimeoutMs(uint64_t Value) { HandshakeIdleTimeoutMs = Value; IsSet.HandshakeIdleTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetDisconnectTimeoutMs(uint32_t Value) { DisconnectTimeoutMs = Value; IsSet.DisconnectTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetPeerBidiStreamCount(uint16_t Value) { PeerBidiStreamCount = Value; IsSet.PeerBidiStreamCount = TRUE; return *this; }
    MsQuicSettings& SetPeerUnidiStreamCount(uint16_t Value) { PeerUnidiStreamCount = Value; IsSet.PeerUnidiStreamCount = TRUE; return *this; }
    MsQuicSettings& SetMaxBytesPerKey(uint64_t Value) { MaxBytesPerKey = Value; IsSet.MaxBytesPerKey = TRUE; return *this; }
    MsQuicSettings& SetMaxAckDelayMs(uint32_t Value) { MaxAckDelayMs = Value; IsSet.MaxAckDelayMs = TRUE; return *this; }
    MsQuicSettings& SetDesiredVersionsList(const uint32_t* DesiredVersions, uint32_t Length) {
        DesiredVersionsList = DesiredVersions; DesiredVersionsListLength = Length; IsSet.DesiredVersionsList = TRUE; return *this; }
    MsQuicSettings& SetVersionNegotiationExtEnabled(bool Value) { VersionNegotiationExtEnabled = Value; IsSet.VersionNegotiationExtEnabled = TRUE; return *this; }
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
    QUIC_STATUS
    SetTicketKey(_In_ const QUIC_TICKET_KEY_CONFIG* KeyConfig) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_CONFIGURATION,
                QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                sizeof(QUIC_TICKET_KEY_CONFIG),
                KeyConfig);
    }
    QUIC_STATUS
    SetTicketKeys(
        _In_reads_(KeyCount) const QUIC_TICKET_KEY_CONFIG* KeyConfig,
        uint8_t KeyCount) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_CONFIGURATION,
                QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                KeyCount * sizeof(QUIC_TICKET_KEY_CONFIG),
                KeyConfig);
    }
};

struct MsQuicListener {
    HQUIC Handle { nullptr };
    QUIC_STATUS InitStatus;

    MsQuicListener(
        _In_ const MsQuicRegistration& Registration,
        _In_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
        _In_ void* Context = nullptr
        ) noexcept {
        if (!Registration.IsValid()) {
            InitStatus = Registration.GetInitStatus();
            return;
        }
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->ListenerOpen(
                    Registration,
                    Handler,
                    Context,
                    &Handle))) {
            Handle = nullptr;
        }
    }

    ~MsQuicListener() noexcept {
        if (Handle) {
            MsQuic->ListenerClose(Handle);
        }
    }

    QUIC_STATUS
    Start(
        _In_ const MsQuicAlpn& Alpns,
        _In_ QUIC_ADDR* Address = nullptr
        ) noexcept {
        return MsQuic->ListenerStart(Handle, Alpns, Alpns.Length(), Address);
    }

    QUIC_STATUS
    SetParam(
        _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
        _In_ uint32_t Param,
        _In_ uint32_t BufferLength,
        _In_reads_bytes_(BufferLength)
            const void* Buffer
        ) noexcept {
        return MsQuic->SetParam(Handle, Level, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetParam(
        _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
        _In_ uint32_t Param,
        _Inout_ _Pre_defensive_ uint32_t* BufferLength,
        _Out_writes_bytes_opt_(*BufferLength)
            void* Buffer
        ) noexcept {
        return MsQuic->GetParam(Handle, Level, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetLocalAddr(_Out_ QuicAddr& Addr) {
        uint32_t Size = sizeof(Addr.SockAddr);
        return
            GetParam(
                QUIC_PARAM_LEVEL_LISTENER,
                QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                &Size,
                &Addr.SockAddr);
    }

    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicListener(MsQuicListener& other) = delete;
    MsQuicListener operator=(MsQuicListener& Other) = delete;
    operator HQUIC () const noexcept { return Handle; }
};

enum MsQuicCleanUpMode {
    CleanUpManual,
    CleanUpAutoDelete,
};

typedef QUIC_STATUS MsQuicConnectionCallback(
    _In_ struct MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    );

struct MsQuicConnection {
    HQUIC Handle { nullptr };
    MsQuicCleanUpMode CleanUpMode;
    MsQuicConnectionCallback* Callback;
    void* Context;
    QUIC_STATUS InitStatus;

    MsQuicConnection(
        _In_ const MsQuicRegistration& Registration,
        _In_ MsQuicCleanUpMode CleanUpMode = CleanUpManual,
        _In_ MsQuicConnectionCallback* Callback = NoOpCallback,
        _In_ void* Context = nullptr
        ) noexcept : CleanUpMode(CleanUpMode), Callback(Callback), Context(Context) {
        if (!Registration.IsValid()) {
            InitStatus = Registration.GetInitStatus();
            return;
        }
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->ConnectionOpen(
                    Registration,
                    (QUIC_CONNECTION_CALLBACK_HANDLER)MsQuicCallback,
                    this,
                    &Handle))) {
            Handle = nullptr;
        }
    }

    MsQuicConnection(
        _In_ HQUIC ConnectionHandle,
        _In_ MsQuicCleanUpMode CleanUpMode,
        _In_ MsQuicConnectionCallback* Callback,
        _In_ void* Context = nullptr
        ) noexcept : CleanUpMode(CleanUpMode), Callback(Callback), Context(Context) {
        Handle = ConnectionHandle;
        MsQuic->SetCallbackHandler(Handle, (void*)MsQuicCallback, this);
        InitStatus = QUIC_STATUS_SUCCESS;
    }

    ~MsQuicConnection() noexcept {
        if (Handle) {
            MsQuic->ConnectionClose(Handle);
        }
    }

    void
    Shutdown(
        _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode, // Application defined error code
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags = QUIC_CONNECTION_SHUTDOWN_FLAG_NONE
        ) noexcept {
        MsQuic->ConnectionShutdown(Handle, Flags, ErrorCode);
    }

    QUIC_STATUS
    Start(
        _In_ const MsQuicConfiguration& Config,
        _In_reads_or_z_opt_(QUIC_MAX_SNI_LENGTH)
            const char* ServerName,
        _In_ uint16_t ServerPort // Host byte order
        ) noexcept {
        return MsQuic->ConnectionStart(Handle, Config, QUIC_ADDRESS_FAMILY_UNSPEC, ServerName, ServerPort);
    }

    QUIC_STATUS
    Start(
        _In_ const MsQuicConfiguration& Config,
        _In_ QUIC_ADDRESS_FAMILY Family,
        _In_reads_or_z_opt_(QUIC_MAX_SNI_LENGTH)
            const char* ServerName,
        _In_ uint16_t ServerPort // Host byte order
        ) noexcept {
        return MsQuic->ConnectionStart(Handle, Config, Family, ServerName, ServerPort);
    }

    QUIC_STATUS
    StartLocalhost(
        _In_ const MsQuicConfiguration& Config,
        _In_ const QuicAddr& LocalhostAddr
        ) noexcept {
        return MsQuic->ConnectionStart(Handle, Config, LocalhostAddr.GetFamily(), QUIC_LOCALHOST_FOR_AF(LocalhostAddr.GetFamily()), LocalhostAddr.GetPort());
    }

    QUIC_STATUS
    SetConfiguration(
        _In_ const MsQuicConfiguration& Config
        ) noexcept {
        return MsQuic->ConnectionSetConfiguration(Handle, Config);
    }

    QUIC_STATUS
    SendResumptionTicket(
        _In_ QUIC_SEND_RESUMPTION_FLAGS Flags = QUIC_SEND_RESUMPTION_FLAG_NONE,
        _In_ uint16_t DataLength = 0,
        _In_reads_bytes_opt_(DataLength)
            const uint8_t* ResumptionData = nullptr
        ) noexcept {
        return MsQuic->ConnectionSendResumptionTicket(Handle, Flags, DataLength, ResumptionData);
    }

    QUIC_STATUS
    SetParam(
        _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
        _In_ uint32_t Param,
        _In_ uint32_t BufferLength,
        _In_reads_bytes_(BufferLength)
            const void* Buffer
        ) noexcept {
        return MsQuic->SetParam(Handle, Level, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetParam(
        _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
        _In_ uint32_t Param,
        _Inout_ _Pre_defensive_ uint32_t* BufferLength,
        _Out_writes_bytes_opt_(*BufferLength)
            void* Buffer
        ) noexcept {
        return MsQuic->GetParam(Handle, Level, Param, BufferLength, Buffer);
    }

    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicConnection(MsQuicConnection& other) = delete;
    MsQuicConnection operator=(MsQuicConnection& Other) = delete;
    operator HQUIC () const noexcept { return Handle; }

    static
    QUIC_STATUS
    QUIC_API
    NoOpCallback(
        _In_ MsQuicConnection* /* Connection */,
        _In_opt_ void* /* Context */,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept {
        if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            //
            // Not great beacuse it doesn't provide an application specific
            // error code. If you expect to get streams, you should not be no-op
            // the callbacks.
            //
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        }
        return QUIC_STATUS_SUCCESS;
    }

private:

    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    static
    QUIC_STATUS
    QUIC_API
    MsQuicCallback(
        _In_ HQUIC /* Connection */,
        _In_opt_ MsQuicConnection* pThis,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept {
        CXPLAT_DBG_ASSERT(pThis);
        auto DeleteOnExit =
            Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE &&
            pThis->CleanUpMode == CleanUpAutoDelete;
        auto Status = pThis->Callback(pThis, pThis->Context, Event);
        if (DeleteOnExit) {
            delete pThis;
        }
        return Status;
    }
};

struct MsQuicAutoAcceptListener : public MsQuicListener {
    const MsQuicConfiguration& Configuration;
    MsQuicConnectionCallback* ConnectionHandler;
    void* ConnectionContext;

    MsQuicAutoAcceptListener(
        _In_ const MsQuicRegistration& Registration,
        _In_ const MsQuicConfiguration& Config,
        _In_ MsQuicConnectionCallback* _ConnectionHandler,
        _In_ void* _ConnectionContext = nullptr
        ) noexcept :
        MsQuicListener(Registration, ListenerCallback, this),
        Configuration(Config),
        ConnectionHandler(_ConnectionHandler),
        ConnectionContext(_ConnectionContext)
    { }

private:

    static
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ListenerCallback(
        _In_ HQUIC /* Listener */,
        _In_opt_ void* Context,
        _Inout_ QUIC_LISTENER_EVENT* Event
        ) noexcept {
        auto pThis = (MsQuicAutoAcceptListener*)Context; CXPLAT_DBG_ASSERT(pThis);
        QUIC_STATUS Status = QUIC_STATUS_INVALID_STATE;
        if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
            auto Connection = new MsQuicConnection(Event->NEW_CONNECTION.Connection, CleanUpAutoDelete, pThis->ConnectionHandler, pThis->ConnectionContext);
            if (Connection) {
                Status = Connection->SetConfiguration(pThis->Configuration);
                if (QUIC_FAILED(Status)) {
                    delete Connection;
                }
            }
        }
        return Status;
    }
};

typedef QUIC_STATUS MsQuicStreamCallback(
    _In_ struct MsQuicStream* Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    );

struct MsQuicStream {
    HQUIC Handle { nullptr };
    MsQuicCleanUpMode CleanUpMode;
    MsQuicStreamCallback* Callback;
    void* Context;
    QUIC_STATUS InitStatus;

    MsQuicStream(
        _In_ const MsQuicConnection& Connection,
        _In_ QUIC_STREAM_OPEN_FLAGS Flags,
        _In_ MsQuicCleanUpMode CleanUpMode = CleanUpManual,
        _In_ MsQuicStreamCallback* Callback = NoOpCallback,
        _In_ void* Context = nullptr
        ) noexcept : CleanUpMode(CleanUpMode), Callback(Callback), Context(Context) {
        if (!Connection.IsValid()) {
            InitStatus = Connection.GetInitStatus();
            return;
        }
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->StreamOpen(
                    Connection,
                    Flags,
                    (QUIC_STREAM_CALLBACK_HANDLER)MsQuicCallback,
                    this,
                    &Handle))) {
            Handle = nullptr;
        }
    }

    MsQuicStream(
        _In_ HQUIC StreamHandle,
        _In_ MsQuicCleanUpMode CleanUpMode,
        _In_ MsQuicStreamCallback* Callback,
        _In_ void* Context = nullptr
        ) noexcept : CleanUpMode(CleanUpMode), Callback(Callback), Context(Context) {
        Handle = StreamHandle;
        MsQuic->SetCallbackHandler(Handle, (void*)MsQuicCallback, this);
        InitStatus = QUIC_STATUS_SUCCESS;
    }

    ~MsQuicStream() noexcept {
        if (Handle) {
            MsQuic->StreamClose(Handle);
        }
    }

    QUIC_STATUS
    Start(
        _In_ QUIC_STREAM_START_FLAGS Flags = QUIC_STREAM_START_FLAG_ASYNC
        ) noexcept {
        return MsQuic->StreamStart(Handle, Flags);
    }

    QUIC_STATUS
    Shutdown(
        _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode, // Application defined error code
        _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags = QUIC_STREAM_SHUTDOWN_FLAG_ABORT
        ) noexcept {
        return MsQuic->StreamShutdown(Handle, Flags, ErrorCode);
    }

    void
    ConnectionShutdown(
        _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode, // Application defined error code
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags = QUIC_CONNECTION_SHUTDOWN_FLAG_NONE
        ) noexcept {
        MsQuic->ConnectionShutdown(Handle, Flags, ErrorCode);
    }

    QUIC_STATUS
    Send(
        _In_reads_(BufferCount) _Pre_defensive_
            const QUIC_BUFFER* const Buffers,
        _In_ uint32_t BufferCount = 1,
        _In_ QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE,
        _In_opt_ void* ClientSendContext = nullptr
        ) noexcept {
        return MsQuic->StreamSend(Handle, Buffers, BufferCount, Flags, ClientSendContext);
    }

    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicStream(MsQuicStream& other) = delete;
    MsQuicStream operator=(MsQuicStream& Other) = delete;
    operator HQUIC () const noexcept { return Handle; }

    static
    QUIC_STATUS
    QUIC_API
    NoOpCallback(
        _In_ MsQuicStream* /* Stream */,
        _In_opt_ void* /* Context */,
        _Inout_ QUIC_STREAM_EVENT* /* Event */
        ) noexcept {
        return QUIC_STATUS_SUCCESS;
    }

private:

    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
    static
    QUIC_STATUS
    QUIC_API
    MsQuicCallback(
        _In_ HQUIC /* Stream */,
        _In_opt_ MsQuicStream* pThis,
        _Inout_ QUIC_STREAM_EVENT* Event
        ) noexcept {
        CXPLAT_DBG_ASSERT(pThis);
        auto DeleteOnExit =
            Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE &&
            pThis->CleanUpMode == CleanUpAutoDelete;
        auto Status = pThis->Callback(pThis, pThis->Context, Event);
        if (DeleteOnExit) {
            delete pThis;
        }
        return Status;
    }
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

struct ConfigurationScope {
    HQUIC Handle;
    ConfigurationScope() noexcept : Handle(nullptr) { }
    ConfigurationScope(HQUIC handle) noexcept : Handle(handle) { }
    ~ConfigurationScope() noexcept { if (Handle) { MsQuic->ConfigurationClose(Handle); } }
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

#ifdef CX_PLATFORM_TYPE

//
// Abstractions for platform specific types/interfaces
//

struct CxPlatEvent {
    CXPLAT_EVENT Handle;
    CxPlatEvent() noexcept { CxPlatEventInitialize(&Handle, FALSE, FALSE); }
    CxPlatEvent(bool ManualReset) noexcept { CxPlatEventInitialize(&Handle, ManualReset, FALSE); }
    CxPlatEvent(CXPLAT_EVENT event) noexcept : Handle(event) { }
    ~CxPlatEvent() noexcept { CxPlatEventUninitialize(Handle); }
    CXPLAT_EVENT* operator &() noexcept { return &Handle; }
    operator CXPLAT_EVENT() const noexcept { return Handle; }
    void Set() { CxPlatEventSet(Handle); }
    void Reset() { CxPlatEventReset(Handle); }
    void WaitForever() { CxPlatEventWaitForever(Handle); }
    bool WaitTimeout(uint32_t TimeoutMs) { return CxPlatEventWaitWithTimeout(Handle, TimeoutMs); }
};

#ifdef CXPLAT_HASH_MIN_SIZE

struct HashTable {
    bool Initialized;
    CXPLAT_HASHTABLE Table;
    HashTable() noexcept { Initialized = CxPlatHashtableInitializeEx(&Table, CXPLAT_HASH_MIN_SIZE); }
    ~HashTable() noexcept { if (Initialized) { CxPlatHashtableUninitialize(&Table); } }
    void Insert(CXPLAT_HASHTABLE_ENTRY* Entry) { CxPlatHashtableInsert(&Table, Entry, Entry->Signature, nullptr); }
    void Remove(CXPLAT_HASHTABLE_ENTRY* Entry) { CxPlatHashtableRemove(&Table, Entry, nullptr); }
    CXPLAT_HASHTABLE_ENTRY* Lookup(uint64_t Signature) {
        CXPLAT_HASHTABLE_LOOKUP_CONTEXT LookupContext;
        return CxPlatHashtableLookup(&Table, Signature, &LookupContext);
    }
    CXPLAT_HASHTABLE_ENTRY* LookupEx(uint64_t Signature, bool (*Equals)(CXPLAT_HASHTABLE_ENTRY* Entry, void* Context), void* Context) {
        CXPLAT_HASHTABLE_LOOKUP_CONTEXT LookupContext;
        CXPLAT_HASHTABLE_ENTRY* Entry = CxPlatHashtableLookup(&Table, Signature, &LookupContext);
        while (Entry != NULL) {
            if (Equals(Entry, Context)) return Entry;
            Entry = CxPlatHashtableLookupNext(&Table, &LookupContext);
        }
        return NULL;
    }
};

#endif // CXPLAT_HASH_MIN_SIZE

#endif // CX_PLATFORM_TYPE
