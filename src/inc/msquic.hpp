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

#include "msquic.h"
#include "msquicp.h"
#ifdef _KERNEL_MODE
#include <new.h>
#else
#include <new>
#endif

#ifndef CXPLAT_DBG_ASSERT
#define CXPLAT_DBG_ASSERT(X) // no-op if not already defined
#endif

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

struct CxPlatLock {
    CXPLAT_LOCK Handle;
    CxPlatLock() noexcept { CxPlatLockInitialize(&Handle); }
    ~CxPlatLock() noexcept { CxPlatLockUninitialize(&Handle); }
    void Acquire() noexcept { CxPlatLockAcquire(&Handle); }
    void Release() noexcept { CxPlatLockRelease(&Handle); }
};

struct CxPlatPool {
    CXPLAT_POOL Handle;
    CxPlatPool(uint32_t Size, uint32_t Tag = 0, bool IsPaged = false) noexcept { CxPlatPoolInitialize(IsPaged, Size, Tag, &Handle); }
    ~CxPlatPool() noexcept { CxPlatPoolUninitialize(&Handle); }
    void* Alloc() noexcept { return CxPlatPoolAlloc(&Handle); }
    void Free(void* Ptr) noexcept { CxPlatPoolFree(&Handle, Ptr); }
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

#ifdef CXPLAT_FRE_ASSERT

class CxPlatWatchdog {
    CXPLAT_THREAD WatchdogThread;
    CxPlatEvent ShutdownEvent {true};
    uint32_t TimeoutMs;
    static CXPLAT_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (CxPlatWatchdog*)Context;
        if (!This->ShutdownEvent.WaitTimeout(This->TimeoutMs)) {
            CXPLAT_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        CXPLAT_THREAD_RETURN(0);
    }
public:
    CxPlatWatchdog(uint32_t WatchdogTimeoutMs) : TimeoutMs(WatchdogTimeoutMs) {
        CXPLAT_THREAD_CONFIG Config;
        memset(&Config, 0, sizeof(CXPLAT_THREAD_CONFIG));
        Config.Name = "cxplat_watchdog";
        Config.Callback = WatchdogThreadCallback;
        Config.Context = this;
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(CxPlatThreadCreate(&Config, &WatchdogThread)));
    }
    ~CxPlatWatchdog() {
        ShutdownEvent.Set();
        CxPlatThreadWait(&WatchdogThread);
        CxPlatThreadDelete(&WatchdogThread);
    }
};

#endif // CXPLAT_FRE_ASSERT

#endif // CX_PLATFORM_TYPE

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
        if (QUIC_SUCCEEDED(InitStatus = MsQuicOpen2(&ApiTable))) {
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

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
class MsQuicVersionSettings : public QUIC_VERSION_SETTINGS {
public:
    MsQuicVersionSettings() noexcept {}
    MsQuicVersionSettings& SetAllVersionLists(const uint32_t* Versions, uint32_t Length) {
        AcceptableVersions = OfferedVersions = FullyDeployedVersions = (uint32_t*)Versions;
        AcceptableVersionsLength = OfferedVersionsLength = FullyDeployedVersionsLength = Length;
        return *this;
    }
};

static_assert(sizeof(QUIC_VERSION_SETTINGS) == sizeof(MsQuicVersionSettings), "Cpp wrappers must not change size");
#endif

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
    MsQuicSettings& SetMaximumMtu(uint16_t Mtu) { MaximumMtu = Mtu; IsSet.MaximumMtu = TRUE; return *this; }
    MsQuicSettings& SetMinimumMtu(uint16_t Mtu) { MinimumMtu = Mtu; IsSet.MinimumMtu = TRUE; return *this; }
    MsQuicSettings& SetMtuDiscoverySearchCompleteTimeoutUs(uint64_t Time) { MtuDiscoverySearchCompleteTimeoutUs = Time; IsSet.MtuDiscoverySearchCompleteTimeoutUs = TRUE; return *this; }
    MsQuicSettings& SetMtuDiscoveryMissingProbeCount(uint8_t Count) { MtuDiscoveryMissingProbeCount = Count; IsSet.MtuDiscoveryMissingProbeCount = TRUE; return *this; }
    MsQuicSettings& SetKeepAlive(uint32_t Time) { KeepAliveIntervalMs = Time; IsSet.KeepAliveIntervalMs = TRUE; return *this; }
    MsQuicSettings& SetConnFlowControlWindow(uint32_t Window) { ConnFlowControlWindow = Window; IsSet.ConnFlowControlWindow = TRUE; return *this; }

    QUIC_STATUS
    SetGlobal() const noexcept {
        const QUIC_SETTINGS* Settings = this;
        return
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_SETTINGS,
                sizeof(*Settings),
                Settings);
    }

    QUIC_STATUS
    GetGlobal() noexcept {
        QUIC_SETTINGS* Settings = this;
        uint32_t Size = sizeof(*Settings);
        return
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_SETTINGS,
                &Size,
                Settings);
    }
};

static_assert(sizeof(QUIC_SETTINGS) == sizeof(MsQuicSettings), "Cpp wrappers must not change size");

class MsQuicCertificateHash : public QUIC_CERTIFICATE_HASH {
public:
    MsQuicCertificateHash(_In_reads_(20) const uint8_t* Thumbprint) {
        QUIC_CERTIFICATE_HASH* thisStruct = this;
        memcpy(thisStruct->ShaHash, Thumbprint, sizeof(thisStruct->ShaHash));
    }
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
    MsQuicCredentialConfig(QUIC_CREDENTIAL_FLAGS _Flags, const QUIC_CERTIFICATE_HASH* _CertificateHash) {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memset(thisStruct, 0, sizeof(QUIC_CREDENTIAL_CONFIG));
        Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Flags = _Flags;
        CertificateHash = (QUIC_CERTIFICATE_HASH*)_CertificateHash;
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
                QUIC_PARAM_CONFIGURATION_TICKET_KEYS,
                KeyCount * sizeof(QUIC_TICKET_KEY_CONFIG),
                KeyConfig);
    }
    QUIC_STATUS
    SetSettings(_In_ const MsQuicSettings& Settings) noexcept {
        const QUIC_SETTINGS* QSettings = &Settings;
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONFIGURATION_SETTINGS,
                sizeof(*QSettings),
                QSettings);
    }

    QUIC_STATUS
    GetSettings(_Out_ MsQuicSettings& Settings) noexcept {
        QUIC_SETTINGS* QSettings = &Settings;
        uint32_t Size = sizeof(*QSettings);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_CONFIGURATION_SETTINGS,
                &Size,
                QSettings);
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    QUIC_STATUS
    SetVersionSettings(
        _In_ const MsQuicVersionSettings& Settings) noexcept {
        const QUIC_VERSION_SETTINGS* QSettings = &Settings;
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                sizeof(*QSettings),
                QSettings);
    }

    QUIC_STATUS
    SetVersionNegotiationExtEnabled(_In_ const BOOLEAN Value) noexcept {
        return MsQuic->SetParam(
            Handle,
            QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED,
            sizeof(Value),
            &Value);
    }
#endif
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
        _In_ uint32_t Param,
        _In_ uint32_t BufferLength,
        _In_reads_bytes_(BufferLength)
            const void* Buffer
        ) noexcept {
        return MsQuic->SetParam(Handle, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetParam(
        _In_ uint32_t Param,
        _Inout_ _Pre_defensive_ uint32_t* BufferLength,
        _Out_writes_bytes_opt_(*BufferLength)
            void* Buffer
        ) noexcept {
        return MsQuic->GetParam(Handle, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetLocalAddr(_Out_ QuicAddr& Addr) {
        uint32_t Size = sizeof(Addr.SockAddr);
        return
            GetParam(
                QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                &Size,
                &Addr.SockAddr);
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    QUIC_STATUS
    SetCibirId(
        _In_reads_(Length) const uint8_t* Value,
        _In_ uint8_t Length) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LISTENER_CIBIR_ID,
                Length,
                Value);
    }
#endif

    QUIC_STATUS
    GetStatistics(_Out_ QUIC_LISTENER_STATISTICS& Statistics) const noexcept {
        uint32_t Size = sizeof(Statistics);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_LISTENER_STATS,
                &Size,
                &Statistics);
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
    // TODO - All the rest of this is not always necessary. Move to a separate class.
    QUIC_STATUS TransportShutdownStatus {0};
    QUIC_UINT62 AppShutdownErrorCode {0};
    bool HandshakeComplete {false};
    bool HandshakeResumed {false};
    uint32_t ResumptionTicketLength {0};
    uint8_t* ResumptionTicket {nullptr};
#ifdef CX_PLATFORM_TYPE
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ResumptionTicketReceivedEvent;
#endif // CX_PLATFORM_TYPE

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
        delete[] ResumptionTicket;
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
        _In_ uint32_t Param,
        _In_ uint32_t BufferLength,
        _In_reads_bytes_(BufferLength)
            const void* Buffer
        ) noexcept {
        return MsQuic->SetParam(Handle, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetParam(
        _In_ uint32_t Param,
        _Inout_ _Pre_defensive_ uint32_t* BufferLength,
        _Out_writes_bytes_opt_(*BufferLength)
            void* Buffer
        ) noexcept {
        return MsQuic->GetParam(Handle, Param, BufferLength, Buffer);
    }

    QUIC_STATUS
    GetLocalAddr(_Out_ QuicAddr& Addr) {
        uint32_t Size = sizeof(Addr.SockAddr);
        return
            GetParam(
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                &Size,
                &Addr.SockAddr);
    }

    QUIC_STATUS
    GetRemoteAddr(_Out_ QuicAddr& Addr) {
        uint32_t Size = sizeof(Addr.SockAddr);
        return
            GetParam(
                QUIC_PARAM_CONN_REMOTE_ADDRESS,
                &Size,
                &Addr.SockAddr);
    }

    QUIC_STATUS
    SetLocalAddr(_In_ const QuicAddr& Addr) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                sizeof(Addr.SockAddr),
                &Addr.SockAddr);
    }

    QUIC_STATUS
    SetRemoteAddr(_In_ const QuicAddr& Addr) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_REMOTE_ADDRESS,
                sizeof(Addr.SockAddr),
                &Addr.SockAddr);
    }

    QUIC_STATUS
    SetLocalInterface(_In_ uint32_t Index) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_LOCAL_INTERFACE,
                sizeof(Index),
                &Index);
    }

    QUIC_STATUS
    SetShareUdpBinding(_In_ bool ShareBinding = true) noexcept {
        BOOLEAN Value = ShareBinding ? TRUE : FALSE;
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                sizeof(Value),
                &Value);
    }

    QUIC_STATUS
    SetResumptionTicket(_In_reads_(TicketLength) const uint8_t* Ticket, uint32_t TicketLength) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_RESUMPTION_TICKET,
                TicketLength,
                Ticket);
    }

    QUIC_STATUS
    SetSettings(_In_ const MsQuicSettings& Settings) noexcept {
        const QUIC_SETTINGS* QSettings = &Settings;
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_SETTINGS,
                sizeof(*QSettings),
                QSettings);
    }

    QUIC_STATUS
    GetSettings(_Out_ MsQuicSettings* Settings) const noexcept {
        QUIC_SETTINGS* QSettings = Settings;
        uint32_t Size = sizeof(*QSettings);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_CONN_SETTINGS,
                &Size,
                QSettings);
    }

    QUIC_STATUS
    GetStatistics(_Out_ QUIC_STATISTICS_V2* Statistics) const noexcept {
        uint32_t Size = sizeof(*Statistics);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_CONN_STATISTICS_V2,
                &Size,
                Statistics);
    }

    QUIC_STATUS
    SetKeepAlivePadding(_In_ uint16_t Value) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_KEEP_ALIVE_PADDING,
                sizeof(Value),
                &Value);
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    QUIC_STATUS
    SetCibirId(
        _In_reads_(Length) const uint8_t* Value,
        _In_ uint8_t Length) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_CONN_CIBIR_ID,
                Length,
                Value);
    }
#endif

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
            // error code. If you expect to get streams, you should not no-op
            // the callbacks.
            //
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        }
        return QUIC_STATUS_SUCCESS;
    }

    static
    QUIC_STATUS
    QUIC_API
    SendResumptionCallback(
        _In_ MsQuicConnection* Connection,
        _In_opt_ void* /* Context */,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept {
        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            MsQuic->ConnectionSendResumptionTicket(*Connection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            //
            // Not great beacuse it doesn't provide an application specific
            // error code. If you expect to get streams, you should not no-op
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
        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            pThis->HandshakeComplete = true;
            pThis->HandshakeResumed = Event->CONNECTED.SessionResumed;
#ifdef CX_PLATFORM_TYPE
            pThis->HandshakeCompleteEvent.Set();
#endif // CX_PLATFORM_TYPE
        } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT) {
            pThis->TransportShutdownStatus = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
#ifdef CX_PLATFORM_TYPE
            if (!pThis->HandshakeComplete) {
                pThis->HandshakeCompleteEvent.Set();
            }
#endif // CX_PLATFORM_TYPE
        } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER) {
            pThis->AppShutdownErrorCode = Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
#ifdef CX_PLATFORM_TYPE
            if (!pThis->HandshakeComplete) {
                pThis->HandshakeCompleteEvent.Set();
            }
#endif // CX_PLATFORM_TYPE
        } else if (Event->Type == QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED && !pThis->ResumptionTicket) {
            pThis->ResumptionTicketLength = Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
            pThis->ResumptionTicket = new(std::nothrow) uint8_t[pThis->ResumptionTicketLength];
            if (pThis->ResumptionTicket) {
                CXPLAT_DBG_ASSERT(pThis->ResumptionTicketLength != 0);
                memcpy(pThis->ResumptionTicket, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, pThis->ResumptionTicketLength);
#ifdef CX_PLATFORM_TYPE
                pThis->ResumptionTicketReceivedEvent.Set();
#endif // CX_PLATFORM_TYPE
            }
        }
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
#ifdef CX_PLATFORM_TYPE
    uint32_t AcceptedConnectionCount {0};
#endif

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
            auto Connection = new(std::nothrow) MsQuicConnection(Event->NEW_CONNECTION.Connection, CleanUpAutoDelete, pThis->ConnectionHandler, pThis->ConnectionContext);
            if (Connection) {
                Status = Connection->SetConfiguration(pThis->Configuration);
                if (QUIC_FAILED(Status)) {
                    //
                    // The connection is being rejected. Let MsQuic free the handle.
                    //
                    Connection->Handle = nullptr;
                    delete Connection;
                } else {
#ifdef CX_PLATFORM_TYPE
                    InterlockedIncrement((long*)&pThis->AcceptedConnectionCount);
#endif
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
        _In_ QUIC_STREAM_START_FLAGS Flags = QUIC_STREAM_START_FLAG_NONE
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

    _IRQL_requires_max_(DISPATCH_LEVEL)
    void
    ReceiveComplete(
        _In_ uint64_t BufferLength
        ) noexcept {
        MsQuic->StreamReceiveComplete(Handle, BufferLength);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    QUIC_STATUS
    ReceiveSetEnabled(
        _In_ bool IsEnabled = true
        ) noexcept {
        return MsQuic->StreamReceiveSetEnabled(Handle, IsEnabled ? TRUE : FALSE);
    }

    QUIC_STATUS
    GetID(_Out_ QUIC_UINT62* ID) const noexcept {
        uint32_t Size = sizeof(*ID);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_STREAM_ID,
                &Size,
                ID);
    }

    QUIC_UINT62 ID() const noexcept {
        QUIC_UINT62 ID;
        GetID(&ID);
        return ID;
    }

    QUIC_STATUS
    SetPriority(_In_ uint16_t Priority) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_STREAM_PRIORITY,
                sizeof(Priority),
                &Priority);
    }

    QUIC_STATUS
    GetPriority(_Out_ uint16_t* Priority) const noexcept {
        uint32_t Size = sizeof(*Priority);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_STREAM_PRIORITY,
                &Size,
                Priority);
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
    QuicBufferScope(uint32_t Size) noexcept : Buffer((QUIC_BUFFER*) new(std::nothrow) uint8_t[sizeof(QUIC_BUFFER) + Size]) {
        CXPLAT_DBG_ASSERT(Buffer);
        memset(Buffer, 0, sizeof(*Buffer) + Size);
        Buffer->Length = Size;
        Buffer->Buffer = (uint8_t*)(Buffer + 1);
    }
    operator QUIC_BUFFER* () noexcept { return Buffer; }
    ~QuicBufferScope() noexcept { if (Buffer) { delete[](uint8_t*) Buffer; } }
};
