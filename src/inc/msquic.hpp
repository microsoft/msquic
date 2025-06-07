/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    C++ Declarations for the MsQuic API, which enables applications and
    drivers to create QUIC connections as a client or server.

    For more detailed information, see ../docs/API.md

    NOTE! This header file not guaranteed to remain binary compatible between
    releases. It is included here for convenience only. For a stable interface
    use msquic.h.

Supported Platforms:

    Windows User mode
    Windows Kernel mode
    Linux User mode

--*/

#ifdef _WIN32
#pragma once
#endif

#ifndef _MSQUIC_HPP_
#define _MSQUIC_HPP_

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
    CxPlatEvent(const CxPlatEvent&) = delete;
    CxPlatEvent& operator=(const CxPlatEvent&) = delete;
    CxPlatEvent(CxPlatEvent&&) = delete;
    CxPlatEvent& operator=(CxPlatEvent&&) = delete;
    CXPLAT_EVENT* operator &() noexcept { return &Handle; }
    operator CXPLAT_EVENT() const noexcept { return Handle; }
    void Set() { CxPlatEventSet(Handle); }
    void Reset() { CxPlatEventReset(Handle); }
    void WaitForever() { CxPlatEventWaitForever(Handle); }
    bool WaitTimeout(uint32_t TimeoutMs) { return CxPlatEventWaitWithTimeout(Handle, TimeoutMs); }
};

struct CxPlatRundown {
    CXPLAT_RUNDOWN_REF Ref;
    CxPlatRundown() noexcept { CxPlatRundownInitialize(&Ref); }
    ~CxPlatRundown() noexcept { CxPlatRundownUninitialize(&Ref); }
    CxPlatRundown(const CxPlatRundown&) = delete;
    CxPlatRundown& operator=(const CxPlatRundown&) = delete;
    CxPlatRundown(CxPlatRundown&&) = delete;
    CxPlatRundown& operator=(CxPlatRundown&&) = delete;
    bool Acquire() noexcept { return CxPlatRundownAcquire(&Ref); }
    void Release() noexcept { CxPlatRundownRelease(&Ref); }
    void ReleaseAndWait() { CxPlatRundownReleaseAndWait(&Ref); }
};

struct CxPlatLock {
    CXPLAT_LOCK Handle;
    CxPlatLock() noexcept { CxPlatLockInitialize(&Handle); }
    ~CxPlatLock() noexcept { CxPlatLockUninitialize(&Handle); }
    CxPlatLock(const CxPlatLock&) = delete;
    CxPlatLock& operator=(const CxPlatLock&) = delete;
    CxPlatLock(CxPlatLock&&) = delete;
    CxPlatLock& operator=(CxPlatLock&&) = delete;
    void Acquire() noexcept { CxPlatLockAcquire(&Handle); }
    void Release() noexcept { CxPlatLockRelease(&Handle); }
};

#pragma warning(push)
#pragma warning(disable:28167) // TODO - Fix SAL annotations for IRQL changes
struct CxPlatLockDispatch {
    CXPLAT_DISPATCH_LOCK Handle;
    CxPlatLockDispatch() noexcept { CxPlatDispatchLockInitialize(&Handle); }
    ~CxPlatLockDispatch() noexcept { CxPlatDispatchLockUninitialize(&Handle); }
    CxPlatLockDispatch(const CxPlatLockDispatch&) = delete;
    CxPlatLockDispatch& operator=(const CxPlatLockDispatch&) = delete;
    CxPlatLockDispatch(CxPlatLockDispatch&&) = delete;
    CxPlatLockDispatch& operator=(CxPlatLockDispatch&&) = delete;
    void Acquire() noexcept { CxPlatDispatchLockAcquire(&Handle); }
    void Release() noexcept { CxPlatDispatchLockRelease(&Handle); }
};
#pragma warning(pop)

struct CxPlatPool {
    CXPLAT_POOL Handle;
    CxPlatPool(uint32_t Size, uint32_t Tag = 0, bool IsPaged = false) noexcept { CxPlatPoolInitialize(IsPaged, Size, Tag, &Handle); }
    ~CxPlatPool() noexcept { CxPlatPoolUninitialize(&Handle); }
    CxPlatPool(const CxPlatPool&) = delete;
    CxPlatPool& operator=(const CxPlatPool&) = delete;
    CxPlatPool(CxPlatPool&&) = delete;
    CxPlatPool& operator=(CxPlatPool&&) = delete;
    void* Alloc() noexcept { return CxPlatPoolAlloc(&Handle); }
    void Free(void* Ptr) noexcept { CxPlatPoolFree(Ptr); }
};

//
// Implementation of std::forward, to allow use in kernel mode.
// Based on reference implementation in MSVC's STL.
//

template <class _Ty>
struct CxPlatRemoveReference {
    using type                 = _Ty;
    using _Const_thru_ref_type = const _Ty;
};

template <class _Ty>
using CxPlatRemoveReferenceT = typename CxPlatRemoveReference<_Ty>::type;

template <class _Ty>
constexpr _Ty&& CxPlatForward(
    CxPlatRemoveReferenceT<_Ty>& _Arg) noexcept { // forward an lvalue as either an lvalue or an rvalue
    return static_cast<_Ty&&>(_Arg);
}

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wmultichar" // Multi-character constant used intentionally for the tag
#endif
template<typename T, uint32_t Tag = 'lPxC', bool Paged = false>
class CxPlatPoolT {
    CXPLAT_POOL Pool;
public:
    CxPlatPoolT() noexcept { CxPlatPoolInitialize(Paged, sizeof(T), Tag, &Pool); }
    ~CxPlatPoolT() noexcept { CxPlatPoolUninitialize(&Pool); }
    CxPlatPoolT(const CxPlatPoolT&) = delete;
    CxPlatPoolT& operator=(const CxPlatPoolT&) = delete;
    CxPlatPoolT(CxPlatPoolT&&) = delete;
    CxPlatPoolT& operator=(CxPlatPoolT&&) = delete;
    template <class... Args>
    T* Alloc(Args&&... args) noexcept {
        void* Raw = CxPlatPoolAlloc(&Pool);
        return Raw ? new (Raw) T (CxPlatForward<Args>(args)...) : nullptr;
    }
    void Free(T* Obj) noexcept {
        if (Obj != nullptr) {
            Obj->~T();
            CxPlatPoolFree(Obj);
        }
    }
};

#ifdef CXPLAT_HASH_MIN_SIZE

struct CxPlatHashTable {
    bool Initialized;
    CXPLAT_HASHTABLE Table;
    CxPlatHashTable() noexcept { Initialized = CxPlatHashtableInitializeEx(&Table, CXPLAT_HASH_MIN_SIZE); }
    ~CxPlatHashTable() noexcept { if (Initialized) { CxPlatHashtableUninitialize(&Table); } }
    CxPlatHashTable(const CxPlatHashTable&) = delete;
    CxPlatHashTable& operator=(const CxPlatHashTable&) = delete;
    CxPlatHashTable(CxPlatHashTable&&) = delete;
    CxPlatHashTable& operator=(CxPlatHashTable&&) = delete;
    void Insert(CXPLAT_HASHTABLE_ENTRY* Entry) noexcept { CxPlatHashtableInsert(&Table, Entry, Entry->Signature, nullptr); }
    void Remove(CXPLAT_HASHTABLE_ENTRY* Entry) noexcept { CxPlatHashtableRemove(&Table, Entry, nullptr); }
    CXPLAT_HASHTABLE_ENTRY* Lookup(uint64_t Signature) noexcept {
        CXPLAT_HASHTABLE_LOOKUP_CONTEXT LookupContext;
        return CxPlatHashtableLookup(&Table, Signature, &LookupContext);
    }
    CXPLAT_HASHTABLE_ENTRY* LookupEx(uint64_t Signature, bool (*Equals)(CXPLAT_HASHTABLE_ENTRY* Entry, void* Context), void* Context) noexcept {
        CXPLAT_HASHTABLE_LOOKUP_CONTEXT LookupContext;
        CXPLAT_HASHTABLE_ENTRY* Entry = CxPlatHashtableLookup(&Table, Signature, &LookupContext);
        while (Entry != NULL) {
            if (Equals(Entry, Context)) return Entry;
            Entry = CxPlatHashtableLookupNext(&Table, &LookupContext);
        }
        return NULL;
    }
    void EnumBegin(CXPLAT_HASHTABLE_ENUMERATOR* Enumerator) noexcept {
        CxPlatHashtableEnumerateBegin(&Table, Enumerator);
    }
    void EnumEnd(CXPLAT_HASHTABLE_ENUMERATOR* Enumerator) noexcept {
        CxPlatHashtableEnumerateEnd(&Table, Enumerator);
    }
    CXPLAT_HASHTABLE_ENTRY* EnumNext(CXPLAT_HASHTABLE_ENUMERATOR* Enumerator) noexcept {
        return CxPlatHashtableEnumerateNext(&Table, Enumerator);
    }
};

#endif // CXPLAT_HASH_MIN_SIZE

class CxPlatThread {
    CXPLAT_THREAD Thread {0};
    bool Initialized : 1;
    bool WaitOnDelete : 1;
public:
    CxPlatThread(bool WaitOnDelete = true) noexcept : Initialized(false), WaitOnDelete(WaitOnDelete) { }
    ~CxPlatThread() noexcept {
        if (Initialized) {
            if (WaitOnDelete) {
                CxPlatThreadWait(&Thread);
            }
            CxPlatThreadDelete(&Thread);
        }
    }
    CxPlatThread(const CxPlatThread&) = delete;
    CxPlatThread& operator=(const CxPlatThread&) = delete;
    CxPlatThread(CxPlatThread&&) = delete;
    CxPlatThread& operator=(CxPlatThread&&) = delete;
    QUIC_STATUS Create(CXPLAT_THREAD_CONFIG* Config) noexcept {
        auto Status = CxPlatThreadCreate(Config, &Thread);
        if (QUIC_SUCCEEDED(Status)) {
            Initialized = true;
        }
        return Status;
    }
    void Wait() noexcept {
        if (Initialized) {
            CxPlatThreadWait(&Thread);
        }
    }
};

#ifdef CXPLAT_FRE_ASSERT

#ifndef _KERNEL_MODE
#include <stdio.h> // For printf below
#endif

class CxPlatWatchdog {
    CxPlatEvent ShutdownEvent {true};
    CxPlatThread WatchdogThread;
    uint32_t TimeoutMs;
    bool WriteToConsole;
    static CXPLAT_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (CxPlatWatchdog*)Context;
        if (!This->ShutdownEvent.WaitTimeout(This->TimeoutMs)) {
#ifndef _KERNEL_MODE // Not supported in kernel mode
            if (This->WriteToConsole) {
                printf("Error: Watchdog timeout fired!\n");
            }
#endif
            CXPLAT_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        CXPLAT_THREAD_RETURN(0);
    }
public:
    CxPlatWatchdog(uint32_t WatchdogTimeoutMs, const char* Name = "cxplat_watchdog", bool WriteToConsole = false) noexcept
        : TimeoutMs(WatchdogTimeoutMs), WriteToConsole(WriteToConsole) {
        CXPLAT_THREAD_CONFIG Config;
        memset(&Config, 0, sizeof(CXPLAT_THREAD_CONFIG));
        Config.Name = Name;
        Config.Callback = WatchdogThreadCallback;
        Config.Context = this;
        if (WatchdogTimeoutMs != UINT32_MAX) {
            CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(WatchdogThread.Create(&Config)));
        }
    }
    ~CxPlatWatchdog() noexcept {
        ShutdownEvent.Set();
    }
    CxPlatWatchdog(const CxPlatWatchdog&) = delete;
    CxPlatWatchdog& operator=(const CxPlatWatchdog&) = delete;
    CxPlatWatchdog(CxPlatWatchdog&&) = delete;
    CxPlatWatchdog& operator=(CxPlatWatchdog&&) = delete;
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
    operator const QUIC_ADDR* () const noexcept { return &SockAddr; }
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
    UniquePtrArray(const UniquePtrArray& other) = delete;
    UniquePtrArray(UniquePtrArray&& other) noexcept {
        this->ptr = other.ptr;
        other.ptr = nullptr;
    }
    UniquePtrArray& operator=(const UniquePtrArray& other) = delete;
    UniquePtrArray& operator=(UniquePtrArray&& other) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
    }
    ~UniquePtrArray() { delete [] ptr; }
    T* get() { return ptr; }
    const T* get() const { return ptr; }
    T& operator*() const { return *ptr; }
    T* operator->() const { return ptr; }
    operator bool() const { return ptr != nullptr; }
    bool operator == (T* _ptr) const { return ptr == _ptr; }
    bool operator != (T* _ptr) const { return ptr != _ptr; }
    T& operator[](size_t i) { return ptr[i]; }
    const T& operator[](size_t i) const { return ptr[i]; }
};

class MsQuicApi : public QUIC_API_TABLE {
    const void* ApiTable {nullptr};
    QUIC_STATUS InitStatus {QUIC_STATUS_INVALID_STATE};
    const MsQuicCloseFn CloseFn {nullptr};
public:
    MsQuicApi(
        MsQuicOpenVersionFn _OpenFn = MsQuicOpenVersion,
        MsQuicCloseFn _CloseFn = MsQuicClose) noexcept : CloseFn(_CloseFn) {
        if (QUIC_SUCCEEDED(InitStatus = _OpenFn(QUIC_API_VERSION_2, &ApiTable))) {
            QUIC_API_TABLE* thisTable = this;
            memcpy(thisTable, ApiTable, sizeof(QUIC_API_TABLE));
        }
    }
    ~MsQuicApi() noexcept {
        if (QUIC_SUCCEEDED(InitStatus)) {
            CloseFn(ApiTable);
            ApiTable = nullptr;
            QUIC_API_TABLE* thisTable = this;
            memset(thisTable, 0, sizeof(*thisTable));
        }
    }
    MsQuicApi(const MsQuicApi&) = delete;
    MsQuicApi& operator=(const MsQuicApi&) = delete;
    MsQuicApi(MsQuicApi&&) = delete;
    MsQuicApi& operator=(MsQuicApi&&) = delete;
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept { return QUIC_SUCCEEDED(InitStatus); }
};

extern const MsQuicApi* MsQuic;

#ifndef _KERNEL_MODE
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

struct MsQuicExecution {
    QUIC_EXECUTION** Executions {nullptr};
    uint32_t Count {0};
    MsQuicExecution(QUIC_EVENTQ* EventQ, QUIC_GLOBAL_EXECUTION_CONFIG_FLAGS Flags = QUIC_GLOBAL_EXECUTION_CONFIG_FLAG_NONE, uint32_t PollingIdleTimeoutUs = 0) noexcept : Count(1) {
        QUIC_EXECUTION_CONFIG Config = { 0, EventQ };
        Initialize(Flags, PollingIdleTimeoutUs, &Config);
    }
    MsQuicExecution(QUIC_EVENTQ** EventQ, uint32_t Count, QUIC_GLOBAL_EXECUTION_CONFIG_FLAGS Flags = QUIC_GLOBAL_EXECUTION_CONFIG_FLAG_NONE, uint32_t PollingIdleTimeoutUs = 0) noexcept : Count(Count) {
        auto Configs = new(std::nothrow) QUIC_EXECUTION_CONFIG[Count];
        if (Configs != nullptr) {
            for (uint32_t i = 0; i < Count; ++i) {
                Configs[i].IdealProcessor = i;
                Configs[i].EventQ = EventQ[i];
            }
            Initialize(Flags, PollingIdleTimeoutUs, Configs);
            delete [] Configs;
        }
    }
    MsQuicExecution(const MsQuicExecution&) = delete;
    MsQuicExecution& operator=(const MsQuicExecution&) = delete;
    MsQuicExecution(MsQuicExecution&&) = delete;
    MsQuicExecution& operator=(MsQuicExecution&&) = delete;
    void Initialize(
        _In_ QUIC_GLOBAL_EXECUTION_CONFIG_FLAGS Flags, // Used for datapath type
        _In_ uint32_t PollingIdleTimeoutUs,
        _In_reads_(this->Count) QUIC_EXECUTION_CONFIG* Configs
        )
    {
        Executions = new(std::nothrow) QUIC_EXECUTION*[Count];
        if (Executions != nullptr) {
            auto Status =
                MsQuic->ExecutionCreate(
                    Flags,
                    PollingIdleTimeoutUs,
                    Count,
                    Configs,
                    Executions);
            if (QUIC_FAILED(Status)) {
                delete [] Executions;
                Executions = nullptr;
            }
        }
    }
    bool IsValid() const noexcept { return Executions != nullptr; }
    QUIC_EXECUTION* operator[](size_t i) const {
        return Executions[i];
    }
};

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
#endif // _KERNEL_MODE

struct MsQuicRegistration {
    bool CloseAllConnectionsOnDelete {false};
    HQUIC Handle {nullptr};
    QUIC_STATUS InitStatus;

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
    MsQuicRegistration(const MsQuicRegistration& Other) = delete;
    MsQuicRegistration& operator=(const MsQuicRegistration& Other) = delete;
    MsQuicRegistration(MsQuicRegistration&& Other) = delete;
    MsQuicRegistration& operator=(MsQuicRegistration&& Other) = delete;
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
    MsQuicVersionSettings(const uint32_t* Versions, uint32_t Length) noexcept {
        AcceptableVersions = OfferedVersions = FullyDeployedVersions = Versions;
        AcceptableVersionsLength = OfferedVersionsLength = FullyDeployedVersionsLength = Length;
    }
    MsQuicVersionSettings& SetAllVersionLists(const uint32_t* Versions, uint32_t Length) {
        AcceptableVersions = OfferedVersions = FullyDeployedVersions = Versions;
        AcceptableVersionsLength = OfferedVersionsLength = FullyDeployedVersionsLength = Length;
        return *this;
    }
    QUIC_STATUS
    SetGlobal() const noexcept {
        const QUIC_VERSION_SETTINGS* Settings = this;
        return
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                sizeof(*Settings),
                Settings);
    }
    QUIC_STATUS
    GetGlobal() noexcept {
        QUIC_VERSION_SETTINGS* Settings = this;
        uint32_t Size = sizeof(*Settings);
        return
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_VERSION_SETTINGS,
                &Size,
                Settings);
    }
};

static_assert(sizeof(QUIC_VERSION_SETTINGS) == sizeof(MsQuicVersionSettings), "Cpp wrappers must not change size");
#endif

class MsQuicGlobalSettings : public QUIC_GLOBAL_SETTINGS {
public:
    MsQuicGlobalSettings() noexcept { IsSetFlags = 0; }
    MsQuicGlobalSettings& SetRetryMemoryLimit(uint16_t Value) { RetryMemoryLimit = Value; IsSet.RetryMemoryLimit = TRUE; return *this; }
    MsQuicGlobalSettings& SetLoadBalancingMode(uint16_t Value) { LoadBalancingMode = Value; IsSet.LoadBalancingMode = TRUE; return *this; }
    MsQuicGlobalSettings& SetFixedServerID(uint32_t Value) { FixedServerID = Value; IsSet.FixedServerID = TRUE; return *this; }

    QUIC_STATUS Set() const noexcept {
        const QUIC_GLOBAL_SETTINGS* Settings = this;
        return
            MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS,
                sizeof(*Settings),
                Settings);
    }

    QUIC_STATUS Get() noexcept {
        QUIC_GLOBAL_SETTINGS* Settings = this;
        uint32_t Size = sizeof(*Settings);
        return
            MsQuic->GetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS,
                &Size,
                Settings);
    }
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
    MsQuicSettings& SetStreamRecvWindowDefault(uint32_t Value) { StreamRecvWindowDefault = Value; IsSet.StreamRecvWindowDefault = TRUE; return *this; }
    MsQuicSettings& SetMaxBytesPerKey(uint64_t Value) { MaxBytesPerKey = Value; IsSet.MaxBytesPerKey = TRUE; return *this; }
    MsQuicSettings& SetMaxAckDelayMs(uint32_t Value) { MaxAckDelayMs = Value; IsSet.MaxAckDelayMs = TRUE; return *this; }
    MsQuicSettings& SetMaximumMtu(uint16_t Mtu) { MaximumMtu = Mtu; IsSet.MaximumMtu = TRUE; return *this; }
    MsQuicSettings& SetMinimumMtu(uint16_t Mtu) { MinimumMtu = Mtu; IsSet.MinimumMtu = TRUE; return *this; }
    MsQuicSettings& SetMtuDiscoverySearchCompleteTimeoutUs(uint64_t Time) { MtuDiscoverySearchCompleteTimeoutUs = Time; IsSet.MtuDiscoverySearchCompleteTimeoutUs = TRUE; return *this; }
    MsQuicSettings& SetMtuDiscoveryMissingProbeCount(uint8_t Count) { MtuDiscoveryMissingProbeCount = Count; IsSet.MtuDiscoveryMissingProbeCount = TRUE; return *this; }
    MsQuicSettings& SetKeepAlive(uint32_t Time) { KeepAliveIntervalMs = Time; IsSet.KeepAliveIntervalMs = TRUE; return *this; }
    MsQuicSettings& SetConnFlowControlWindow(uint32_t Window) { ConnFlowControlWindow = Window; IsSet.ConnFlowControlWindow = TRUE; return *this; }
    MsQuicSettings& SetCongestionControlAlgorithm(QUIC_CONGESTION_CONTROL_ALGORITHM Cc) { CongestionControlAlgorithm = (uint8_t)Cc; IsSet.CongestionControlAlgorithm = TRUE; return *this; }
    MsQuicSettings& SetDestCidUpdateIdleTimeoutMs(uint32_t Value) { DestCidUpdateIdleTimeoutMs = Value; IsSet.DestCidUpdateIdleTimeoutMs = TRUE; return *this; }
    MsQuicSettings& SetGreaseQuicBitEnabled(bool Value) { GreaseQuicBitEnabled = Value; IsSet.GreaseQuicBitEnabled = TRUE; return *this; }
    MsQuicSettings& SetEcnEnabled(bool Value) { EcnEnabled = Value; IsSet.EcnEnabled = TRUE; return *this; }
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    MsQuicSettings& SetEncryptionOffloadAllowed(bool Value) { EncryptionOffloadAllowed = Value; IsSet.EncryptionOffloadAllowed = TRUE; return *this; }
    MsQuicSettings& SetReliableResetEnabled(bool value) { ReliableResetEnabled = value; IsSet.ReliableResetEnabled = TRUE; return *this; }
    MsQuicSettings& SetXdpEnabled(bool value) { XdpEnabled = value; IsSet.XdpEnabled = TRUE; return *this; }
    MsQuicSettings& SetQtipEnabled(bool value) { QTIPEnabled = value; IsSet.QTIPEnabled = TRUE; return *this; }
    MsQuicSettings& SetRioEnabled(bool value) { RioEnabled = value; IsSet.RioEnabled = TRUE; return *this; }
    MsQuicSettings& SetOneWayDelayEnabled(bool value) { OneWayDelayEnabled = value; IsSet.OneWayDelayEnabled = TRUE; return *this; }
    MsQuicSettings& SetNetStatsEventEnabled(bool value) { NetStatsEventEnabled = value; IsSet.NetStatsEventEnabled = TRUE; return *this; }
    MsQuicSettings& SetStreamMultiReceiveEnabled(bool value) { StreamMultiReceiveEnabled = value; IsSet.StreamMultiReceiveEnabled = TRUE; return *this; }
#endif

    QUIC_STATUS
    SetGlobal() const noexcept {
        if (IsSetFlags == 0) {
            return QUIC_STATUS_SUCCESS; // Nothing to set
        }
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

struct MsQuicConfiguration {
    HQUIC Handle {nullptr};
    QUIC_STATUS InitStatus;
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
    MsQuicConfiguration(const MsQuicConfiguration& Other) = delete;
    MsQuicConfiguration& operator=(const MsQuicConfiguration& Other) = delete;
    MsQuicConfiguration(MsQuicConfiguration&& Other) = delete;
    MsQuicConfiguration& operator=(MsQuicConfiguration&& Other) = delete;
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
        if (Settings.IsSetFlags == 0) {
            return QUIC_STATUS_SUCCESS; // Nothing to set
        }
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
    GetVersionSettings(
        _Out_ MsQuicVersionSettings& Settings,
        _Inout_ uint32_t* SettingsLength) noexcept {
        QUIC_VERSION_SETTINGS* VSettings = &Settings;
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                SettingsLength,
                VSettings);
    }

    QUIC_STATUS
    SetVersionNegotiationExtEnabled(_In_ const bool Value = true) noexcept {
        BOOLEAN _Value = Value;
        return MsQuic->SetParam(
            Handle,
            QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED,
            sizeof(_Value),
            &_Value);
    }
#endif
};

enum MsQuicCleanUpMode {
    CleanUpManual,
    CleanUpAutoDelete,
};

typedef QUIC_STATUS QUIC_API MsQuicListenerCallback(
    _In_ struct MsQuicListener* Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
);

struct MsQuicListener {
    HQUIC Handle { nullptr };
    QUIC_STATUS InitStatus;
    MsQuicCleanUpMode CleanUpMode;
    MsQuicListenerCallback* Callback{ nullptr };
    void* Context{ nullptr };

    MsQuicListener(
        _In_ const MsQuicRegistration& Registration,
        _In_ MsQuicCleanUpMode CleanUpMode,
        _In_ MsQuicListenerCallback* Callback,
        _In_ void* Context = nullptr
        ) noexcept : CleanUpMode(CleanUpMode), Callback(Callback), Context(Context) {
        if (!Registration.IsValid()) {
            InitStatus = Registration.GetInitStatus();
            return;
        }
        if (QUIC_FAILED(
            InitStatus =
                MsQuic->ListenerOpen(
                    Registration,
                    (QUIC_LISTENER_CALLBACK_HANDLER)MsQuicCallback,
                    this,
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
        _In_opt_ const QUIC_ADDR* Address = nullptr
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
    MsQuicListener(const MsQuicListener& Other) = delete;
    MsQuicListener& operator=(const MsQuicListener& Other) = delete;
    MsQuicListener(MsQuicListener&& Other) = delete;
    MsQuicListener& operator=(MsQuicListener&& Other) = delete;
    operator HQUIC () const noexcept { return Handle; }

private:
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK)
    static
    QUIC_STATUS
    QUIC_API
    MsQuicCallback(
        _In_ HQUIC /* Listener */,
        _In_opt_ MsQuicListener* pThis,
        _Inout_ QUIC_LISTENER_EVENT* Event
        ) noexcept {
        CXPLAT_DBG_ASSERT(pThis);
        auto DeleteOnExit =
            Event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE &&
            pThis->CleanUpMode == CleanUpAutoDelete;
        auto Status = pThis->Callback(pThis, pThis->Context, Event);
        if (DeleteOnExit) {
            delete pThis;
        }
        return Status;
    }
};

typedef QUIC_STATUS QUIC_API MsQuicConnectionCallback(
    _In_ struct MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    );

struct MsQuicConnection {
    HQUIC Handle {nullptr};
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
        _In_ const MsQuicRegistration& Registration,
        _In_ uint16_t PartitionIndex,
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
                MsQuic->ConnectionOpenInPartition(
                    Registration,
                    PartitionIndex,
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
        Close();
        delete[] ResumptionTicket;
    }

    void
    Shutdown(
        _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode, // Application defined error code
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags = QUIC_CONNECTION_SHUTDOWN_FLAG_NONE
        ) noexcept {
        MsQuic->ConnectionShutdown(Handle, Flags, ErrorCode);
    }

    void
    Close(
    ) noexcept {
#ifdef _WIN32
        auto HandleToClose = (HQUIC)InterlockedExchangePointer((PVOID*)&Handle, NULL);
#else
        auto HandleToClose = (HQUIC)__sync_fetch_and_and(&Handle, 0);
#endif
        if (HandleToClose) {
            MsQuic->ConnectionClose(HandleToClose);
        }
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
    MsQuicConnection(const MsQuicConnection& Other) = delete;
    MsQuicConnection& operator=(const MsQuicConnection& Other) = delete;
    MsQuicConnection(MsQuicConnection&& Other) = delete;
    MsQuicConnection& operator=(MsQuicConnection&& Other) = delete;
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
    const MsQuicConfiguration* Configuration;
    MsQuicConnectionCallback* ConnectionHandler;
    MsQuicConnection* LastConnection {nullptr};
    void* ConnectionContext;
#ifdef CX_PLATFORM_TYPE
    uint32_t AcceptedConnectionCount {0};
#endif

    MsQuicAutoAcceptListener(
        _In_ const MsQuicRegistration& Registration,
        _In_ MsQuicConnectionCallback* _ConnectionHandler,
        _In_ void* _ConnectionContext = nullptr
        ) noexcept :
        MsQuicListener(Registration, CleanUpManual, ListenerCallback, this),
        Configuration(nullptr),
        ConnectionHandler(_ConnectionHandler),
        ConnectionContext(_ConnectionContext)
    { }

    MsQuicAutoAcceptListener(
        _In_ const MsQuicRegistration& Registration,
        _In_ const MsQuicConfiguration& Config,
        _In_ MsQuicConnectionCallback* _ConnectionHandler,
        _In_ void* _ConnectionContext = nullptr
        ) noexcept :
        MsQuicListener(Registration, CleanUpManual, ListenerCallback, this),
        Configuration(&Config),
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
        _In_ MsQuicListener* /* Listener */,
        _In_opt_ void* Context,
        _Inout_ QUIC_LISTENER_EVENT* Event
        ) noexcept {
        auto pThis = (MsQuicAutoAcceptListener*)Context; CXPLAT_DBG_ASSERT(pThis);
        QUIC_STATUS Status = QUIC_STATUS_INVALID_STATE;
        if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
            auto Connection = new(std::nothrow) MsQuicConnection(Event->NEW_CONNECTION.Connection, CleanUpAutoDelete, pThis->ConnectionHandler, pThis->ConnectionContext);
            if (Connection) {
                if (!pThis->Configuration ||
                    QUIC_FAILED(Status = Connection->SetConfiguration(*pThis->Configuration))) {
                    //
                    // The connection is being rejected. Let MsQuic free the handle.
                    //
                    Connection->Handle = nullptr;
                    delete Connection;
                } else {
                    Status = QUIC_STATUS_SUCCESS;
                    pThis->LastConnection = Connection;
#ifdef CX_PLATFORM_TYPE
                    InterlockedIncrement((long*)&pThis->AcceptedConnectionCount);
#endif
                }
            }
        }
        return Status;
    }
};

typedef QUIC_STATUS QUIC_API MsQuicStreamCallback(
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
        _In_ MsQuicStreamCallback* Callback = NoOpCallback,
        _In_ void* Context = nullptr
        ) noexcept : CleanUpMode(CleanUpMode), Callback(Callback), Context(Context) {
        Handle = StreamHandle;
        MsQuic->SetCallbackHandler(Handle, (void*)MsQuicCallback, this);
        InitStatus = QUIC_STATUS_SUCCESS;
    }

    ~MsQuicStream() noexcept {
        Close();
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
    Close(
    ) noexcept {
#ifdef _WIN32
        auto HandleToClose = (HQUIC)InterlockedExchangePointer((PVOID*)&Handle, NULL);
#else
        HQUIC HandleToClose = (HQUIC)__sync_fetch_and_and(&Handle, 0);
#endif
        if (HandleToClose) {
            MsQuic->StreamClose(HandleToClose);
        }
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

    QUIC_STATUS
    GetIdealSendBufferSize(_Out_ uint64_t* SendBufferSize) const noexcept {
        uint32_t Size = sizeof(*SendBufferSize);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,
                &Size,
                SendBufferSize);
    }

    QUIC_STATUS
    GetStatistics(_Out_ QUIC_STREAM_STATISTICS* Statistics) const noexcept {
        uint32_t Size = sizeof(*Statistics);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_STREAM_STATISTICS,
                &Size,
                Statistics);
    }

    #ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    QUIC_STATUS
    SetReliableOffset(_In_ uint64_t Offset) noexcept {
        return
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_STREAM_RELIABLE_OFFSET,
                sizeof(Offset),
                &Offset);
    }

    QUIC_STATUS
    GetReliableOffset(_Out_ uint64_t* Offset) const noexcept {
        uint32_t Size = sizeof(*Offset);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_STREAM_RELIABLE_OFFSET,
                &Size,
                Offset);
    }

    QUIC_STATUS
    ProvideReceiveBuffers(
        _In_ uint32_t BufferCount,
        _In_reads_(BufferCount) const QUIC_BUFFER* Buffers
        ) const noexcept {
        return MsQuic->StreamProvideReceiveBuffers(Handle, BufferCount, Buffers);
    }

    QUIC_STATUS
    GetReliableOffsetRecv(_Out_ uint64_t* Offset) const noexcept {
        uint32_t Size = sizeof(*Offset);
        return
            MsQuic->GetParam(
                Handle,
                QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV,
                &Size,
                Offset);
    }
    #endif

    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    MsQuicStream(const MsQuicStream& Other) = delete;
    MsQuicStream& operator=(const MsQuicStream& Other) = delete;
    MsQuicStream(MsQuicStream&& Other) = delete;
    MsQuicStream& operator=(MsQuicStream&& Other) = delete;
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
    ConnectionScope(const ConnectionScope&) = delete;
    ConnectionScope& operator=(const ConnectionScope&) = delete;
    ConnectionScope(ConnectionScope&&) = delete;
    ConnectionScope& operator=(ConnectionScope&&) = delete;
    operator HQUIC() const noexcept { return Handle; }
};

static_assert(sizeof(ConnectionScope) == sizeof(HQUIC), "Scope guards should be the same size as the guarded type");

struct StreamScope {
    HQUIC Handle;
    StreamScope() noexcept : Handle(nullptr) { }
    StreamScope(HQUIC handle) noexcept : Handle(handle) { }
    ~StreamScope() noexcept { if (Handle) { MsQuic->StreamClose(Handle); } }
    StreamScope(const StreamScope&) = delete;
    StreamScope& operator=(const StreamScope&) = delete;
    StreamScope(StreamScope&&) = delete;
    StreamScope& operator=(StreamScope&&) = delete;
    operator HQUIC() const noexcept { return Handle; }
};

static_assert(sizeof(StreamScope) == sizeof(HQUIC), "Scope guards should be the same size as the guarded type");

struct ConfigurationScope {
    HQUIC Handle;
    ConfigurationScope() noexcept : Handle(nullptr) { }
    ConfigurationScope(HQUIC handle) noexcept : Handle(handle) { }
    ~ConfigurationScope() noexcept { if (Handle) { MsQuic->ConfigurationClose(Handle); } }
    ConfigurationScope(const ConfigurationScope&) = delete;
    ConfigurationScope& operator=(const ConfigurationScope&) = delete;
    ConfigurationScope(ConfigurationScope&&) = delete;
    ConfigurationScope& operator=(ConfigurationScope&&) = delete;
    operator HQUIC() const noexcept { return Handle; }
};

static_assert(sizeof(ConfigurationScope) == sizeof(HQUIC), "Scope guards should be the same size as the guarded type");

struct QuicBufferScope {
    QUIC_BUFFER* Buffer;
    QuicBufferScope() noexcept : Buffer(nullptr) { }
    QuicBufferScope(uint32_t Size) noexcept : Buffer((QUIC_BUFFER*) new(std::nothrow) uint8_t[sizeof(QUIC_BUFFER) + Size]) {
        CXPLAT_DBG_ASSERT(Buffer);
        memset(Buffer, 0, sizeof(*Buffer) + Size);
        Buffer->Length = Size;
        Buffer->Buffer = (uint8_t*)(Buffer + 1);
    }
    ~QuicBufferScope() noexcept { if (Buffer) { delete[](uint8_t*) Buffer; } }
    QuicBufferScope(const QuicBufferScope&) = delete;
    QuicBufferScope& operator=(const QuicBufferScope&) = delete;
    QuicBufferScope(QuicBufferScope&&) = delete;
    QuicBufferScope& operator=(QuicBufferScope&&) = delete;
    operator QUIC_BUFFER* () noexcept { return Buffer; }
};

static_assert(sizeof(QuicBufferScope) == sizeof(QUIC_BUFFER*), "Scope guards should be the same size as the guarded type");

#endif  //  _MSQUIC_HPP_
