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
#ifdef _KERNEL_MODE
extern uint8_t SelfSignedSecurityHash[20];
#else
extern QUIC_SEC_CONFIG_PARAMS* SelfSignedParams;
#endif
extern bool IsSelfSignedValid;

#define QUIC_TEST_SESSION_CLOSED    1

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
    QUIC_LISTENER_CALLBACK_HANDLER Handler;
    void* Context;
    MsQuicListener(const MsQuicSession& Session) {
        if (!Session.IsValid()) {
            return;
        }
        if (QUIC_FAILED(
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
        _In_ QUIC_LISTENER_CALLBACK_HANDLER ShadowHandler,
        _In_ void* ShadowContext) {
        Handler = ShadowHandler;
        Context = ShadowContext;
        return MsQuic->ListenerStart(Handle, Address);
    }

    QUIC_STATUS
    ListenerCallback(HQUIC Listener, QUIC_LISTENER_EVENT* Event) {
        return Handler(Listener, Context, Event);
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
#ifdef _KERNEL_MODE
            CreateSecConfigHelper Helper;
            SecurityConfig =
                Helper.Create(
                    MsQuic,
                    Registration,
                    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
                    &SelfSignedSecurityHash,
                    nullptr);
#else
            SecurityConfig =
                GetSecConfigForSelfSigned(
                    MsQuic,
                    Registration,
                    SelfSignedParams);
#endif
            if (!SecurityConfig) {
                WriteOutput("Failed to create security config for self signed certificate\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else {
            const char* certThumbprint;
            if (!TryGetValue(argc, argv, "thumbprint", &certThumbprint)) {
                WriteOutput("Must specify -thumbprint: for server mode.\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            const char* certStoreName;
            if (!TryGetValue(argc, argv, "cert_store", &certStoreName)) {
                SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, certThumbprint);
                if (SecurityConfig == nullptr) {
                    WriteOutput("Failed to create security configuration for thumbprint:'%s'.\n", certThumbprint);
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
            } else {
                uint32_t machineCert = 0;
                TryGetValue(argc, argv, "machine_cert", &machineCert);
                QUIC_CERTIFICATE_HASH_STORE_FLAGS flags =
                    machineCert ? QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE : QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;

                SecurityConfig = GetSecConfigForThumbprintAndStore(MsQuic, Registration, flags, certThumbprint, certStoreName);
                if (SecurityConfig == nullptr) {
                    WriteOutput(
                        "Failed to create security configuration for thumbprint:'%s' and store: '%s'.\n",
                        certThumbprint,
                        certStoreName);
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
            }
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
