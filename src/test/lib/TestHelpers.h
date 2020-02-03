/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Test Helpers

--*/

#define QUIC_TEST_NO_ERROR          0
#define QUIC_TEST_SESSION_CLOSED    1
#define QUIC_TEST_SPECIAL_ERROR     0x1234

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
    MsQuicSession(_In_ const char* ALPN = "MsQuicTest", _In_ bool AutoCleanup = false)
        : Handle(nullptr),
        CloseAllConnectionsOnDelete(AutoCleanup) {
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Registration,
                ALPN,
                nullptr,
                &Handle))) {
            Handle = nullptr;
        }
    }
    MsQuicSession(HQUIC Reg, _In_ const char* ALPN = "MsQuicTest", _In_ bool AutoCleanup = false)
        : Handle(nullptr),
        CloseAllConnectionsOnDelete(AutoCleanup) {
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Reg,
                ALPN,
                nullptr,
                &Handle))) {
            Handle = nullptr;
        }
    }
    MsQuicSession(MsQuicRegistration& Reg, _In_ const char* ALPN = "MsQuicTest", _In_ bool AutoCleanup = false)
        : Handle(nullptr),
        CloseAllConnectionsOnDelete(AutoCleanup) {
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Reg,
                ALPN,
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
