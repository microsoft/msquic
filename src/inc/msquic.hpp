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

class QuicApiTable : public QUIC_API_TABLE {
    QUIC_STATUS Init;
public:
    QuicApiTable() {
        const QUIC_API_TABLE* table;
        if (QUIC_SUCCEEDED(Init = MsQuicOpen(&table))) {
            QUIC_API_TABLE* thisTable = this;
            QuicCopyMemory(thisTable, table, sizeof(*table));
        }
    }

    ~QuicApiTable() {
        if (QUIC_SUCCEEDED(Init)) {
            MsQuicClose(this);
        }
    }

    QUIC_STATUS InitStatus() const {
        return Init;
    }
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
                    1);
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
