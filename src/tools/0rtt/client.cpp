/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_platform.h"
#include "msquic.hpp"
#include "quic_0rtt.h"

#define QUIC_0RTT_CLIENT_WAIT_TIMEOUT_MS 100

#define QUIC_0RTT_CLIENT_CREDENTIAL_FLAGS \
    (QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)

typedef struct QUIC_0RTT_CLIENT {
    MsQuicRegistration Registration {true};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(QUIC_0RTT_ALPN),
        MsQuicSettings().SetPeerBidiStreamCount(100),
        MsQuicCredentialConfig(QUIC_0RTT_CLIENT_CREDENTIAL_FLAGS)};
    MsQuicConnection Connection {
        Registration,
        CleanUpManual,
        MsQuicConnection::NoOpCallback,
        this};
    uint64_t DataCenterId;
    uint64_t ServerId;
    uint64_t IdIndex {0};
    bool IsValid() const { return Configuration.IsValid() && Connection.IsValid(); }
    QUIC_0RTT_CLIENT(uint64_t DataCenterId, uint64_t ServerId) : DataCenterId(DataCenterId), ServerId(ServerId) {}
    bool Connect(_In_z_ const char* ServerName) {
        return QUIC_SUCCEEDED(Connection.Start(Configuration, ServerName, QUIC_0RTT_PORT));
    }
    void NewIdenfitier(_Out_ QUIC_0RTT_IDENTIFIER* Id) {
        Id->DataCenter = DataCenterId;
        Id->Server = ServerId;
        Id->Index = InterlockedIncrement64((LONG64*)&IdIndex);
    }
} QUIC_0RTT_CLIENT;

extern "C"
QUIC_0RTT_CLIENT*
Quic0RttClientInitialize(
    _In_ uint64_t DataCenterId,
    _In_ uint64_t ServerId,
    _In_z_ const char* ServerName
    )
{
    auto Client = new(std::nothrow) QUIC_0RTT_CLIENT(DataCenterId, ServerId);
    if (Client) {
        if (!Client->IsValid() || !Client->Connect(ServerName)) {
            delete Client;
            Client = nullptr;
        }
    }
    return Client;
}

extern "C"
void
Quic0RttClientUninitialize(
    _In_ QUIC_0RTT_CLIENT* Client
    )
{
    delete Client;
}

extern "C"
void
Quic0RttClientGenerateIdentifier(
    _In_ QUIC_0RTT_CLIENT* Client,
    _Out_writes_(QUIC_0RTT_ID_LENGTH)
        uint8_t* Identifier
    )
{
    Client->NewIdenfitier((QUIC_0RTT_IDENTIFIER*)Identifier);
}

MsQuicStreamCallback Quic0RttClientStreamCallback;

typedef struct QUIC_0RTT_REQUEST {
    QUIC_0RTT_CLIENT& Client;
    CxPlatEvent CompletionEvent;
    MsQuicStream Stream {
        Client.Connection,
        QUIC_STREAM_OPEN_FLAG_NONE,
        CleanUpManual,
        Quic0RttClientStreamCallback,
        &CompletionEvent};
    QUIC_BUFFER Buffer {QUIC_0RTT_ID_LENGTH, nullptr};
    bool Success {false};
    QUIC_0RTT_REQUEST(QUIC_0RTT_CLIENT& Client) : Client(Client) {}
    bool IsValid() const { return Stream.IsValid(); }
    bool Send(_In_reads_(QUIC_0RTT_ID_LENGTH) uint8_t* Identifier) {
        Buffer.Buffer = Identifier;
        return QUIC_SUCCEEDED(Stream.Send(&Buffer, 1, QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN));
    }
    bool WaitForResponse() {
        return CompletionEvent.WaitTimeout(QUIC_0RTT_CLIENT_WAIT_TIMEOUT_MS) && Success;
    }
} QUIC_0RTT_REQUEST;

extern "C"
BOOLEAN
Quic0RttClientValidateIdentifier(
    _In_ QUIC_0RTT_CLIENT* Client,
    _In_reads_(QUIC_0RTT_ID_LENGTH)
        uint8_t* Identifier
    )
{
    auto Id = (QUIC_0RTT_IDENTIFIER*)Identifier;
    if (Id->DataCenter != Client->DataCenterId || Id->Server != Client->ServerId) {
        return false;
    }

    QUIC_0RTT_REQUEST Request(*Client);
    return
        Request.IsValid() &&
        Request.Send(Identifier) &&
        Request.WaitForResponse();
}

QUIC_STATUS
Quic0RttClientStreamCallback(
    _In_ MsQuicStream* Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) noexcept
{
    auto Request = (QUIC_0RTT_REQUEST*)Context;
    if (Event->Type == QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN) {
        Request->Success = true;
    } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
        Request->CompletionEvent.Set();
    }
    return QUIC_STATUS_SUCCESS;
}
