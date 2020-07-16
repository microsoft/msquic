/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A client helper for resolving the public IP address.

TODO:

    Don't use the QUIC_ADDR format, as it's not cross-platform. Use the same
    format as the QUIC spec's preferred address TP.

--*/

#include <msquichelper.h>

const QUIC_API_TABLE* MsQuic;

typedef struct CALLBACK_CONTEXT {
    BOOLEAN Success;
    QUIC_ADDR* LocalAdrress;
    QUIC_ADDR* PublicAddress;
} CALLBACK_CONTEXT;

QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* _Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    CALLBACK_CONTEXT* Context = (CALLBACK_CONTEXT*)_Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.AbsoluteOffset + Event->RECEIVE.TotalBufferLength <= sizeof(QUIC_ADDR)) {
            uint64_t Offset = Event->RECEIVE.AbsoluteOffset;
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                memcpy(
                    ((uint8_t*)Context->PublicAddress) + Offset,
                    Event->RECEIVE.Buffers[i].Buffer,
                    Event->RECEIVE.Buffers[i].Length);
                Offset += Event->RECEIVE.Buffers[i].Length;
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
        Context->Success = TRUE;
        MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        uint32_t LocalAddressLength = sizeof(QUIC_ADDR);
        MsQuic->GetParam(Stream, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_LOCAL_ADDRESS, &LocalAddressLength, Context->LocalAdrress);
        break;
    }
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ClientStreamCallback, Context);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

BOOLEAN
MsQuicGetPublicIP(
    _In_ const char* Target,
    _In_ BOOLEAN Unsecure,
    _In_ QUIC_ADDR* LocalAddress, // Can be unspecified
    _Out_ QUIC_ADDR* PublicAddress
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    const QUIC_REGISTRATION_CONFIG RegConfig = { "ip", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    const QUIC_BUFFER Alpn = { sizeof("ip") - 1, (uint8_t*)"ip" };
    const uint16_t UdpPort = 4444;
    const uint64_t IdleTimeoutMs = 2000;
    const uint16_t PeerStreamCount = 1;

    HQUIC Registration = nullptr;
    HQUIC Session = nullptr;
    HQUIC Connection = nullptr;

    CALLBACK_CONTEXT Context = { FALSE, LocalAddress, PublicAddress };

    if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SessionOpen(Registration, &Alpn, 1, nullptr, &Session))) {
        printf("SessionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_IDLE_TIMEOUT, sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
        printf("SetParam(SESSION_IDLE_TIMEOUT) failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount))) {
        printf("SetParam(SESSION_PEER_UNIDI_STREAM_COUNT) failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Session, ClientConnectionCallback, &Context, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (Unsecure) {
        const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS, sizeof(CertificateValidationFlags), &CertificateValidationFlags))) {
            printf("SetParam(CONN_CERT_VALIDATION_FLAGS) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    if (AF_UNSPEC != QuicAddrGetFamily(LocalAddress)) {
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_LOCAL_ADDRESS, sizeof(QUIC_ADDR), LocalAddress))) {
            printf("SetParam(CONN_LOCAL_ADDRESS) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, QuicAddrGetFamily(LocalAddress), Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

Error:

    if (MsQuic) {
        if (QUIC_FAILED(Status) && Connection) {
            MsQuic->ConnectionClose(Connection);
        }
        if (Session) {
            MsQuic->SessionClose(Session); // Waits on all connections to be cleaned up.
        }
        if (Registration) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return Context.Success;
}
