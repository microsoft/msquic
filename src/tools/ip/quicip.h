/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A client helper for resolving the public IP address.

TODO:

    Don't use the QUIC_ADDR format, as it's not cross-platform. Use the same
    format as the QUIC spec's preferred address TP.

--*/

#pragma once

#include "msquic.h"
#include <mutex>
#include <condition_variable>

#ifdef ENABLE_QUIC_PRINTF
#include <stdio.h>
#define QUIC_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define QUIC_PRINTF(fmt, ...)
#endif

#define QUIC_IP_DEFAULT_STATUS QUIC_STATUS_ABORTED

typedef struct QUIC_IP_LOOKUP {
    BOOLEAN Success;
    QUIC_STATUS Status;
    const QUIC_API_TABLE* MsQuic;
    HQUIC Configuration;
    HQUIC Connection;
    QUIC_ADDR* LocalAdrress;
    QUIC_ADDR* PublicAddress;
    std::mutex DoneMutex;
    std::condition_variable DoneEvent;
    bool IsDone {false};
} QUIC_IP_LOOKUP;

inline
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* _Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    QUIC_IP_LOOKUP* Context = (QUIC_IP_LOOKUP*)_Context;
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
        Context->MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        uint32_t LocalAddressLength = sizeof(QUIC_ADDR);
        Context->MsQuic->GetParam(Stream, QUIC_PARAM_CONN_LOCAL_ADDRESS, &LocalAddressLength, Context->LocalAdrress);
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        if (!Context->Success && Context->Status == QUIC_IP_DEFAULT_STATUS) {
            QUIC_PRINTF("Stream Peer Send Aborted!\n");
        }
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        if (!Context->Success && Context->Status == QUIC_IP_DEFAULT_STATUS) {
            QUIC_PRINTF("Stream Peer Receive Aborted!\n");
        }
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        Context->MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

inline
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC /*Connection*/,
    _In_opt_ void* _Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    QUIC_IP_LOOKUP* Context = (QUIC_IP_LOOKUP*)_Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (!Context->Success && Context->Status == QUIC_IP_DEFAULT_STATUS) {
            QUIC_PRINTF("Connection Shutdown, 0x%x!\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            Context->Status = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        if (!Context->Success && Context->Status == QUIC_IP_DEFAULT_STATUS) {
            QUIC_PRINTF("Connection Shutdown by Peer!\n");
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        {
            Context->MsQuic->ConnectionClose(Context->Connection);
            std::lock_guard Lock{Context->DoneMutex};
            Context->IsDone = true;
            Context->DoneEvent.notify_all();
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        Context->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ClientStreamCallback, Context);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

inline
QUIC_STATUS
MsQuicGetPublicIPEx(
    _In_ const QUIC_API_TABLE* MsQuic,
    _In_ HQUIC Registration,
    _In_ const char* Target,
    _In_ BOOLEAN Unsecure,
    _In_ QUIC_ADDR* LocalAddress, // Can be unspecified
    _Out_ QUIC_ADDR* PublicAddress
    )
{
    const QUIC_BUFFER Alpn = { sizeof("ip") - 1, (uint8_t*)"ip" };
    const uint16_t UdpPort = 4444;

    QUIC_SETTINGS Settings{0};
    Settings.IdleTimeoutMs = 2000;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.PeerUnidiStreamCount = 1;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG CredConfig;
    CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    QUIC_IP_LOOKUP Context = {
        FALSE, QUIC_STATUS_SUCCESS, MsQuic, NULL, NULL, LocalAddress, PublicAddress
    };

    if (QUIC_FAILED(Context.Status = Context.MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Context.Configuration))) {
        QUIC_PRINTF("ConfigurationOpen failed, 0x%x!\n", Context.Status);
        goto Error;
    }

    if (QUIC_FAILED(Context.Status = Context.MsQuic->ConfigurationLoadCredential(Context.Configuration, &CredConfig))) {
        QUIC_PRINTF("ConfigurationLoadCredential failed, 0x%x!\n", Context.Status);
        goto Error;
    }

    if (QUIC_FAILED(Context.Status = Context.MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, &Context, &Context.Connection))) {
        QUIC_PRINTF("ConnectionOpen failed, 0x%x!\n", Context.Status);
        goto Error;
    }

    if (QUIC_ADDRESS_FAMILY_UNSPEC != QuicAddrGetFamily(LocalAddress)) {
        if (QUIC_FAILED(Context.Status = Context.MsQuic->SetParam(Context.Connection, QUIC_PARAM_CONN_LOCAL_ADDRESS, sizeof(QUIC_ADDR), LocalAddress))) {
            QUIC_PRINTF("SetParam(CONN_LOCAL_ADDRESS) failed, 0x%x!\n", Context.Status);
            goto Error;
        }
    }

    Context.Status = QUIC_IP_DEFAULT_STATUS;

    QUIC_STATUS Status; // Don't use Context.Status as it might overwrite real error on success.
    if (QUIC_FAILED(Status = Context.MsQuic->ConnectionStart(Context.Connection, Context.Configuration, QuicAddrGetFamily(LocalAddress), Target, UdpPort))) {
        Context.Status = Status;
        QUIC_PRINTF("ConnectionStart failed, 0x%x!\n", Context.Status);
        Context.MsQuic->ConnectionClose(Context.Connection);
        goto Error;
    }

    {
        std::unique_lock Lock{Context.DoneMutex};
        Context.DoneEvent.wait(Lock, [&]{return Context.IsDone;});
    }

Error:

    if (Context.Configuration) {
        Context.MsQuic->ConfigurationClose(Context.Configuration);
    }

    return Context.Success ? QUIC_STATUS_SUCCESS : Context.Status;
}

inline
QUIC_STATUS
MsQuicGetPublicIP(
    _In_ const char* Target,
    _In_ BOOLEAN Unsecure,
    _In_ QUIC_ADDR* LocalAddress, // Can be unspecified
    _Out_ QUIC_ADDR* PublicAddress
    )
{
    QUIC_STATUS Status;
    const QUIC_API_TABLE* MsQuic = NULL;
    HQUIC Registration = NULL;
    const QUIC_REGISTRATION_CONFIG RegConfig = { "ip", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        QUIC_PRINTF("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        QUIC_PRINTF("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuicGetPublicIPEx(MsQuic, Registration, Target, Unsecure, LocalAddress, PublicAddress))) {
        goto Error;
    }

Error:

    if (MsQuic) {
        if (Registration) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return Status;
}
