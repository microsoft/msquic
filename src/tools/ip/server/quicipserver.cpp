/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A server implementation for a public IP lookup protocol.

TODO:

    Don't use the QUIC_ADDR format, as it's not cross-platform. Use the same
    format as the QUIC spec's preferred address TP.

--*/

#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#include "msquichelper.h"

const QUIC_REGISTRATION_CONFIG RegConfig = { "ip", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("ip") - 1, (uint8_t*)"ip" };
const uint16_t UdpPort = 4444;
const uint64_t IdleTimeoutMs = 2000;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Configuration;

void
PrintUsage()
{
    printf("\nquicip runs a public IP lookup server.\n\n");

    printf("Usage:\n");
    printf("  quicipserver.exe -selfsign:1 or -cert_hash:<...> [and -cert_store:<...> | -machine] or (-cert_file:<...> and -key_file:<...>)\n");
}

QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        CXPLAT_FREE(Event->SEND_COMPLETE.ClientContext, QUIC_POOL_TOOL);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ServerSendIp(
    _In_ HQUIC Connection
    )
{
    QUIC_STATUS Status;
    HQUIC Stream = nullptr;

    auto SendBufferRaw = CXPLAT_ALLOC_PAGED(sizeof(QUIC_BUFFER) + sizeof(QUIC_ADDR), QUIC_POOL_TOOL);
    if (SendBufferRaw == nullptr) {
        return;
    }

    auto SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = sizeof(QUIC_ADDR);

    if (QUIC_FAILED(Status = MsQuic->GetParam(Connection, QUIC_PARAM_CONN_REMOTE_ADDRESS, &SendBuffer->Length, SendBuffer->Buffer))) {
        printf("GetParam(CONN_REMOTE_ADDRESS) failed, 0x%x!\n", Status);
        CXPLAT_FREE(SendBuffer, QUIC_POOL_TOOL);
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, ServerStreamCallback, nullptr, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(Stream);
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        CXPLAT_FREE(SendBufferRaw, QUIC_POOL_TOOL);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        ServerSendIp(Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, nullptr);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    default:
        break;
    }
    return Status;
}

void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Listener = nullptr;

    QUIC_SETTINGS Settings{0};
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    Configuration =
        GetServerConfigurationFromArgs(
            argc,
            argv,
            MsQuic,
            Registration,
            &Alpn,
            1,
            &Settings,
            sizeof(Settings));
    if (!Configuration) {
        printf("Failed to load configuration from args!\n");
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, nullptr, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Press Enter to exit.\n\n");
    getchar();

Error:

    if (Listener != nullptr) {
        MsQuic->ListenerClose(Listener);
    }
    if (Configuration) {
        FreeServerConfiguration(MsQuic, Configuration);
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    CxPlatSystemLoad();

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = CxPlatInitialize())) {
        printf("CxPlatInitialize failed, 0x%x!\n", Status);
        CxPlatSystemUnload();
        return Status;
    }

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (argc < 2) {
        PrintUsage();
        goto Error;
    }

    RunServer(argc, argv);

Error:

    if (MsQuic != nullptr) {
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return (int)Status;
}
