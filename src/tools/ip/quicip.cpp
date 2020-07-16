/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A server and client implementation for a public IP lookup protocol.

TODO:

    Don't use the QUIC_ADDR format, as it's not cross-platform. Use the same
    format as the QUIC spec's preferred address TP.

--*/

#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#include <msquichelper.h>

const QUIC_REGISTRATION_CONFIG RegConfig = { "ip", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("ip") - 1, (uint8_t*)"ip" };
const uint16_t UdpPort = 4444;
const uint64_t IdleTimeoutMs = 2000;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Session;
QUIC_SEC_CONFIG* SecurityConfig;

extern "C" void QuicTraceRundown(void) { }

void
PrintUsage()
{
    printf("\nquicip runs a public IP lookup client or server.\n\n");

    printf("Usage:\n");
    printf("  quicip.exe -client -target:<...> [-unsecure]\n");
    printf("  quicip.exe -server -selfsign or -cert_hash:<...> or (-cert_file:<...> and -key_file:<...>)\n");
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
        QUIC_FREE(Event->SEND_COMPLETE.ClientContext);
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

    auto SendBufferRaw = QUIC_ALLOC_PAGED(sizeof(QUIC_BUFFER) + sizeof(QUIC_ADDR));
    if (SendBufferRaw == nullptr) {
        return;
    }

    auto SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = sizeof(QUIC_ADDR);

    if (QUIC_FAILED(Status = MsQuic->GetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_REMOTE_ADDRESS, &SendBuffer->Length, SendBuffer->Buffer))) {
        printf("GetParam(CONN_REMOTE_ADDRESS) failed, 0x%x!\n", Status);
        QUIC_FREE(SendBuffer);
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
        QUIC_FREE(SendBufferRaw);
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
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, nullptr);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Listener = nullptr;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, AF_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams = nullptr;
    const char* Cert;
    const char* KeyFile;
    if (GetValue(argc, argv, "selfsign")) {
        SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
        if (!SelfSignedCertParams) {
            printf("Failed to create platform self signed certificate\n");
            return;
        }

        SecurityConfig = GetSecConfigForSelfSigned(MsQuic, Registration, SelfSignedCertParams);
        if (!SecurityConfig) {
            printf("Failed to create security config for self signed certificate\n");
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return;
        }
    } else if (TryGetValue(argc, argv, "cert_hash", &Cert)) {
        SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, Cert);
        if (SecurityConfig == nullptr) {
            printf("Failed to load certificate from hash!\n");
            return;
        }
    } else if (TryGetValue(argc, argv, "cert_file", &Cert) &&
        TryGetValue(argc, argv, "key_file", &KeyFile)) {
        SecurityConfig = GetSecConfigForFile(MsQuic, Registration, KeyFile, Cert);
        if (SecurityConfig == nullptr) {
            printf("Failed to load certificate from file!\n");
            return;
        }
    } else {
        printf("Must specify 'selfsign', '-cert_hash' or 'cert_file'!\n");
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Session, ServerListenerCallback, nullptr, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Press Enter to exit.\n\n");
    getchar();

Error:

    if (Listener != nullptr) {
        MsQuic->ListenerClose(Listener);
    }
    MsQuic->SecConfigDelete(SecurityConfig);
    if (SelfSignedCertParams) {
        QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
    }
}

QUIC_ADDR PublicIp;

QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.AbsoluteOffset + Event->RECEIVE.TotalBufferLength <= sizeof(QUIC_ADDR)) {
            uint64_t Offset = Event->RECEIVE.AbsoluteOffset;
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                memcpy(
                    ((uint8_t*)&PublicIp) + Offset,
                    Event->RECEIVE.Buffers[i].Buffer,
                    Event->RECEIVE.Buffers[i].Length);
                Offset += Event->RECEIVE.Buffers[i].Length;
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
        QUIC_ADDR_STR AddrStr = { 0 };
        QuicAddrToString(&PublicIp, &AddrStr);
        printf("Public IP: %s\n\n", AddrStr.Address);
        MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
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
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ClientStreamCallback, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        printf("Resumption ticket received (%u bytes):\n", Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    const uint16_t PeerStreamCount = 1;
    const char* ResumptionTicketString = nullptr;
    HQUIC Connection = nullptr;

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT,
            sizeof(PeerStreamCount), &PeerStreamCount))) {
        printf("SetParam(SESSION_PEER_UNIDI_STREAM_COUNT) failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Session, ClientConnectionCallback, nullptr, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (TryGetValue(argc, argv, "ticket", &ResumptionTicketString) && ResumptionTicketString != nullptr) {
        uint8_t ResumptionTicket[1024];
         uint16_t TicketLength = (uint16_t)DecodeHexBuffer(ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
        if (QUIC_FAILED(Status = MsQuic->SetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_RESUMPTION_STATE,
                TicketLength,
                ResumptionTicket))) {
            printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    if (GetValue(argc, argv, "unsecure")) {
        const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
        if (QUIC_FAILED(Status = MsQuic->SetParam(
                Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertificateValidationFlags), &CertificateValidationFlags))) {
            printf("SetParam(QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    const char* Target;
    if (!TryGetValue(argc, argv, "target", &Target)) {
        printf("Must specify '-target' argument!\n");
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, AF_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status) && Connection != nullptr) {
        MsQuic->ConnectionClose(Connection);
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QuicPlatformSystemLoad();

    QUIC_SERVER_RESUMPTION_LEVEL ResumptionLevel = QUIC_SERVER_RESUME_ONLY;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = QuicPlatformInitialize())) {
        printf("QuicPlatformInitialize failed, 0x%x!\n", Status);
        QuicPlatformSystemUnload();
        return Status;
    }

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

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_IDLE_TIMEOUT,
            sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
        printf("SetParam(QUIC_PARAM_SESSION_IDLE_TIMEOUT) failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Session, QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL,
            sizeof(ResumptionLevel), &ResumptionLevel))) {
            printf("SetParam(QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL) failed, 0x%x!\n", Status);
            goto Error;
        }

    if (GetValue(argc, argv, "help") ||
        GetValue(argc, argv, "?")) {
        PrintUsage();
    } else if (GetValue(argc, argv, "client")) {
        RunClient(argc, argv);
    } else if (GetValue(argc, argv, "server")) {
        RunServer(argc, argv);
    } else {
        PrintUsage();
    }

Error:

    if (MsQuic != nullptr) {
        if (Session != nullptr) {
            MsQuic->SessionClose(Session); // Waits on all connections to be cleaned up.
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return (int)Status;
}
