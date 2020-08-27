/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides a very simple MsQuic API sample server and client application.

--*/

#include <msquichelper.h>

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
const uint16_t UdpPort = 4567;
const uint64_t IdleTimeoutMs = 1000;
const uint32_t SendBufferLength = 100;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Configuration;
HQUIC Session;

void
PrintUsage()
{
    printf("\nquicsample runs a simple client or server.\n\n");

    printf("Usage:\n");
    printf("  quicinterop.exe -client -target:<...> [-unsecure]\n");
    printf("  quicinterop.exe -server -cert_hash:<...> or (-cert_file:<...> and -key_file:<...>)\n");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONFIGURATION_CALLBACK)
QUIC_STATUS
QUIC_API
ConfigurationCallback(
    _In_ HQUIC /* Configuration */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONFIGURATION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONFIGURATION_EVENT_LOAD_COMPLETE:
        if (QUIC_FAILED(Event->LOAD_CREDENTIAL_COMPLETE.Status)) {
            printf("Configuration load failed, 0x%x\n", Event->LOAD_CREDENTIAL_COMPLETE.Status);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ServerSend(
    _In_ HQUIC Stream
    )
{
    auto SendBufferRaw = QUIC_ALLOC_PAGED(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == nullptr) {
        printf("SendBuffer allocation failed!\n");
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }

    auto SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", Stream);

    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        QUIC_FREE(SendBufferRaw);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
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
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        printf("[strm][%p] Data received\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("[strm][%p] Peer shutdown\n", Stream);
        ServerSend(Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
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
        printf("[conn][%p] Connected\n", Connection);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, nullptr);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
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
        Event->NEW_CONNECTION.Configuration = Configuration;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, nullptr);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

bool
ServerLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_LOAD_SYNCHRONOUS;

    const char* Cert;
    const char* KeyFile;
    if (TryGetValue(argc, argv, "cert_hash", &Cert)) {
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            return false;
        }
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Config.CredConfig.Creds = &Config.CertHash;

    } else if (TryGetValue(argc, argv, "cert_file", &Cert) &&
        TryGetValue(argc, argv, "key_file", &KeyFile)) {
        Config.CertFile.CertificateFile = (char*)Cert;
        Config.CertFile.PrivateKeyFile = (char*)KeyFile;
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        Config.CredConfig.Creds = &Config.CertFile;

    } else {
        printf("Must specify '-cert_hash' or 'cert_file'!\n");
        return false;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, ConfigurationCallback, nullptr, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return false;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return false;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Configuration, QUIC_PARAM_LEVEL_CONFIGURATION, QUIC_PARAM_CONFIG_IDLE_TIMEOUT,
            sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
        printf("SetParam(QUIC_PARAM_CONFIG_IDLE_TIMEOUT) failed, 0x%x!\n", Status);
        return false;
    }

    QUIC_SERVER_RESUMPTION_LEVEL ResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Configuration, QUIC_PARAM_LEVEL_CONFIGURATION, QUIC_PARAM_CONFIG_SERVER_RESUMPTION_LEVEL,
            sizeof(ResumptionLevel), &ResumptionLevel))) {
        printf("SetParam(QUIC_PARAM_CONFIG_SERVER_RESUMPTION_LEVEL) failed, 0x%x!\n", Status);
        return false;
    }

    const uint16_t PeerStreamCount = 1;
    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Configuration, QUIC_PARAM_LEVEL_CONFIGURATION, QUIC_PARAM_CONFIG_PEER_BIDI_STREAM_COUNT,
            sizeof(PeerStreamCount), &PeerStreamCount))) {
        printf("SetParam(QUIC_PARAM_CONFIG_PEER_BIDI_STREAM_COUNT) failed, 0x%x!\n", Status);
        return false;
    }

    return true;
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

    if (!ServerLoadConfiguration(argc, argv)) {
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Session, ServerListenerCallback, nullptr, &Listener))) {
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
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        QUIC_FREE(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        printf("[strm][%p] Data received\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("[strm][%p] Peer shutdown\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ClientSend(
    _In_ HQUIC Connection
    )
{
    QUIC_STATUS Status;
    HQUIC Stream = nullptr;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;
    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, nullptr, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[strm][%p] Starting...\n", Stream);

    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(Stream);
        goto Error;
    }

    SendBufferRaw = (uint8_t*)QUIC_ALLOC_PAGED(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == nullptr) {
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", Stream);

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        QUIC_FREE(SendBufferRaw);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
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
        printf("[conn][%p] Connected\n", Connection);
        ClientSend(Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
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

bool
ClientLoadConfiguration(
    bool Unsecure
    )
{
    QUIC_CREDENTIAL_CONFIG CredConfig;
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_LOAD_SYNCHRONOUS | QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, ConfigurationCallback, nullptr, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return false;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return false;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Configuration, QUIC_PARAM_LEVEL_CONFIGURATION, QUIC_PARAM_CONFIG_IDLE_TIMEOUT,
            sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
        printf("SetParam(QUIC_PARAM_CONFIG_IDLE_TIMEOUT) failed, 0x%x!\n", Status);
        return false;
    }

    return true;
}

void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    if (!ClientLoadConfiguration(GetValue(argc, argv, "unsecure"))) {
        return;
    }

    QUIC_STATUS Status;
    const char* ResumptionTicketString = nullptr;
    HQUIC Connection = nullptr;
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

    const char* Target;
    if (!TryGetValue(argc, argv, "target", &Target)) {
        printf("Must specify '-target' argument!\n");
        goto Error;
    }

    printf("[conn][%p] Connecting...\n", Connection);

    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, &Alpn, 1, AF_UNSPEC, Target, UdpPort))) {
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
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SessionOpen(Registration, nullptr, &Session))) {
        printf("SessionOpen failed, 0x%x!\n", Status);
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
        if (Configuration != nullptr) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
